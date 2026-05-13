package logs

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Result struct {
	Sources []Source `json:"linuxLogSources"`
	Events  []Event  `json:"linuxLogEvents"`
}

type Source struct {
	Path       string `json:"path"`
	EventCount int    `json:"eventCount"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
}

type Event struct {
	EventType string `json:"eventType"`
	Source    string `json:"source"`
	Program   string `json:"program"`
	Actor     string `json:"actor,omitempty"`
	Target    string `json:"target,omitempty"`
	RemoteIP  string `json:"remoteIp,omitempty"`
	Evidence  string `json:"evidence,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Raw       string `json:"raw"`
}

var (
	acceptedPasswordPattern = regexp.MustCompile(`Accepted \S+ for ([^ ]+) from ([^ ]+)`)
	failedPasswordPattern   = regexp.MustCompile(`Failed \S+ for (?:invalid user )?([^ ]+) from ([^ ]+)`)
	sudoPattern             = regexp.MustCompile(`^\s*([^:]+)\s*:\s.*COMMAND=(.+)$`)
	suSessionPattern        = regexp.MustCompile(`session opened for user ([^ ]+) by ([^( ]+)`)
	cronPattern             = regexp.MustCompile(`\(([^)]+)\) CMD \((.*)\)`)
)

func Collect(root string) (Result, error) {
	textCandidates := []string{
		filepath.Join("var", "log", "auth.log"),
		filepath.Join("var", "log", "secure"),
		filepath.Join("var", "log", "syslog"),
		filepath.Join("var", "log", "messages"),
		filepath.Join("var", "log", "audit", "audit.log"),
	}
	loginCandidates := []loginDatabaseCandidate{
		{relPath: filepath.Join("run", "utmp"), altRelPaths: []string{filepath.Join("var", "run", "utmp")}, eventType: "login_session_active"},
		{relPath: filepath.Join("var", "log", "wtmp"), eventType: "login_success"},
		{relPath: filepath.Join("var", "log", "btmp"), eventType: "login_failure"},
		{relPath: filepath.Join("var", "log", "lastlog"), eventType: "last_login"},
	}

	result := Result{
		Sources: []Source{},
		Events:  []Event{},
	}
	for _, relPath := range textCandidates {
		events, err := readLogFile(filepath.Join(root, relPath), relPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				result.Sources = append(result.Sources, Source{Path: relPath, EventCount: 0, Status: "missing", Reason: "file_not_found"})
				continue
			}
			return Result{}, err
		}
		if len(events) == 0 {
			result.Sources = append(result.Sources, Source{Path: relPath, EventCount: 0, Status: "available", Reason: "no_matching_events"})
			continue
		}
		result.Sources = append(result.Sources, Source{Path: relPath, EventCount: len(events), Status: "available"})
		result.Events = append(result.Events, events...)
	}
	usersByUID := readUsersByUID(filepath.Join(root, "etc", "passwd"))
	for _, candidate := range loginCandidates {
		sourcePath, events, err := readLoginDatabase(root, candidate, usersByUID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				result.Sources = append(result.Sources, Source{Path: candidate.relPath, EventCount: 0, Status: "missing", Reason: "file_not_found"})
				continue
			}
			return Result{}, err
		}
		if len(events) == 0 {
			result.Sources = append(result.Sources, Source{Path: sourcePath, EventCount: 0, Status: "available", Reason: "no_matching_events"})
			continue
		}
		result.Sources = append(result.Sources, Source{Path: sourcePath, EventCount: len(events), Status: "available"})
		result.Events = append(result.Events, events...)
	}
	journalEvents, journalSources, err := collectJournaldExport(root)
	if err != nil {
		return Result{}, err
	}
	result.Sources = append(result.Sources, journalSources...)
	result.Events = append(result.Events, journalEvents...)
	auditConfigEvents, auditConfigSources, err := collectAuditConfiguration(root)
	if err != nil {
		return Result{}, err
	}
	result.Sources = append(result.Sources, auditConfigSources...)
	result.Events = append(result.Events, auditConfigEvents...)
	sort.Slice(result.Sources, func(i, j int) bool { return result.Sources[i].Path < result.Sources[j].Path })
	sort.SliceStable(result.Events, func(i, j int) bool {
		left := result.Events[i]
		right := result.Events[j]
		return left.Source+"|"+left.Timestamp+"|"+left.Raw < right.Source+"|"+right.Timestamp+"|"+right.Raw
	})
	return result, nil
}

func collectJournaldExport(root string) ([]Event, []Source, error) {
	journalRoot := filepath.Join(root, "var", "log", "journal")
	var paths []string
	err := filepath.WalkDir(journalRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".journal.export") || strings.HasSuffix(name, ".journal.txt") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	sort.Strings(paths)

	var events []Event
	var sources []Source
	for _, path := range paths {
		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return nil, nil, err
		}
		relPath = filepath.ToSlash(relPath)
		fileEvents, err := readJournaldExportFile(path, relPath)
		if err != nil {
			return nil, nil, err
		}
		source := Source{Path: relPath, EventCount: len(fileEvents), Status: "available"}
		if len(fileEvents) == 0 {
			source.Reason = "no_matching_events"
		}
		sources = append(sources, source)
		events = append(events, fileEvents...)
	}
	return events, sources, nil
}

func readJournaldExportFile(path string, source string) ([]Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []Event
	record := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			if event, ok := classifyJournalRecord(source, record); ok {
				events = append(events, event)
			}
			record = map[string]string{}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		record[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if event, ok := classifyJournalRecord(source, record); ok {
		events = append(events, event)
	}
	return events, nil
}

func classifyJournalRecord(source string, record map[string]string) (Event, bool) {
	if len(record) == 0 {
		return Event{}, false
	}
	program := firstNonEmpty(record["SYSLOG_IDENTIFIER"], strings.TrimSuffix(record["_SYSTEMD_UNIT"], ".service"), record["_COMM"])
	message := record["MESSAGE"]
	if message == "" {
		return Event{}, false
	}
	line := "Jan 02 15:04:05 journal " + program + ": " + message
	event, ok := classifyLine(source, line)
	if !ok {
		return Event{}, false
	}
	event.Source = source
	event.Program = program
	event.Timestamp = journaldRealtimeTimestamp(record["__REALTIME_TIMESTAMP"])
	event.Raw = line
	return event, true
}

func journaldRealtimeTimestamp(value string) string {
	micros, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || micros <= 0 {
		return ""
	}
	return time.Unix(0, micros*int64(time.Microsecond)).UTC().Format(time.RFC3339Nano)
}

func collectAuditConfiguration(root string) ([]Event, []Source, error) {
	var events []Event
	var sources []Source
	for _, relPath := range []string{filepath.Join("etc", "audit", "auditd.conf")} {
		fileEvents, source, err := readAuditConfigFile(filepath.Join(root, relPath), relPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, nil, err
		}
		events = append(events, fileEvents...)
		sources = append(sources, source)
	}
	ruleEvents, ruleSources, err := readAuditRulesDirectory(filepath.Join(root, "etc", "audit", "rules.d"), filepath.Join("etc", "audit", "rules.d"))
	if err != nil {
		return nil, nil, err
	}
	events = append(events, ruleEvents...)
	sources = append(sources, ruleSources...)
	return events, sources, nil
}

func readAuditConfigFile(absPath string, relPath string) ([]Event, Source, error) {
	file, err := os.Open(absPath)
	if err != nil {
		return nil, Source{}, err
	}
	defer file.Close()

	var events []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := stripAuditComment(scanner.Text())
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		if key == "local_events" || key == "write_logs" || key == "max_log_file_action" || key == "space_left_action" || key == "admin_space_left_action" {
			events = append(events, Event{
				EventType: "audit_policy",
				Source:    relPath,
				Program:   "auditd",
				Evidence:  key + "=" + value,
				Raw:       line,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, Source{}, err
	}
	return events, Source{Path: relPath, EventCount: len(events), Status: "available"}, nil
}

func readAuditRulesDirectory(absDir string, relDir string) ([]Event, []Source, error) {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var events []Event
	var sources []Source
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(entry.Name(), ".rules") {
			continue
		}
		relPath := filepath.Join(relDir, entry.Name())
		fileEvents, source, err := readAuditRulesFile(filepath.Join(absDir, entry.Name()), relPath)
		if err != nil {
			return nil, nil, err
		}
		events = append(events, fileEvents...)
		sources = append(sources, source)
	}
	return events, sources, nil
}

func readAuditRulesFile(absPath string, relPath string) ([]Event, Source, error) {
	file, err := os.Open(absPath)
	if err != nil {
		return nil, Source{}, err
	}
	defer file.Close()

	var events []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := stripAuditComment(scanner.Text())
		if line == "" {
			continue
		}
		if event, ok := auditRuleEvent(relPath, line); ok {
			events = append(events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, Source{}, err
	}
	return events, Source{Path: relPath, EventCount: len(events), Status: "available"}, nil
}

func auditRuleEvent(source string, line string) (Event, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return Event{}, false
	}
	event := Event{Source: source, Program: "auditd", Raw: line}
	switch fields[0] {
	case "-w":
		if len(fields) < 2 {
			return Event{}, false
		}
		event.EventType = "audit_rule_watch"
		event.Evidence = fields[1]
		event.Target = auditRuleKey(fields)
		return event, true
	case "-a":
		syscalls := auditRuleSyscalls(fields)
		if len(syscalls) == 0 {
			return Event{}, false
		}
		event.EventType = "audit_rule_syscall"
		event.Evidence = strings.Join(syscalls, ",")
		event.Target = auditRuleKey(fields)
		return event, true
	default:
		return Event{}, false
	}
}

func auditRuleSyscalls(fields []string) []string {
	var syscalls []string
	for index, field := range fields {
		switch {
		case field == "-S" && index+1 < len(fields):
			syscalls = append(syscalls, fields[index+1])
		case strings.HasPrefix(field, "-S") && len(field) > 2:
			syscalls = append(syscalls, strings.TrimPrefix(field, "-S"))
		}
	}
	return syscalls
}

func auditRuleKey(fields []string) string {
	for index, field := range fields {
		if field == "-k" && index+1 < len(fields) {
			return fields[index+1]
		}
		if strings.HasPrefix(field, "-k") && len(field) > 2 {
			return strings.TrimPrefix(field, "-k")
		}
	}
	return ""
}

func stripAuditComment(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	if before, _, ok := strings.Cut(trimmed, "#"); ok {
		return strings.TrimSpace(before)
	}
	return trimmed
}

func readLogFile(path string, source string) ([]Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []Event
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		event, ok := classifyLine(source, line)
		if ok {
			events = append(events, event)
		}
	}
	return events, scanner.Err()
}

func classifyLine(source string, line string) (Event, bool) {
	if strings.HasSuffix(source, filepath.Join("audit", "audit.log")) {
		return classifyAuditLine(source, line)
	}

	program, message := splitProgramMessage(line)
	event := Event{Source: source, Program: program, Raw: line}

	if program == "sshd" {
		if match := acceptedPasswordPattern.FindStringSubmatch(message); len(match) == 3 {
			event.EventType = "auth_success"
			event.Actor = match[1]
			event.RemoteIP = match[2]
			event.Evidence = match[2]
			return event, true
		}
		if match := failedPasswordPattern.FindStringSubmatch(message); len(match) == 3 {
			event.EventType = "auth_failure"
			event.Actor = match[1]
			event.RemoteIP = match[2]
			event.Evidence = match[2]
			return event, true
		}
	}

	if program == "sudo" {
		if match := sudoPattern.FindStringSubmatch(message); len(match) == 3 {
			event.EventType = "sudo_command"
			event.Actor = strings.TrimSpace(match[1])
			event.Target = "root"
			event.Evidence = strings.TrimSpace(match[2])
			return event, true
		}
	}

	if program == "su" {
		if match := suSessionPattern.FindStringSubmatch(message); len(match) == 3 {
			event.EventType = "su_session_opened"
			event.Actor = match[1]
			event.Target = match[2]
			event.Evidence = match[2]
			return event, true
		}
	}

	if program == "CRON" {
		if match := cronPattern.FindStringSubmatch(message); len(match) == 3 {
			event.EventType = "cron_command"
			event.Actor = match[1]
			event.Evidence = match[2]
			return event, true
		}
	}

	if program == "systemd" && (strings.HasPrefix(message, "Started ") || strings.HasPrefix(message, "Starting ") || strings.HasPrefix(message, "Stopped ")) {
		event.EventType = "systemd_unit"
		event.Evidence = message
		return event, true
	}

	return Event{}, false
}

func classifyAuditLine(source string, line string) (Event, bool) {
	auditType, fields, ok := parseAuditLine(line)
	if !ok {
		return Event{}, false
	}
	event := Event{
		EventType: "audit_" + strings.ToLower(auditType),
		Source:    source,
		Program:   "auditd",
		Timestamp: auditTimestamp(fields["audit_seconds"]),
		Raw:       line,
	}
	switch auditType {
	case "EXECVE":
		args := auditExecArgs(fields)
		if len(args) == 0 {
			return Event{}, false
		}
		event.EventType = "audit_execve"
		event.Evidence = strings.Join(args, " ")
		return event, true
	case "SYSCALL":
		event.EventType = "audit_syscall"
		event.Actor = fields["auid"]
		event.Target = "uid:" + fields["uid"]
		event.Evidence = firstNonEmpty(fields["exe"], fields["comm"], fields["syscall"])
		return event, event.Evidence != ""
	case "USER_AUTH", "USER_LOGIN":
		event.EventType = "audit_" + strings.ToLower(auditType)
		event.Actor = fields["acct"]
		event.RemoteIP = firstNonEmpty(fields["addr"], fields["hostname"])
		event.Target = fields["terminal"]
		event.Evidence = fields["res"]
		return event, event.Actor != "" || event.Evidence != ""
	default:
		return Event{}, false
	}
}

func parseAuditLine(line string) (string, map[string]string, bool) {
	fields := map[string]string{}
	parts := strings.Fields(line)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "type=") {
		return "", nil, false
	}
	auditType := strings.TrimPrefix(parts[0], "type=")
	for _, part := range parts[1:] {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"'`)
		if key == "msg" && strings.HasPrefix(value, "audit(") {
			fields["audit_seconds"] = auditSeconds(value)
			continue
		}
		fields[key] = value
	}
	if _, inner, ok := strings.Cut(line, " msg='"); ok {
		inner = strings.TrimSuffix(inner, "'")
		for _, part := range strings.Fields(inner) {
			key, value, ok := strings.Cut(part, "=")
			if ok {
				fields[key] = strings.Trim(value, `"'`)
			}
		}
	}
	return auditType, fields, true
}

func auditSeconds(value string) string {
	start := strings.Index(value, "(")
	end := strings.Index(value, ":")
	if start < 0 || end <= start+1 {
		return ""
	}
	seconds := value[start+1 : end]
	if dot := strings.Index(seconds, "."); dot >= 0 {
		seconds = seconds[:dot]
	}
	return seconds
}

func auditTimestamp(secondsText string) string {
	if secondsText == "" {
		return ""
	}
	seconds, err := strconv.ParseInt(secondsText, 10, 64)
	if err != nil || seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

func auditExecArgs(fields map[string]string) []string {
	argc, _ := strconv.Atoi(fields["argc"])
	if argc <= 0 {
		argc = 64
	}
	args := []string{}
	for index := 0; index < argc; index++ {
		value := fields["a"+strconv.Itoa(index)]
		if value == "" {
			continue
		}
		args = append(args, value)
	}
	return args
}

func splitProgramMessage(line string) (string, string) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", line
	}
	restStart := 4
	if strings.Contains(fields[0], "T") && strings.Contains(fields[0], "-") {
		restStart = 2
	}
	if len(fields) <= restStart {
		return "", line
	}
	rest := strings.Join(fields[restStart:], " ")
	programField, message, ok := strings.Cut(rest, ":")
	if !ok {
		return "", rest
	}
	program := programField
	if bracket := strings.Index(program, "["); bracket >= 0 {
		program = program[:bracket]
	}
	return strings.TrimSpace(program), strings.TrimSpace(message)
}

type loginDatabaseCandidate struct {
	relPath     string
	altRelPaths []string
	eventType   string
}

const (
	utmpRecordSize      = 384
	utmpUserProcess     = 7
	lastlogRecordSize32 = 292
	lastlogRecordSize64 = 296
	utmpLineOffset      = 8
	utmpLineSize        = 32
	utmpUserOffset      = 44
	utmpUserSize        = 32
	utmpHostOffset      = 76
	utmpHostSize        = 256
	utmpTimestampOffset = 340
	lastlog32LineOffset = 4
	lastlog64LineOffset = 8
	lastlogLineSize     = 32
	lastlogHostSize     = 256
)

func readLoginDatabase(root string, candidate loginDatabaseCandidate, usersByUID map[int]string) (string, []Event, error) {
	relPath, path, err := resolveFirstExistingPath(root, candidate.relPath, candidate.altRelPaths)
	if err != nil {
		return candidate.relPath, nil, err
	}
	switch filepath.Base(relPath) {
	case "utmp", "wtmp", "btmp":
		events, err := readUtmpEvents(path, relPath, candidate.eventType)
		return relPath, events, err
	case "lastlog":
		events, err := readLastlogEvents(path, relPath, usersByUID)
		return relPath, events, err
	default:
		return relPath, nil, nil
	}
}

func resolveFirstExistingPath(root string, relPath string, altRelPaths []string) (string, string, error) {
	candidates := append([]string{relPath}, altRelPaths...)
	var firstErr error
	for _, candidate := range candidates {
		path := filepath.Join(root, candidate)
		if _, err := os.Stat(path); err == nil {
			return candidate, path, nil
		} else if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = os.ErrNotExist
	}
	return relPath, filepath.Join(root, relPath), firstErr
}

func readUtmpEvents(path string, source string, eventType string) ([]Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []Event
	buffer := make([]byte, utmpRecordSize)
	for {
		_, err := io.ReadFull(file, buffer)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return nil, err
		}
		if int16(binary.LittleEndian.Uint16(buffer[0:2])) != utmpUserProcess {
			continue
		}
		user := trimCString(buffer[utmpUserOffset : utmpUserOffset+utmpUserSize])
		if user == "" {
			continue
		}
		host := trimCString(buffer[utmpHostOffset : utmpHostOffset+utmpHostSize])
		line := trimCString(buffer[utmpLineOffset : utmpLineOffset+utmpLineSize])
		timestamp := timestampFromUnix32(buffer[utmpTimestampOffset : utmpTimestampOffset+4])
		events = append(events, Event{
			EventType: eventType,
			Source:    source,
			Program:   "utmp",
			Actor:     user,
			Target:    line,
			RemoteIP:  host,
			Evidence:  firstNonEmpty(host, line),
			Timestamp: timestamp,
			Raw:       strings.TrimSpace(strings.Join([]string{eventType, user, line, host, timestamp}, " ")),
		})
	}
	return events, nil
}

func readLastlogEvents(path string, source string, usersByUID map[int]string) ([]Event, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	recordSize := detectLastlogRecordSize(len(body))
	if recordSize == 0 {
		return nil, nil
	}
	lineOffset := lastlog32LineOffset
	if recordSize == lastlogRecordSize64 {
		lineOffset = lastlog64LineOffset
	}

	var events []Event
	for offset := 0; offset+recordSize <= len(body); offset += recordSize {
		record := body[offset : offset+recordSize]
		uid := offset / recordSize
		timestamp := lastlogTimestamp(record, recordSize)
		if timestamp == "" {
			continue
		}
		user := usersByUID[uid]
		if user == "" {
			user = strconv.Itoa(uid)
		}
		line := trimCString(record[lineOffset : lineOffset+lastlogLineSize])
		hostStart := lineOffset + lastlogLineSize
		host := trimCString(record[hostStart : hostStart+lastlogHostSize])
		events = append(events, Event{
			EventType: "last_login",
			Source:    source,
			Program:   "lastlog",
			Actor:     user,
			Target:    line,
			RemoteIP:  host,
			Evidence:  firstNonEmpty(host, line),
			Timestamp: timestamp,
			Raw:       strings.TrimSpace(strings.Join([]string{"last_login", user, line, host, timestamp}, " ")),
		})
	}
	return events, nil
}

func detectLastlogRecordSize(size int) int {
	switch {
	case size <= 0:
		return 0
	case size%lastlogRecordSize32 == 0:
		return lastlogRecordSize32
	case size%lastlogRecordSize64 == 0:
		return lastlogRecordSize64
	default:
		return 0
	}
}

func lastlogTimestamp(record []byte, recordSize int) string {
	var seconds int64
	if recordSize == lastlogRecordSize64 {
		seconds = int64(binary.LittleEndian.Uint64(record[0:8]))
	} else {
		seconds = int64(binary.LittleEndian.Uint32(record[0:4]))
	}
	if seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

func timestampFromUnix32(raw []byte) string {
	seconds := int64(binary.LittleEndian.Uint32(raw))
	if seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

func trimCString(raw []byte) string {
	if index := strings.IndexByte(string(raw), 0); index >= 0 {
		raw = raw[:index]
	}
	return strings.TrimSpace(string(raw))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func readUsersByUID(path string) map[int]string {
	file, err := os.Open(path)
	if err != nil {
		return map[int]string{}
	}
	defer file.Close()

	users := map[int]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		users[uid] = fields[0]
	}
	return users
}
