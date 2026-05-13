package logs

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectParsesLinuxAuthAndSystemLogs(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect logs: %v", err)
	}
	if len(result.Sources) != 9 {
		t.Fatalf("expected nine log source statuses, got %#v", result.Sources)
	}
	available := 0
	for _, source := range result.Sources {
		if source.Status == "available" && source.EventCount > 0 {
			available++
		}
	}
	if available != 3 {
		t.Fatalf("expected three available log sources, got %#v", result.Sources)
	}
	if !hasSource(result.Sources, filepath.Join("run", "utmp")) {
		t.Fatalf("expected current session source status, got %#v", result.Sources)
	}
	if len(result.Events) != 9 {
		t.Fatalf("expected nine log events, got %#v", result.Events)
	}

	assertEvent(t, findEvent(result.Events, "auth_success"), "auth_success", "sshd", "alice", "10.0.0.8")
	assertEvent(t, findEvent(result.Events, "auth_failure"), "auth_failure", "sshd", "admin", "10.0.0.9")
	assertEvent(t, findEvent(result.Events, "sudo_command"), "sudo_command", "sudo", "alice", "/usr/bin/id")
	assertEvent(t, findEvent(result.Events, "su_session_opened"), "su_session_opened", "su", "root", "alice")
	assertEvent(t, findEvent(result.Events, "cron_command"), "cron_command", "CRON", "root", "/usr/local/bin/persist.sh")
	assertEvent(t, findEvent(result.Events, "systemd_unit"), "systemd_unit", "systemd", "", "Started Suspicious reverse shell.")
}

func TestCollectToleratesMissingLogFiles(t *testing.T) {
	result, err := Collect(t.TempDir())
	if err != nil {
		t.Fatalf("collect missing logs: %v", err)
	}
	if len(result.Sources) != 9 {
		t.Fatalf("expected missing source status for candidates, got %#v", result.Sources)
	}
	for _, source := range result.Sources {
		if source.EventCount != 0 || source.Status != "missing" {
			t.Fatalf("expected missing zero-event source, got %#v", source)
		}
	}
	if len(result.Events) != 0 {
		t.Fatalf("expected no events, got %#v", result.Events)
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if string(body) == `{"linuxLogSources":null,"linuxLogEvents":null}` {
		t.Fatalf("expected stable arrays instead of null slices: %s", body)
	}
}

func hasSource(sources []Source, path string) bool {
	for _, source := range sources {
		if source.Path == path {
			return true
		}
	}
	return false
}

func TestCollectParsesAuditdEvents(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect auditd logs: %v", err)
	}

	var execve, syscall, userAuth *Event
	for index := range result.Events {
		event := &result.Events[index]
		switch event.EventType {
		case "audit_execve":
			execve = event
		case "audit_syscall":
			syscall = event
		case "audit_user_auth":
			userAuth = event
		}
	}
	if execve == nil || syscall == nil || userAuth == nil {
		t.Fatalf("expected audit events, got execve=%#v syscall=%#v userAuth=%#v all=%#v", execve, syscall, userAuth, result.Events)
	}
	assertEvent(t, *execve, "audit_execve", "auditd", "", "bash -c id")
	if execve.Timestamp != "2026-05-09T08:00:01Z" {
		t.Fatalf("expected audit exec timestamp, got %#v", execve)
	}
	assertEvent(t, *syscall, "audit_syscall", "auditd", "1000", "/usr/bin/bash")
	if syscall.Target != "uid:0" {
		t.Fatalf("expected syscall target uid, got %#v", syscall)
	}
	assertEvent(t, *userAuth, "audit_user_auth", "auditd", "alice", "success")
	if userAuth.RemoteIP != "10.0.0.8" {
		t.Fatalf("expected audit remote ip, got %#v", userAuth)
	}
}

func TestCollectParsesAuditConfigurationEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "audit", "rules.d"), 0o755); err != nil {
		t.Fatalf("create audit rules dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var", "log"), 0o755); err != nil {
		t.Fatalf("create log dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "audit", "auditd.conf"), []byte("local_events = no\n"), 0o644); err != nil {
		t.Fatalf("write auditd.conf: %v", err)
	}
	rules := "" +
		"-w /etc/passwd -p wa -k identity\n" +
		"-a always,exit -F arch=b64 -S execve -k exec\n"
	if err := os.WriteFile(filepath.Join(root, "etc", "audit", "rules.d", "forensic.rules"), []byte(rules), 0o640); err != nil {
		t.Fatalf("write audit rules: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect audit config: %v", err)
	}

	watch := findEvent(result.Events, "audit_rule_watch")
	assertEvent(t, watch, "audit_rule_watch", "auditd", "", "/etc/passwd")
	if watch.Source != filepath.Join("etc", "audit", "rules.d", "forensic.rules") {
		t.Fatalf("unexpected audit watch source: %#v", watch)
	}
	syscall := findEvent(result.Events, "audit_rule_syscall")
	assertEvent(t, syscall, "audit_rule_syscall", "auditd", "", "execve")
	policy := findEvent(result.Events, "audit_policy")
	assertEvent(t, policy, "audit_policy", "auditd", "", "local_events=no")
}

func TestCollectParsesLinuxLoginDatabases(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "var", "log")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("create log dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatalf("create etc dir: %v", err)
	}
	passwd := []byte("root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\n")
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), passwd, 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}

	loginAt := time.Date(2026, 5, 9, 8, 1, 2, 0, time.UTC)
	failedAt := time.Date(2026, 5, 9, 8, 2, 3, 0, time.UTC)
	lastAt := time.Date(2026, 5, 9, 8, 3, 4, 0, time.UTC)
	if err := os.WriteFile(filepath.Join(logDir, "wtmp"), linuxUtmpRecord(7, "pts/0", "alice", "10.0.0.8", loginAt), 0o644); err != nil {
		t.Fatalf("write wtmp: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "btmp"), linuxUtmpRecord(7, "ssh:notty", "root", "10.0.0.9", failedAt), 0o644); err != nil {
		t.Fatalf("write btmp: %v", err)
	}
	lastlog := make([]byte, linuxLastlogRecordSize*1001)
	copy(lastlog[1000*linuxLastlogRecordSize:], linuxLastlogRecord("pts/0", "10.0.0.8", lastAt))
	if err := os.WriteFile(filepath.Join(logDir, "lastlog"), lastlog, 0o644); err != nil {
		t.Fatalf("write lastlog: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect login databases: %v", err)
	}

	var loginSuccess, loginFailure, lastLogin *Event
	for index := range result.Events {
		event := &result.Events[index]
		switch event.EventType {
		case "login_success":
			loginSuccess = event
		case "login_failure":
			loginFailure = event
		case "last_login":
			lastLogin = event
		}
	}
	assertEvent(t, *loginSuccess, "login_success", "utmp", "alice", "10.0.0.8")
	assertEvent(t, *loginFailure, "login_failure", "utmp", "root", "10.0.0.9")
	assertEvent(t, *lastLogin, "last_login", "lastlog", "alice", "10.0.0.8")
	if loginSuccess.Timestamp != loginAt.Format(time.RFC3339) {
		t.Fatalf("expected login timestamp, got %#v", loginSuccess)
	}
	if lastLogin.Target != "pts/0" {
		t.Fatalf("expected lastlog line target, got %#v", lastLogin)
	}
}

func TestCollectParsesCurrentLoginSessionsFromRunUtmp(t *testing.T) {
	root := t.TempDir()
	runDir := filepath.Join(root, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("create run dir: %v", err)
	}
	activeAt := time.Date(2026, 5, 9, 8, 4, 5, 0, time.UTC)
	if err := os.WriteFile(filepath.Join(runDir, "utmp"), linuxUtmpRecord(7, "pts/1", "bob", "10.0.0.10", activeAt), 0o644); err != nil {
		t.Fatalf("write run utmp: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect current sessions: %v", err)
	}

	activeSession := findEvent(result.Events, "login_session_active")
	assertEvent(t, activeSession, "login_session_active", "utmp", "bob", "10.0.0.10")
	if activeSession.Source != filepath.Join("run", "utmp") || activeSession.Target != "pts/1" {
		t.Fatalf("unexpected active session source/target: %#v", activeSession)
	}
	if activeSession.Timestamp != activeAt.Format(time.RFC3339) {
		t.Fatalf("expected active session timestamp, got %#v", activeSession)
	}
}

func TestCollectParsesISO8601TimestampedLinuxLogs(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "var", "log")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("create log dir: %v", err)
	}
	body := []byte(
		"2026-05-09T08:00:01.123456+08:00 ubuntu sshd[1234]: Accepted publickey for alice from 10.0.0.8 port 54321 ssh2\n" +
			"2026-05-09T08:00:02.123456+08:00 ubuntu sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id\n",
	)
	if err := os.WriteFile(filepath.Join(logDir, "auth.log"), body, 0o644); err != nil {
		t.Fatalf("write auth log: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect logs: %v", err)
	}

	if len(result.Events) != 2 {
		t.Fatalf("expected two parsed events, got %#v", result.Events)
	}
	assertEvent(t, result.Events[0], "auth_success", "sshd", "alice", "10.0.0.8")
	assertEvent(t, result.Events[1], "sudo_command", "sudo", "alice", "/usr/bin/id")
}

func TestCollectParsesJournaldExportEvidence(t *testing.T) {
	root := t.TempDir()
	journalDir := filepath.Join(root, "var", "log", "journal")
	if err := os.MkdirAll(journalDir, 0o755); err != nil {
		t.Fatalf("create journal dir: %v", err)
	}
	body := "" +
		"__REALTIME_TIMESTAMP=1778313601123456\n" +
		"_SYSTEMD_UNIT=ssh.service\n" +
		"SYSLOG_IDENTIFIER=sshd\n" +
		"_PID=1234\n" +
		"_UID=0\n" +
		"MESSAGE=Accepted publickey for alice from 10.0.0.8 port 54321 ssh2\n\n" +
		"__REALTIME_TIMESTAMP=1778313602123456\n" +
		"_SYSTEMD_UNIT=sudo.service\n" +
		"SYSLOG_IDENTIFIER=sudo\n" +
		"MESSAGE=alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id\n\n"
	if err := os.WriteFile(filepath.Join(journalDir, "system.journal.export"), []byte(body), 0o640); err != nil {
		t.Fatalf("write journal export: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect journal export: %v", err)
	}

	auth := findEvent(result.Events, "auth_success")
	assertEvent(t, auth, "auth_success", "sshd", "alice", "10.0.0.8")
	if auth.Source != filepath.Join("var", "log", "journal", "system.journal.export") {
		t.Fatalf("expected journal export source, got %#v", auth)
	}
	if auth.Timestamp != "2026-05-09T08:00:01.123456Z" {
		t.Fatalf("expected journal realtime timestamp, got %#v", auth)
	}
	sudo := findEvent(result.Events, "sudo_command")
	assertEvent(t, sudo, "sudo_command", "sudo", "alice", "/usr/bin/id")
	if sudo.Target != "root" {
		t.Fatalf("expected sudo target, got %#v", sudo)
	}
}

func assertEvent(t *testing.T, event Event, eventType string, program string, actor string, evidence string) {
	t.Helper()
	if event.EventType != eventType || event.Program != program || event.Actor != actor || event.Evidence != evidence {
		t.Fatalf("unexpected event: %#v", event)
	}
	if event.Source == "" || event.Raw == "" {
		t.Fatalf("expected source and raw line: %#v", event)
	}
}

func findEvent(events []Event, eventType string) Event {
	for _, event := range events {
		if event.EventType == eventType {
			return event
		}
	}
	return Event{}
}

const (
	linuxUtmpRecordSize    = 384
	linuxLastlogRecordSize = 292
)

func linuxUtmpRecord(recordType int16, line string, user string, host string, at time.Time) []byte {
	record := make([]byte, linuxUtmpRecordSize)
	binary.LittleEndian.PutUint16(record[0:2], uint16(recordType))
	copy(record[8:40], line)
	copy(record[44:76], user)
	copy(record[76:332], host)
	binary.LittleEndian.PutUint32(record[340:344], uint32(at.Unix()))
	return record
}

func linuxLastlogRecord(line string, host string, at time.Time) []byte {
	record := make([]byte, linuxLastlogRecordSize)
	binary.LittleEndian.PutUint32(record[0:4], uint32(at.Unix()))
	copy(record[4:36], line)
	copy(record[36:292], host)
	return record
}
