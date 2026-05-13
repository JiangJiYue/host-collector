package accounts

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"collector-shared/linuxutil"
)

type Result struct {
	Users  []User  `json:"users"`
	Groups []Group `json:"groups"`
}

type User struct {
	Username            string              `json:"username"`
	UID                 string              `json:"uid"`
	GID                 string              `json:"gid"`
	Home                string              `json:"home"`
	Shell               string              `json:"shell"`
	LoginShell          string              `json:"loginShell,omitempty"`
	Gecos               string              `json:"gecos,omitempty"`
	AccountType         string              `json:"accountType,omitempty"`
	LoginAbility        string              `json:"loginAbility,omitempty"`
	PasswordState       string              `json:"passwordState,omitempty"`
	PrivilegeLevel      string              `json:"privilegeLevel,omitempty"`
	RiskLevel           string              `json:"riskLevel,omitempty"`
	RiskReasons         []string            `json:"riskReasons,omitempty"`
	PrimaryGroup        string              `json:"primaryGroup,omitempty"`
	SupplementaryGroups []string            `json:"supplementaryGroups,omitempty"`
	LastLogin           string              `json:"lastLogin,omitempty"`
	LastLoginSource     string              `json:"lastLoginSource,omitempty"`
	Platform            string              `json:"platform"`
	SSHAuthorizedKeys   []SSHKey            `json:"sshAuthorizedKeys,omitempty"`
	SSHKnownHosts       []SSHKey            `json:"sshKnownHosts,omitempty"`
	SSHConfigHosts      []SSHConfigHost     `json:"sshConfigHosts,omitempty"`
	PrivilegeEvidence   []PrivilegeEvidence `json:"privilegeEvidence,omitempty"`
}

type Group struct {
	Name    string   `json:"name"`
	GID     string   `json:"gid"`
	Members []string `json:"members,omitempty"`
}

type SSHKey struct {
	Source            string `json:"source"`
	Line              int    `json:"line"`
	KeyType           string `json:"keyType"`
	FingerprintSHA256 string `json:"fingerprintSha256"`
	Comment           string `json:"comment,omitempty"`
	Options           string `json:"options,omitempty"`
	HostPattern       string `json:"hostPattern,omitempty"`
	HashedHost        bool   `json:"hashedHost,omitempty"`
	PublicKey         string `json:"publicKey,omitempty"`
}

type SSHConfigHost struct {
	Source       string `json:"source"`
	Line         int    `json:"line"`
	HostPattern  string `json:"hostPattern"`
	HostName     string `json:"hostName,omitempty"`
	User         string `json:"user,omitempty"`
	Port         string `json:"port,omitempty"`
	IdentityFile string `json:"identityFile,omitempty"`
	ProxyJump    string `json:"proxyJump,omitempty"`
	ProxyCommand string `json:"proxyCommand,omitempty"`
}

type PrivilegeEvidence struct {
	Subject    string   `json:"subject"`
	Privilege  string   `json:"privilege"`
	Source     string   `json:"source"`
	Line       int      `json:"line,omitempty"`
	Command    string   `json:"command,omitempty"`
	Control    string   `json:"control,omitempty"`
	Module     string   `json:"module,omitempty"`
	ModulePath string   `json:"modulePath,omitempty"`
	RunAs      string   `json:"runAs,omitempty"`
	Options    []string `json:"options,omitempty"`
	NoPassword bool     `json:"noPassword,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

func Collect(root string) (Result, error) {
	groups, err := readGroups(filepath.Join(root, "etc", "group"))
	if err != nil {
		return Result{}, err
	}
	users, err := readUsers(root, filepath.Join(root, "etc", "passwd"), groups, readShadowStates(filepath.Join(root, "etc", "shadow")), readSudoers(filepath.Join(root, "etc", "sudoers"), filepath.Join(root, "etc", "sudoers.d")), readPAMEvidence(filepath.Join(root, "etc", "pam.d")), readPolkitEvidence(root))
	if err != nil {
		return Result{}, err
	}
	return Result{Users: users, Groups: groups}, nil
}

func readUsers(root string, path string, groups []Group, passwordStates map[string]string, sudo sudoRules, pamEvidence []PrivilegeEvidence, polkitEvidence []PrivilegeEvidence) ([]User, error) {
	lines, err := readColonFile(path)
	if err != nil {
		return nil, err
	}
	primaryGroups := primaryGroupNames(groups)
	supplementaryGroups := supplementaryGroupsByUser(groups)
	users := make([]User, 0, len(lines))
	for _, fields := range lines {
		if len(fields) < 7 {
			continue
		}
		user := User{
			Username: fields[0],
			UID:      fields[2],
			GID:      fields[3],
			Gecos:    fields[4],
			Home:     fields[5],
			Shell:    fields[6],
			Platform: "linux",
		}
		enrichUser(&user, primaryGroups, supplementaryGroups, passwordStates, sudo, pamEvidence, polkitEvidence)
		enrichSSHKeys(root, &user)
		users = append(users, user)
	}
	return users, nil
}

func enrichUser(user *User, primaryGroups map[string]string, supplementaryGroups map[string][]string, passwordStates map[string]string, sudo sudoRules, pamEvidence []PrivilegeEvidence, polkitEvidence []PrivilegeEvidence) {
	user.LoginShell = user.Shell
	user.PrimaryGroup = primaryGroups[user.GID]
	user.SupplementaryGroups = supplementaryGroups[user.Username]
	user.AccountType = accountType(user)
	user.LoginAbility = loginAbility(user.Shell)
	user.PasswordState = passwordStates[user.Username]
	if user.PasswordState == "" {
		user.PasswordState = "unknown"
	}
	user.PrivilegeLevel = privilegeLevel(*user, sudo)
	user.PrivilegeEvidence = append(privilegeEvidence(*user, sudo), pamEvidence...)
	user.PrivilegeEvidence = append(user.PrivilegeEvidence, matchingPolkitEvidence(*user, polkitEvidence)...)
	user.RiskLevel, user.RiskReasons = riskAssessment(*user)
}

func accountType(user *User) string {
	if user.UID == "0" {
		return "root"
	}
	uid := parseUID(user.UID)
	if uid >= 0 && uid < 1000 {
		return "system"
	}
	return "regular"
}

func loginAbility(shell string) string {
	cleaned := strings.TrimSpace(shell)
	if cleaned == "" {
		return "unknown"
	}
	if strings.Contains(cleaned, "nologin") || strings.HasSuffix(cleaned, "/false") {
		return "nologin"
	}
	return "interactive"
}

func privilegeLevel(user User, sudo sudoRules) string {
	if user.UID == "0" {
		return "root"
	}
	if sudo.users[user.Username] {
		return "sudo"
	}
	for _, group := range user.SupplementaryGroups {
		if sudo.groups[group] {
			return "sudo"
		}
	}
	return "standard"
}

func privilegeEvidence(user User, sudo sudoRules) []PrivilegeEvidence {
	var evidence []PrivilegeEvidence
	evidence = append(evidence, sudo.evidenceByUser[user.Username]...)
	for _, group := range user.SupplementaryGroups {
		evidence = append(evidence, sudo.evidenceByGroup[group]...)
	}
	return evidence
}

func riskAssessment(user User) (string, []string) {
	var reasons []string
	if user.PrivilegeLevel == "root" {
		reasons = append(reasons, "uid_0")
	}
	if user.PrivilegeLevel == "sudo" {
		reasons = append(reasons, "sudo_privilege")
	}
	for _, evidence := range user.PrivilegeEvidence {
		if evidence.NoPassword {
			reasons = append(reasons, "sudo_nopasswd")
		}
		if linuxutil.ContainsString(evidence.Tags, "dangerous_command") {
			reasons = append(reasons, "sudo_dangerous_command")
		}
		if evidence.Privilege == "polkit" {
			reasons = append(reasons, "polkit_privilege")
		}
		if linuxutil.ContainsString(evidence.Tags, "polkit_manage_units") {
			reasons = append(reasons, "polkit_manage_units")
		}
		if linuxutil.ContainsString(evidence.Tags, "polkit_allow_any") {
			reasons = append(reasons, "polkit_allow_any")
		}
	}
	if user.LoginAbility == "interactive" && user.AccountType == "system" {
		reasons = append(reasons, "system_account_interactive_shell")
	}
	if user.LoginAbility == "interactive" && user.PasswordState == "locked" {
		reasons = append(reasons, "locked_account_has_interactive_shell")
	}
	switch {
	case linuxutil.ContainsString(reasons, "uid_0") || linuxutil.ContainsString(reasons, "system_account_interactive_shell"):
		return "high", uniqueSorted(reasons)
	case len(reasons) > 0:
		return "medium", uniqueSorted(reasons)
	default:
		return "low", nil
	}
}

func readGroups(path string) ([]Group, error) {
	lines, err := readColonFile(path)
	if err != nil {
		return nil, err
	}
	groups := make([]Group, 0, len(lines))
	for _, fields := range lines {
		if len(fields) < 3 {
			continue
		}
		var members []string
		if len(fields) >= 4 && strings.TrimSpace(fields[3]) != "" {
			members = strings.Split(fields[3], ",")
		}
		groups = append(groups, Group{Name: fields[0], GID: fields[2], Members: members})
	}
	return groups, nil
}

func primaryGroupNames(groups []Group) map[string]string {
	values := map[string]string{}
	for _, group := range groups {
		values[group.GID] = group.Name
	}
	return values
}

func supplementaryGroupsByUser(groups []Group) map[string][]string {
	values := map[string][]string{}
	for _, group := range groups {
		for _, member := range group.Members {
			member = strings.TrimSpace(member)
			if member == "" {
				continue
			}
			values[member] = append(values[member], group.Name)
		}
	}
	for member := range values {
		values[member] = uniqueSorted(values[member])
	}
	return values
}

func readShadowStates(path string) map[string]string {
	lines, err := readColonFile(path)
	if err != nil {
		return map[string]string{}
	}
	states := map[string]string{}
	for _, fields := range lines {
		if len(fields) < 2 {
			continue
		}
		states[fields[0]] = passwordState(fields[1])
	}
	return states
}

func passwordState(value string) string {
	switch {
	case value == "":
		return "empty"
	case strings.HasPrefix(value, "!") || strings.HasPrefix(value, "*"):
		return "locked"
	default:
		return "set"
	}
}

type sudoRules struct {
	users           map[string]bool
	groups          map[string]bool
	evidenceByUser  map[string][]PrivilegeEvidence
	evidenceByGroup map[string][]PrivilegeEvidence
}

func readSudoers(paths ...string) sudoRules {
	rules := sudoRules{users: map[string]bool{}, groups: map[string]bool{}, evidenceByUser: map[string][]PrivilegeEvidence{}, evidenceByGroup: map[string][]PrivilegeEvidence{}}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
					continue
				}
				readSudoersFile(filepath.Join(path, entry.Name()), &rules)
			}
			continue
		}
		readSudoersFile(path, &rules)
	}
	return rules
}

func readSudoersFile(path string, rules *sudoRules) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for lineIndex, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		subject := fields[0]
		spec := parseSudoersSpec(line)
		evidence := PrivilegeEvidence{
			Subject:    strings.TrimPrefix(subject, "%"),
			Privilege:  "sudo",
			Source:     relativeSudoersSource(path),
			Line:       lineIndex + 1,
			Command:    spec.Command,
			RunAs:      spec.RunAs,
			Options:    spec.Options,
			NoPassword: spec.NoPassword,
			Tags:       sudoersTags(spec),
		}
		if strings.HasPrefix(subject, "%") {
			group := strings.TrimPrefix(subject, "%")
			rules.groups[group] = true
			rules.evidenceByGroup[group] = append(rules.evidenceByGroup[group], evidence)
		} else {
			rules.users[subject] = true
			rules.evidenceByUser[subject] = append(rules.evidenceByUser[subject], evidence)
		}
	}
}

func relativeSudoersSource(path string) string {
	normalized := filepath.ToSlash(path)
	if index := strings.Index(normalized, "/etc/"); index >= 0 {
		return filepath.FromSlash(strings.TrimPrefix(normalized[index:], "/"))
	}
	return filepath.Clean(path)
}

type sudoersSpec struct {
	RunAs      string
	Options    []string
	NoPassword bool
	Command    string
}

func parseSudoersSpec(line string) sudoersSpec {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return sudoersSpec{}
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return sudoersSpec{}
	}
	prefix := strings.TrimSpace(parts[0])
	command := strings.TrimSpace(parts[1])
	spec := sudoersSpec{Command: command}
	if start := strings.Index(prefix, "("); start >= 0 {
		if end := strings.Index(prefix[start+1:], ")"); end >= 0 {
			spec.RunAs = strings.TrimSpace(prefix[start+1 : start+1+end])
		}
	}
	optionSource := strings.TrimSpace(command)
	if lastSpace := strings.LastIndex(prefix, " "); lastSpace >= 0 {
		optionSource = strings.TrimSpace(prefix[lastSpace+1:]) + ":" + command
	}
	spec.Options = sudoersOptions(optionSource)
	spec.NoPassword = linuxutil.ContainsString(spec.Options, "NOPASSWD")
	return spec
}

func sudoersOptions(value string) []string {
	var options []string
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ':' || r == ','
	}) {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		upper := strings.ToUpper(token)
		switch upper {
		case "NOPASSWD", "PASSWD", "NOEXEC", "SETENV", "NOSETENV", "LOG_INPUT", "LOG_OUTPUT":
			options = append(options, upper)
		}
	}
	return uniqueSorted(options)
}

func sudoersTags(spec sudoersSpec) []string {
	var tags []string
	if spec.NoPassword {
		tags = append(tags, "nopasswd")
	}
	if sudoersCommandIsDangerous(spec.Command) {
		tags = append(tags, "dangerous_command")
	}
	return uniqueSorted(tags)
}

func sudoersCommandIsDangerous(command string) bool {
	normalized := strings.ToLower(command)
	dangerous := []string{
		"all",
		"/bin/bash",
		"/bin/sh",
		"/usr/bin/bash",
		"/usr/bin/sh",
		"/usr/bin/su",
		"/bin/su",
		"/usr/bin/sudo",
		"/usr/bin/systemctl",
		"/bin/systemctl",
		"/usr/bin/vim",
		"/usr/bin/vi",
		"/usr/bin/nano",
		"/usr/bin/python",
		"/usr/bin/python3",
		"/usr/bin/perl",
		"/usr/bin/ruby",
		"/usr/bin/find",
		"/usr/bin/awk",
		"/usr/bin/sed",
		"/usr/bin/cp",
		"/usr/bin/chmod",
		"/usr/bin/chown",
	}
	for _, token := range dangerous {
		if normalized == token || strings.Contains(normalized, token+" ") || strings.Contains(normalized, token+",") {
			return true
		}
	}
	return false
}

func readPAMEvidence(pamDir string) []PrivilegeEvidence {
	entries, err := os.ReadDir(pamDir)
	if err != nil {
		return nil
	}
	var evidence []PrivilegeEvidence
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		evidence = append(evidence, readPAMFile(filepath.Join(pamDir, entry.Name()))...)
	}
	return evidence
}

func readPAMFile(path string) []PrivilegeEvidence {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	service := filepath.Base(path)
	source := relativeEtcSource(path)
	var evidence []PrivilegeEvidence
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		privilege, ok := pamPrivilege(fields[2])
		if !ok {
			continue
		}
		evidence = append(evidence, PrivilegeEvidence{
			Subject:    "pam:" + service,
			Privilege:  privilege,
			Source:     source,
			Line:       lineNumber,
			Command:    line,
			Control:    fields[1],
			Module:     strings.TrimSuffix(filepath.Base(fields[2]), ".so"),
			ModulePath: fields[2],
			Options:    pamOptions(fields),
			Tags:       pamRiskTags(fields[2], fields[1], fields[3:]),
		})
	}
	return evidence
}

func pamOptions(fields []string) []string {
	if len(fields) <= 3 {
		return nil
	}
	return append([]string{}, fields[3:]...)
}

func pamRiskTags(modulePath string, control string, args []string) []string {
	module := strings.TrimSuffix(filepath.Base(modulePath), ".so")
	var tags []string
	switch module {
	case "pam_exec":
		tags = append(tags, "pam_exec_hook")
		if linuxutil.ContainsString(args, "expose_authtok") {
			tags = append(tags, "pam_exposes_auth_token")
		}
	case "pam_python":
		tags = append(tags, "pam_python_hook")
	case "pam_permit":
		tags = append(tags, "pam_unconditional_permit")
	case "pam_rootok":
		tags = append(tags, "pam_rootok_trusts_uid0")
	case "pam_succeed_if":
		tags = append(tags, "pam_conditional_bypass")
	}
	if strings.Contains(modulePath, "/tmp/") || strings.Contains(modulePath, "/var/tmp/") || strings.Contains(modulePath, "/dev/shm/") {
		tags = append(tags, "pam_module_temp_path")
	}
	if control == "sufficient" || control == "optional" {
		tags = append(tags, "pam_non_required_control")
	}
	return tags
}

func pamPrivilege(module string) (string, bool) {
	module = filepath.Base(module)
	module = strings.TrimSuffix(module, ".so")
	switch module {
	case "pam_exec", "pam_python", "pam_permit", "pam_rootok", "pam_succeed_if":
		return module, true
	default:
		return "", false
	}
}

func readPolkitEvidence(root string) []PrivilegeEvidence {
	var evidence []PrivilegeEvidence
	for _, relDir := range []string{
		filepath.Join("etc", "polkit-1", "rules.d"),
		filepath.Join("usr", "share", "polkit-1", "rules.d"),
	} {
		entries, err := os.ReadDir(filepath.Join(root, relDir))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(entry.Name(), ".rules") {
				continue
			}
			relPath := filepath.Join(relDir, entry.Name())
			evidence = append(evidence, readPolkitRulesFile(filepath.Join(root, relPath), relPath)...)
		}
	}
	return evidence
}

func readPolkitRulesFile(path string, source string) []PrivilegeEvidence {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	var evidence []PrivilegeEvidence
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		subject, control, ok := polkitSubject(trimmed)
		if !ok {
			continue
		}
		action := polkitActionID(trimmed)
		result, resultLine := polkitResultNear(lines, index)
		if result == "" {
			continue
		}
		evidence = append(evidence, PrivilegeEvidence{
			Subject:   subject,
			Privilege: "polkit",
			Source:    source,
			Line:      resultLine,
			Command:   polkitCommandSummary(action, result),
			Control:   control,
			Options:   polkitOptions(action, result),
			Tags:      polkitRiskTags(action, result),
		})
	}
	return evidence
}

var (
	polkitGroupRe  = regexp.MustCompile(`subject\.isInGroup\(["']([^"']+)["']\)`)
	polkitUserRe   = regexp.MustCompile(`subject\.user\s*={2,3}\s*["']([^"']+)["']`)
	polkitActionRe = regexp.MustCompile(`action\.id\s*={2,3}\s*["']([^"']+)["']`)
	polkitResultRe = regexp.MustCompile(`polkit\.Result\.([A-Z_]+)`)
)

func polkitSubject(line string) (string, string, bool) {
	if match := polkitGroupRe.FindStringSubmatch(line); len(match) == 2 {
		return match[1], "group", true
	}
	if match := polkitUserRe.FindStringSubmatch(line); len(match) == 2 {
		return match[1], "user", true
	}
	return "", "", false
}

func polkitActionID(line string) string {
	if match := polkitActionRe.FindStringSubmatch(line); len(match) == 2 {
		return match[1]
	}
	return "*"
}

func polkitResultNear(lines []string, subjectLine int) (string, int) {
	for index := subjectLine; index < len(lines) && index <= subjectLine+8; index++ {
		if match := polkitResultRe.FindStringSubmatch(lines[index]); len(match) == 2 {
			return match[1], index + 1
		}
	}
	return "", 0
}

func polkitCommandSummary(action string, result string) string {
	if action == "" {
		action = "*"
	}
	return action + " => " + result
}

func polkitOptions(action string, result string) []string {
	var options []string
	if action != "" && action != "*" {
		options = append(options, action)
	}
	if result != "" {
		options = append(options, result)
	}
	return uniqueSorted(options)
}

func polkitRiskTags(action string, result string) []string {
	var tags []string
	switch result {
	case "YES":
		tags = append(tags, "polkit_allow")
	case "AUTH_SELF_KEEP", "AUTH_ADMIN_KEEP":
		tags = append(tags, "polkit_auth_keep")
	}
	if action == "*" {
		tags = append(tags, "polkit_allow_any")
	}
	if strings.Contains(action, "systemd1.manage-units") {
		tags = append(tags, "polkit_manage_units")
	}
	if strings.Contains(action, "packagekit") || strings.Contains(action, "apt") || strings.Contains(action, "dnf") {
		tags = append(tags, "polkit_package_management")
	}
	return uniqueSorted(tags)
}

func matchingPolkitEvidence(user User, evidence []PrivilegeEvidence) []PrivilegeEvidence {
	var matches []PrivilegeEvidence
	for _, item := range evidence {
		switch item.Control {
		case "user":
			if item.Subject == user.Username {
				matches = append(matches, item)
			}
		case "group":
			if linuxutil.ContainsString(user.SupplementaryGroups, item.Subject) || item.Subject == user.PrimaryGroup {
				matches = append(matches, item)
			}
		}
	}
	return matches
}

func relativeEtcSource(path string) string {
	normalized := filepath.ToSlash(path)
	if index := strings.Index(normalized, "/etc/"); index >= 0 {
		return filepath.FromSlash(strings.TrimPrefix(normalized[index:], "/"))
	}
	return filepath.Clean(path)
}

func readColonFile(path string) ([][]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var records [][]string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		records = append(records, strings.Split(line, ":"))
	}
	return records, scanner.Err()
}

func enrichSSHKeys(root string, user *User) {
	if strings.TrimSpace(user.Home) == "" {
		return
	}
	homeRel := strings.TrimPrefix(user.Home, string(os.PathSeparator))
	sshDir := filepath.Join(root, homeRel, ".ssh")
	sourcePrefix := filepath.Join(homeRel, ".ssh")
	user.SSHAuthorizedKeys = readAuthorizedKeys(filepath.Join(sshDir, "authorized_keys"), filepath.Join(sourcePrefix, "authorized_keys"))
	user.SSHKnownHosts = readKnownHosts(filepath.Join(sshDir, "known_hosts"), filepath.Join(sourcePrefix, "known_hosts"))
	user.SSHConfigHosts = readSSHConfigHosts(filepath.Join(sshDir, "config"), filepath.Join(sourcePrefix, "config"))
}

func readAuthorizedKeys(path string, source string) []SSHKey {
	return readSSHKeyLines(path, source, parseAuthorizedKeyLine)
}

func readKnownHosts(path string, source string) []SSHKey {
	return readSSHKeyLines(path, source, parseKnownHostLine)
}

func readSSHKeyLines(path string, source string, parser func(string, string, int) (SSHKey, bool)) []SSHKey {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var keys []SSHKey
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		key, ok := parser(scanner.Text(), source, lineNumber)
		if ok {
			keys = append(keys, key)
		}
	}
	return keys
}

func parseAuthorizedKeyLine(line string, source string, lineNumber int) (SSHKey, bool) {
	trimmed := strings.TrimSpace(line)
	fields := strings.Fields(trimmed)
	if len(fields) < 2 || strings.HasPrefix(trimmed, "#") {
		return SSHKey{}, false
	}
	keyIndex := sshKeyTypeIndex(fields)
	if keyIndex < 0 || keyIndex+1 >= len(fields) {
		return SSHKey{}, false
	}
	key := sshKeyFromFields(source, lineNumber, fields, keyIndex)
	if keyIndex > 0 {
		key.Options = strings.Join(fields[:keyIndex], " ")
	}
	if keyIndex+2 < len(fields) {
		key.Comment = strings.Join(fields[keyIndex+2:], " ")
	}
	return key, key.FingerprintSHA256 != ""
}

func parseKnownHostLine(line string, source string, lineNumber int) (SSHKey, bool) {
	trimmed := strings.TrimSpace(line)
	fields := strings.Fields(trimmed)
	if len(fields) < 3 || strings.HasPrefix(trimmed, "#") {
		return SSHKey{}, false
	}
	keyIndex := sshKeyTypeIndex(fields)
	if keyIndex < 1 || keyIndex+1 >= len(fields) {
		return SSHKey{}, false
	}
	key := sshKeyFromFields(source, lineNumber, fields, keyIndex)
	key.HostPattern = strings.Join(fields[:keyIndex], " ")
	key.HashedHost = strings.HasPrefix(key.HostPattern, "|1|")
	if keyIndex+2 < len(fields) {
		key.Comment = strings.Join(fields[keyIndex+2:], " ")
	}
	return key, key.FingerprintSHA256 != ""
}

func sshKeyFromFields(source string, lineNumber int, fields []string, keyIndex int) SSHKey {
	return SSHKey{
		Source:            source,
		Line:              lineNumber,
		KeyType:           fields[keyIndex],
		FingerprintSHA256: sshFingerprint(fields[keyIndex+1]),
	}
}

func sshKeyTypeIndex(fields []string) int {
	for index, field := range fields {
		if strings.HasPrefix(field, "ssh-") || strings.HasPrefix(field, "ecdsa-") || strings.HasPrefix(field, "sk-") {
			return index
		}
	}
	return -1
}

func sshFingerprint(encodedKey string) string {
	decoded, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(decoded)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

func readSSHConfigHosts(path string, source string) []SSHConfigHost {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var hosts []SSHConfigHost
	var current *SSHConfigHost
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := splitSSHConfigDirective(line)
		if !ok {
			continue
		}
		if strings.EqualFold(key, "Host") {
			if current != nil && current.HostPattern != "" {
				hosts = append(hosts, *current)
			}
			current = &SSHConfigHost{Source: source, Line: lineNumber, HostPattern: value}
			continue
		}
		if current == nil {
			continue
		}
		applySSHConfigDirective(current, key, value)
	}
	if current != nil && current.HostPattern != "" {
		hosts = append(hosts, *current)
	}
	return hosts
}

func splitSSHConfigDirective(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, " ")
	if !ok {
		key, value, ok = strings.Cut(line, "\t")
	}
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func applySSHConfigDirective(host *SSHConfigHost, key string, value string) {
	switch strings.ToLower(key) {
	case "hostname":
		host.HostName = value
	case "user":
		host.User = value
	case "port":
		host.Port = value
	case "identityfile":
		host.IdentityFile = value
	case "proxyjump":
		host.ProxyJump = value
	case "proxycommand":
		host.ProxyCommand = value
	}
}

func parseUID(value string) int {
	parsed := 0
	for _, char := range value {
		if char < '0' || char > '9' {
			return -1
		}
		parsed = parsed*10 + int(char-'0')
	}
	return parsed
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}
