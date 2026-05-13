package accounts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectAccountsFromPasswdAndGroup(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect accounts: %v", err)
	}
	if len(result.Users) != 4 {
		t.Fatalf("expected 4 users, got %#v", result.Users)
	}
	alice := findUser(result.Users, "alice")
	if alice == nil || alice.UID != "1000" {
		t.Fatalf("expected alice user, got %#v", result.Users)
	}
	if len(result.Groups) != 5 {
		t.Fatalf("expected 5 groups, got %#v", result.Groups)
	}
	if findGroup(result.Groups, "sudo") == nil {
		t.Fatalf("expected sudo group, got %#v", result.Groups)
	}
}

func TestCollectLinuxAccountRiskFromFixture(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect accounts: %v", err)
	}

	alice := findUser(result.Users, "alice")
	if alice == nil {
		t.Fatalf("expected alice user, got %#v", result.Users)
	}
	if alice.AccountType != "regular" || alice.LoginShell == "" || alice.RiskLevel == "" {
		t.Fatalf("expected linux account model, got %#v", alice)
	}
	if !testContains(alice.SupplementaryGroups, "sudo") {
		t.Fatalf("expected sudo group membership, got %#v", alice)
	}
	if alice.PrivilegeLevel != "sudo" || alice.PasswordState != "set" {
		t.Fatalf("expected sudo privilege and password state, got %#v", alice)
	}
	if alice.Platform != "linux" {
		t.Fatalf("expected linux platform, got %#v", alice)
	}

	apt := findUser(result.Users, "_apt")
	if apt == nil || apt.AccountType != "system" || apt.LoginAbility != "nologin" {
		t.Fatalf("expected system nologin account, got %#v", apt)
	}
}

func TestCollectIncludesSudoersDropInPrivilegeEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "sudoers.d"), 0o755); err != nil {
		t.Fatalf("create sudoers.d: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("bob:x:1000:1000:Bob:/home/bob:/bin/bash\n"), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte("bob:x:1000:\n"), 0o644); err != nil {
		t.Fatalf("write group: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "sudoers.d", "99-bob"), []byte("bob ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n"), 0o440); err != nil {
		t.Fatalf("write sudoers drop-in: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect accounts: %v", err)
	}

	bob := findUser(result.Users, "bob")
	if bob == nil {
		t.Fatalf("expected bob user, got %#v", result.Users)
	}
	if bob.PrivilegeLevel != "sudo" || bob.RiskLevel != "medium" {
		t.Fatalf("expected sudo privilege from drop-in, got %#v", bob)
	}
	if len(bob.PrivilegeEvidence) != 1 {
		t.Fatalf("expected sudoers drop-in evidence, got %#v", bob.PrivilegeEvidence)
	}
	evidence := bob.PrivilegeEvidence[0]
	if evidence.Source != filepath.Join("etc", "sudoers.d", "99-bob") || evidence.Line != 1 || evidence.Command != "/usr/bin/systemctl" {
		t.Fatalf("unexpected sudoers evidence: %#v", evidence)
	}
	if evidence.RunAs != "ALL" || !evidence.NoPassword || !testContains(evidence.Options, "NOPASSWD") {
		t.Fatalf("expected sudoers runas and NOPASSWD metadata, got %#v", evidence)
	}
	if !testContains(evidence.Tags, "dangerous_command") {
		t.Fatalf("expected dangerous command tag, got %#v", evidence)
	}
	if !testContains(bob.RiskReasons, "sudo_nopasswd") || !testContains(bob.RiskReasons, "sudo_dangerous_command") {
		t.Fatalf("expected sudoers risk reasons, got %#v", bob.RiskReasons)
	}
}

func TestCollectIncludesPAMPrivilegeEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "pam.d"), 0o755); err != nil {
		t.Fatalf("create pam.d: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte("alice:x:1000:\n"), 0o644); err != nil {
		t.Fatalf("write group: %v", err)
	}
	pamConfig := "" +
		"auth optional pam_exec.so expose_authtok /usr/local/libexec/pam-backdoor\n" +
		"account sufficient pam_permit.so\n"
	if err := os.WriteFile(filepath.Join(root, "etc", "pam.d", "sshd"), []byte(pamConfig), 0o644); err != nil {
		t.Fatalf("write pam config: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect accounts: %v", err)
	}

	alice := findUser(result.Users, "alice")
	if alice == nil {
		t.Fatalf("expected alice user, got %#v", result.Users)
	}
	if len(alice.PrivilegeEvidence) != 2 {
		t.Fatalf("expected PAM evidence to be attached to users, got %#v", alice.PrivilegeEvidence)
	}
	execEvidence := findPrivilegeEvidence(alice.PrivilegeEvidence, "pam_exec")
	if execEvidence.Source != filepath.Join("etc", "pam.d", "sshd") || execEvidence.Line != 1 {
		t.Fatalf("unexpected pam_exec evidence: %#v", execEvidence)
	}
	if execEvidence.Command != "auth optional pam_exec.so expose_authtok /usr/local/libexec/pam-backdoor" {
		t.Fatalf("unexpected pam_exec command: %#v", execEvidence)
	}
	if execEvidence.Module != "pam_exec" || execEvidence.Control != "optional" || execEvidence.ModulePath != "pam_exec.so" {
		t.Fatalf("expected structured pam_exec metadata, got %#v", execEvidence)
	}
	if !testContains(execEvidence.Options, "expose_authtok") || !testContains(execEvidence.Options, "/usr/local/libexec/pam-backdoor") {
		t.Fatalf("expected pam_exec arguments in options, got %#v", execEvidence.Options)
	}
	if !testContains(execEvidence.Tags, "pam_exec_hook") || !testContains(execEvidence.Tags, "pam_exposes_auth_token") {
		t.Fatalf("expected pam_exec risk tags, got %#v", execEvidence.Tags)
	}
	permitEvidence := findPrivilegeEvidence(alice.PrivilegeEvidence, "pam_permit")
	if permitEvidence.Source != filepath.Join("etc", "pam.d", "sshd") || permitEvidence.Line != 2 {
		t.Fatalf("unexpected pam_permit evidence: %#v", permitEvidence)
	}
	if permitEvidence.Module != "pam_permit" || !testContains(permitEvidence.Tags, "pam_unconditional_permit") {
		t.Fatalf("expected pam_permit structured risk metadata, got %#v", permitEvidence)
	}
}

func TestCollectIncludesPolkitPrivilegeEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "polkit-1", "rules.d"), 0o755); err != nil {
		t.Fatalf("create polkit rules dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte("alice:x:1000:\nsudo:x:27:alice\n"), 0o644); err != nil {
		t.Fatalf("write group: %v", err)
	}
	rule := "" +
		"polkit.addRule(function(action, subject) {\n" +
		"  if (subject.isInGroup(\"sudo\") && action.id == \"org.freedesktop.systemd1.manage-units\") {\n" +
		"    return polkit.Result.YES;\n" +
		"  }\n" +
		"});\n"
	if err := os.WriteFile(filepath.Join(root, "etc", "polkit-1", "rules.d", "49-sudo.rules"), []byte(rule), 0o644); err != nil {
		t.Fatalf("write polkit rule: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect accounts: %v", err)
	}

	alice := findUser(result.Users, "alice")
	if alice == nil {
		t.Fatalf("expected alice user, got %#v", result.Users)
	}
	evidence := findPrivilegeEvidence(alice.PrivilegeEvidence, "polkit")
	if evidence.Subject != "sudo" || evidence.Source != filepath.Join("etc", "polkit-1", "rules.d", "49-sudo.rules") || evidence.Line != 3 {
		t.Fatalf("unexpected polkit evidence identity: %#v", evidence)
	}
	if evidence.Command != "org.freedesktop.systemd1.manage-units => YES" || evidence.Control != "group" {
		t.Fatalf("unexpected polkit command metadata: %#v", evidence)
	}
	if !testContains(evidence.Options, "org.freedesktop.systemd1.manage-units") || !testContains(evidence.Tags, "polkit_allow") || !testContains(evidence.Tags, "polkit_manage_units") {
		t.Fatalf("expected polkit risk metadata, got %#v", evidence)
	}
	if !testContains(alice.RiskReasons, "polkit_privilege") || !testContains(alice.RiskReasons, "polkit_manage_units") {
		t.Fatalf("expected polkit risk reasons, got %#v", alice.RiskReasons)
	}
}

func TestCollectIncludesSSHAuthorizedKeysAndKnownHosts(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatalf("create etc: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "home", "alice", ".ssh"), 0o700); err != nil {
		t.Fatalf("create ssh dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"), 0o644); err != nil {
		t.Fatalf("write passwd: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "group"), []byte("alice:x:1000:\n"), 0o644); err != nil {
		t.Fatalf("write group: %v", err)
	}
	authorizedKeys := "" +
		"# comment\n" +
		"ssh-rsa AQIDBAUG alice@example\n" +
		"command=\"/usr/local/bin/backup\",no-pty ssh-ed25519 BwgJCgsM backup-key\n"
	if err := os.WriteFile(filepath.Join(root, "home", "alice", ".ssh", "authorized_keys"), []byte(authorizedKeys), 0o600); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}
	knownHosts := "" +
		"github.com,140.82.112.4 ssh-ed25519 DQ4PEA==\n" +
		"|1|salt|hash ssh-rsa ERITFA==\n"
	if err := os.WriteFile(filepath.Join(root, "home", "alice", ".ssh", "known_hosts"), []byte(knownHosts), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	sshConfig := "" +
		"Host prod-db *.internal\n" +
		"  HostName 10.0.0.20\n" +
		"  User deploy\n" +
		"  Port 2222\n" +
		"  IdentityFile ~/.ssh/prod_ed25519\n" +
		"  ProxyJump bastion.example.com\n"
	if err := os.WriteFile(filepath.Join(root, "home", "alice", ".ssh", "config"), []byte(sshConfig), 0o600); err != nil {
		t.Fatalf("write ssh config: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect accounts: %v", err)
	}

	alice := findUser(result.Users, "alice")
	if alice == nil {
		t.Fatalf("expected alice user, got %#v", result.Users)
	}
	if len(alice.SSHAuthorizedKeys) != 2 {
		t.Fatalf("expected two authorized keys, got %#v", alice.SSHAuthorizedKeys)
	}
	firstKey := alice.SSHAuthorizedKeys[0]
	if firstKey.KeyType != "ssh-rsa" || firstKey.Comment != "alice@example" || firstKey.FingerprintSHA256 == "" {
		t.Fatalf("expected parsed authorized key metadata, got %#v", firstKey)
	}
	if firstKey.PublicKey != "" {
		t.Fatalf("expected public key material to be omitted, got %#v", firstKey)
	}
	secondKey := alice.SSHAuthorizedKeys[1]
	if secondKey.Options != `command="/usr/local/bin/backup",no-pty` || secondKey.KeyType != "ssh-ed25519" {
		t.Fatalf("expected key options and type, got %#v", secondKey)
	}
	if len(alice.SSHKnownHosts) != 2 {
		t.Fatalf("expected two known hosts, got %#v", alice.SSHKnownHosts)
	}
	if alice.SSHKnownHosts[0].HostPattern != "github.com,140.82.112.4" || alice.SSHKnownHosts[0].KeyType != "ssh-ed25519" {
		t.Fatalf("expected known_hosts metadata, got %#v", alice.SSHKnownHosts[0])
	}
	if !alice.SSHKnownHosts[1].HashedHost {
		t.Fatalf("expected hashed known_host marker, got %#v", alice.SSHKnownHosts[1])
	}
	if len(alice.SSHConfigHosts) != 1 {
		t.Fatalf("expected one ssh config host, got %#v", alice.SSHConfigHosts)
	}
	configHost := alice.SSHConfigHosts[0]
	if configHost.HostPattern != "prod-db *.internal" || configHost.HostName != "10.0.0.20" || configHost.User != "deploy" {
		t.Fatalf("unexpected ssh config host identity: %#v", configHost)
	}
	if configHost.Port != "2222" || configHost.IdentityFile != "~/.ssh/prod_ed25519" || configHost.ProxyJump != "bastion.example.com" {
		t.Fatalf("unexpected ssh config routing metadata: %#v", configHost)
	}
}

func findUser(users []User, username string) *User {
	for i := range users {
		if users[i].Username == username {
			return &users[i]
		}
	}
	return nil
}

func findGroup(groups []Group, name string) *Group {
	for i := range groups {
		if groups[i].Name == name {
			return &groups[i]
		}
	}
	return nil
}

func findPrivilegeEvidence(items []PrivilegeEvidence, privilege string) PrivilegeEvidence {
	for _, item := range items {
		if item.Privilege == privilege {
			return item
		}
	}
	return PrivilegeEvidence{}
}

func testContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
