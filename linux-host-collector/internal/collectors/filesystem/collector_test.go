package filesystem

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCollectBuildsLinuxFileSystemEvidence(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "etc"))
	mustMkdir(t, filepath.Join(root, "proc"))
	mustMkdir(t, filepath.Join(root, "var", "tmp"))
	mustWrite(t, filepath.Join(root, "proc", "mounts"), "/dev/sda1 / ext4 rw,relatime 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n", 0o444)
	mustWrite(t, filepath.Join(root, "etc", "passwd"), "root:x:0:0:root:/root:/bin/sh\n", 0o644)
	mustWrite(t, filepath.Join(root, "var", "tmp", ".hidden"), "secret", 0o666)
	if err := os.Chmod(filepath.Join(root, "var", "tmp", ".hidden"), 0o666); err != nil {
		t.Fatalf("chmod hidden fixture: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join("etc", "passwd"), filepath.Join(root, "passwd.link")); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
	}

	result, err := CollectWithOptions(root, Options{MaxEntries: 100, MaxDepth: 10})
	if err != nil {
		t.Fatalf("collect file system: %v", err)
	}

	if len(result.Volumes) != 1 {
		t.Fatalf("expected one volume, got %#v", result.Volumes)
	}
	if result.Volumes[0].VolumeID == "" {
		t.Fatalf("unexpected volume row: %#v", result.Volumes[0])
	}
	if result.Volumes[0].DevicePath != "/dev/sda1" || result.Volumes[0].FileSystem != "ext4" {
		t.Fatalf("expected linux mount metadata when mount source exists, got %#v", result.Volumes[0])
	}
	if result.Volumes[0].MountPoint != "/" {
		t.Fatalf("expected linux mount point, got %#v", result.Volumes[0])
	}
	if len(result.DirectoryNodes) == 0 {
		t.Fatalf("expected directory nodes")
	}

	passwd := findEntry(result.FileEntries, "/etc/passwd")
	if passwd == nil {
		t.Fatalf("expected /etc/passwd entry, got %#v", result.FileEntries)
	}
	if passwd.Inode == 0 || passwd.DeviceID == 0 || passwd.UID == "" || passwd.GID == "" {
		t.Fatalf("expected linux stat identifiers, got %#v", passwd)
	}
	if passwd.Mode == "" || passwd.Permissions == "" || passwd.FileType != "file" {
		t.Fatalf("expected linux mode fields, got %#v", passwd)
	}
	if passwd.MountPoint != "/" || passwd.FileSystem != "ext4" {
		t.Fatalf("expected linux mount metadata on file entry, got %#v", passwd)
	}
	if passwd.HashState != "not_hashed" || passwd.IsDeleted || !passwd.IsAllocated || passwd.TimestampSource != "stat" {
		t.Fatalf("unexpected compatible fields: %#v", passwd)
	}
	if passwd.ModifiedAt == "" || passwd.AccessedAt == "" || passwd.ChangedAt == "" {
		t.Fatalf("expected stat timestamps, got %#v", passwd)
	}

	hidden := findEntry(result.FileEntries, "/var/tmp/.hidden")
	if hidden == nil || !hidden.HiddenName || !hidden.WorldWritable {
		t.Fatalf("expected hidden world-writable evidence, got %#v", hidden)
	}

	link := findEntry(result.FileEntries, "/passwd.link")
	if runtime.GOOS != "windows" && (link == nil || link.FileType != "symlink" || link.LinkTarget == "") {
		t.Fatalf("expected symlink evidence, got %#v", link)
	}

	if len(result.TimelineEvents) == 0 {
		t.Fatalf("expected timeline events")
	}
	for _, event := range result.TimelineEvents {
		if event.EventID == "" || event.EntryID == "" || event.Path == "" || event.Timestamp == "" {
			t.Fatalf("timeline event missing identity fields: %#v", event)
		}
		if !strings.HasPrefix(event.EventType, "linux.file.") {
			t.Fatalf("expected linux file timeline event type, got %#v", event)
		}
	}
}

func TestEvidenceTagsForPathMarksSuspiciousPrivilegeFiles(t *testing.T) {
	category, tags := evidenceTagsForPath("/tmp/.cache/suid-shell", os.ModeSetuid|0o755)

	if category != "privilege_escalation" {
		t.Fatalf("expected privilege escalation category, got %q with tags %#v", category, tags)
	}
	for _, tag := range []string{"suid", "suid_temp_path", "hidden_path"} {
		if !testContains(tags, tag) {
			t.Fatalf("expected suspicious SUID tag %q, got %#v", tag, tags)
		}
	}
}

func TestCollectTagsContainerRuntimeEvidence(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "proc"))
	mustMkdir(t, filepath.Join(root, "var", "lib", "docker", "containers", "abc123"))
	mustMkdir(t, filepath.Join(root, "etc", "kubernetes"))
	mustWrite(t, filepath.Join(root, "proc", "mounts"), "/dev/sda1 / ext4 rw,relatime 0 0\n", 0o444)
	mustWrite(t, filepath.Join(root, "var", "lib", "docker", "containers", "abc123", "config.v2.json"), "{}", 0o600)
	mustWrite(t, filepath.Join(root, "var", "lib", "docker", "containers", "abc123", "abc123-json.log"), "{}", 0o600)
	mustWrite(t, filepath.Join(root, "etc", "kubernetes", "admin.conf"), "apiVersion: v1\n", 0o600)

	result, err := CollectWithOptions(root, Options{MaxEntries: 100, MaxDepth: 10})
	if err != nil {
		t.Fatalf("collect file system: %v", err)
	}

	containerConfig := findEntry(result.FileEntries, "/var/lib/docker/containers/abc123/config.v2.json")
	if containerConfig == nil || containerConfig.EvidenceCategory != "container" {
		t.Fatalf("expected container config evidence, got %#v", containerConfig)
	}
	if !testContains(containerConfig.EvidenceTags, "docker") || !testContains(containerConfig.EvidenceTags, "container_config") {
		t.Fatalf("expected docker config tags, got %#v", containerConfig.EvidenceTags)
	}
	containerLog := findEntry(result.FileEntries, "/var/lib/docker/containers/abc123/abc123-json.log")
	if containerLog == nil || !testContains(containerLog.EvidenceTags, "container_log") {
		t.Fatalf("expected container log tag, got %#v", containerLog)
	}
	kubeConfig := findEntry(result.FileEntries, "/etc/kubernetes/admin.conf")
	if kubeConfig == nil || kubeConfig.EvidenceCategory != "container" || !testContains(kubeConfig.EvidenceTags, "kubernetes_config") {
		t.Fatalf("expected kubernetes config evidence, got %#v", kubeConfig)
	}
}

func TestCollectExplainsHighRiskLinuxFileEvidence(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "proc"))
	mustMkdir(t, filepath.Join(root, "etc", "sudoers.d"))
	mustMkdir(t, filepath.Join(root, "etc", "pam.d"))
	mustMkdir(t, filepath.Join(root, "root", ".ssh"))
	mustMkdir(t, filepath.Join(root, "usr", "local", "bin"))
	mustWrite(t, filepath.Join(root, "proc", "mounts"), "/dev/sda1 / ext4 rw,relatime 0 0\n", 0o444)
	mustWrite(t, filepath.Join(root, "etc", "ld.so.preload"), "/tmp/libhide.so\n", 0o644)
	mustWrite(t, filepath.Join(root, "etc", "sudoers.d", "ops"), "ops ALL=(ALL) NOPASSWD:ALL\n", 0o440)
	mustWrite(t, filepath.Join(root, "etc", "pam.d", "sshd"), "auth required pam_unix.so\n", 0o644)
	mustWrite(t, filepath.Join(root, "root", ".ssh", "authorized_keys"), "ssh-ed25519 AAAA comment\n", 0o600)
	mustWrite(t, filepath.Join(root, "usr", "local", "bin", "backup"), "#!/bin/sh\nid\n", 0o777)
	if err := os.Chmod(filepath.Join(root, "usr", "local", "bin", "backup"), 0o777); err != nil {
		t.Fatalf("chmod backup fixture: %v", err)
	}

	result, err := CollectWithOptions(root, Options{MaxEntries: 100, MaxDepth: 10})
	if err != nil {
		t.Fatalf("collect file system: %v", err)
	}

	preload := findEntry(result.FileEntries, "/etc/ld.so.preload")
	if preload == nil || preload.EvidenceCategory != "privilege_escalation" || !testContains(preload.EvidenceTags, "ld_so_preload") {
		t.Fatalf("expected ld.so.preload evidence, got %#v", preload)
	}
	if !testContains(preload.EvidenceReasons, "Dynamic linker preload affects process library loading and is a common persistence or hijack point.") {
		t.Fatalf("expected ld.so.preload explanation, got %#v", preload.EvidenceReasons)
	}
	sudoers := findEntry(result.FileEntries, "/etc/sudoers.d/ops")
	if sudoers == nil || !testContains(sudoers.EvidenceTags, "sudoers_policy") {
		t.Fatalf("expected sudoers policy evidence, got %#v", sudoers)
	}
	rootKey := findEntry(result.FileEntries, "/root/.ssh/authorized_keys")
	if rootKey == nil || !testContains(rootKey.EvidenceTags, "ssh_authorized_keys") {
		t.Fatalf("expected root authorized_keys evidence, got %#v", rootKey)
	}
	localBin := findEntry(result.FileEntries, "/usr/local/bin/backup")
	if localBin == nil || !localBin.WorldWritable || !testContains(localBin.EvidenceTags, "world_writable_exec_path") {
		t.Fatalf("expected writable executable path evidence, got %#v", localBin)
	}
	if !testContains(localBin.EvidenceReasons, "World-writable executable search paths can let untrusted users replace commands used by services or scripts.") {
		t.Fatalf("expected world writable executable explanation, got %#v", localBin.EvidenceReasons)
	}
}

func TestLinuxSecurityAttributesFromXattrs(t *testing.T) {
	attrs := securityAttributesFromXattrs(map[string][]byte{
		"security.selinux":         []byte("system_u:object_r:sshd_exec_t:s0\x00"),
		"security.capability":      []byte{0x01, 0x02, 0x03},
		"system.posix_acl_access":  []byte{0x02},
		"system.posix_acl_default": []byte{0x03},
		"user.comment":             []byte("ignored"),
		"security.ima":             []byte("integrity"),
		"trusted.overlay.opaque":   []byte("y"),
	})

	if attrs.SELinuxContext != "system_u:object_r:sshd_exec_t:s0" {
		t.Fatalf("expected SELinux context, got %#v", attrs)
	}
	if attrs.LinuxCapabilities != "010203" {
		t.Fatalf("expected hex encoded capability xattr, got %#v", attrs)
	}
	if !attrs.HasACL || attrs.ACLTypes == nil || !testContains(attrs.ACLTypes, "access") || !testContains(attrs.ACLTypes, "default") {
		t.Fatalf("expected ACL markers, got %#v", attrs)
	}
	for _, name := range []string{"security.capability", "security.ima", "security.selinux", "system.posix_acl_access", "system.posix_acl_default", "trusted.overlay.opaque"} {
		if !testContains(attrs.XattrNames, name) {
			t.Fatalf("expected security xattr name %q in %#v", name, attrs.XattrNames)
		}
	}
	if testContains(attrs.XattrNames, "user.comment") {
		t.Fatalf("expected non-security xattr to be omitted, got %#v", attrs.XattrNames)
	}
}

func TestCollectSkipsPseudoPathsAndHonorsEntryLimit(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "proc"))
	mustWrite(t, filepath.Join(root, "proc", "dynamic"), "skip", 0o644)
	mustWrite(t, filepath.Join(root, "kept"), "keep", 0o644)

	result, err := CollectWithOptions(root, Options{MaxEntries: 1, MaxDepth: 10})
	if err != nil {
		t.Fatalf("collect file system: %v", err)
	}
	if findEntry(result.FileEntries, "/proc/dynamic") != nil {
		t.Fatalf("expected pseudo path to be skipped, got %#v", result.FileEntries)
	}
	if len(result.FileEntries) > 1 {
		t.Fatalf("expected entry limit to be honored, got %#v", result.FileEntries)
	}
	if len(result.Diagnostics) == 0 {
		t.Fatalf("expected limit or skip diagnostics")
	}
}

func findEntry(entries []FileEntry, path string) *FileEntry {
	for i := range entries {
		if entries[i].Path == path {
			return &entries[i]
		}
	}
	return nil
}

func testContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWrite(t *testing.T, path string, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
