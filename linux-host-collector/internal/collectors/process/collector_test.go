package process

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectProcessesFromProcfsFixture(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect processes: %v", err)
	}
	if len(result.Processes) < 3 {
		t.Fatalf("expected fixture processes, got %#v", result.Processes)
	}
	if result.Processes[0].PID != 1 || result.Processes[0].Name != "systemd" {
		t.Fatalf("expected pid 1 systemd, got %#v", result.Processes[0])
	}
	if result.Processes[1].PPID != 1 || result.Processes[1].CommandLine != "/usr/sbin/sshd -D" {
		t.Fatalf("expected sshd child command line, got %#v", result.Processes[1])
	}
	if result.Processes[2].PID != 3 || result.Processes[2].Name != "nginx" || result.Processes[2].CommandLine != "/usr/sbin/nginx -c /etc/nginx/nginx.conf" {
		t.Fatalf("expected nginx web log fixture process, got %#v", result.Processes[2])
	}
}

func TestCollectLinuxProcessDetailsFromProcfsFixture(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect processes: %v", err)
	}

	proc := findProcess(result.Processes, 957)
	if proc == nil {
		t.Fatalf("expected accounts-daemon process, got %#v", result.Processes)
	}
	if proc.Name != "accounts-daemon" || proc.ImagePath == "" || proc.User == "" {
		t.Fatalf("expected linux process basics, got %#v", proc)
	}
	if proc.ThreadCount != 2 || proc.ParentPid != 1 {
		t.Fatalf("expected linux process counts and parent, got %#v", proc)
	}
	if proc.ParentProcessName != "systemd" || proc.ParentCommandLine != "/sbin/init" {
		t.Fatalf("expected parent process identity, got %#v", proc)
	}
	if proc.ProcessPath == "" || proc.CreateTime != "2023-11-15T01:39:05Z" || proc.CreatedAt != proc.CreateTime || proc.SessionID == "" || proc.BasePriority == "" {
		t.Fatalf("expected enriched process basics, got %#v", proc)
	}
	if proc.HandleCount == 0 || proc.Is64BitProcess != true || proc.DomainName != "linux" {
		t.Fatalf("expected linux process handle count and architecture markers, got %#v", proc)
	}
	details := result.ProcessDetails["957"]
	if details.IOStats == nil || details.IOStats.ReadCount == 0 || details.IOStats.ReadTransferCount == 0 {
		t.Fatalf("expected io stats, got %#v", details.IOStats)
	}
	if len(details.MemoryBlocks) == 0 || len(details.Modules) == 0 || len(details.Threads) == 0 {
		t.Fatalf("expected process details, got %#v", details)
	}
	if len(details.NetworkConnections) == 0 {
		t.Fatalf("expected socket inode network connection, got %#v", details.NetworkConnections)
	}
	if details.NetworkConnections[0].ProcessID != 957 || details.NetworkConnections[0].ProcessName != "accounts-daemon" {
		t.Fatalf("expected process-owned network connection, got %#v", details.NetworkConnections)
	}
	if len(details.Handles) == 0 || details.Handles[0].Kind == "" || details.Handles[0].Target == "" {
		t.Fatalf("expected linux fd handles, got %#v", details.Handles)
	}
	if len(details.Windows) != 0 {
		t.Fatalf("linux must not synthesize windows-only windows, got %#v", details)
	}
}

func TestCollectLinuxProcessFileIdentityFromProcExe(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "proc", "100")
	binDir := filepath.Join(root, "usr", "bin")
	workDir := filepath.Join(root, "srv", "app")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatalf("create proc dir: %v", err)
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create bin dir: %v", err)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("create working dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc", "stat"), []byte("btime 1700000000\n"), 0o644); err != nil {
		t.Fatalf("write proc stat: %v", err)
	}
	status := "Name:\tsuspiciousd\nPid:\t100\nPPid:\t1\nUid:\t0\t0\t0\t0\nThreads:\t1\n"
	if err := os.WriteFile(filepath.Join(procDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cmdline"), []byte("/usr/bin/suspiciousd\x00--daemon"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	environ := "LD_PRELOAD=/tmp/libhide.so\x00PATH=/tmp/bin:/usr/bin\x00AWS_SECRET_ACCESS_KEY=secret-value\x00container=docker\x00"
	if err := os.WriteFile(filepath.Join(procDir, "environ"), []byte(environ), 0o600); err != nil {
		t.Fatalf("write environ: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "stat"), []byte("100 (suspiciousd) S 1 100 100 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 100\n"), 0o644); err != nil {
		t.Fatalf("write stat: %v", err)
	}
	exePath := filepath.Join(binDir, "suspiciousd")
	if err := os.WriteFile(exePath, []byte("suspicious executable bytes"), 0o755); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	if err := os.Symlink("/usr/bin/suspiciousd", filepath.Join(procDir, "exe")); err != nil {
		t.Fatalf("symlink exe: %v", err)
	}
	if err := os.Symlink("/srv/app", filepath.Join(procDir, "cwd")); err != nil {
		t.Fatalf("symlink cwd: %v", err)
	}
	if err := os.Symlink("/", filepath.Join(procDir, "root")); err != nil {
		t.Fatalf("symlink root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte("0::/system.slice/suspicious.service\n"), 0o644); err != nil {
		t.Fatalf("write cgroup: %v", err)
	}
	nsDir := filepath.Join(procDir, "ns")
	if err := os.MkdirAll(nsDir, 0o755); err != nil {
		t.Fatalf("create ns dir: %v", err)
	}
	if err := os.Symlink("mnt:[4026531840]", filepath.Join(nsDir, "mnt")); err != nil {
		t.Fatalf("symlink mnt ns: %v", err)
	}
	if err := os.Symlink("pid:[4026531836]", filepath.Join(nsDir, "pid")); err != nil {
		t.Fatalf("symlink pid ns: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect processes: %v", err)
	}

	proc := findProcess(result.Processes, 100)
	if proc == nil {
		t.Fatalf("expected process 100, got %#v", result.Processes)
	}
	if proc.FileIdentityID == "" || proc.SHA256 == "" || proc.HashState != "completed" || proc.SignatureState != "unsupported" {
		t.Fatalf("expected process file identity fields, got %#v", proc)
	}
	if proc.Deleted || len(proc.RiskTags) != 0 {
		t.Fatalf("did not expect deleted process image for fixture executable, got %#v", proc)
	}
	if proc.WorkingDirectory != "/srv/app" || proc.RootPath != "/" {
		t.Fatalf("expected process cwd/root context, got %#v", proc)
	}
	if len(proc.Cgroups) != 1 || proc.Cgroups[0] != "0::/system.slice/suspicious.service" {
		t.Fatalf("expected cgroup context, got %#v", proc)
	}
	if proc.Container.ID != "" || proc.Container.Runtime != "" {
		t.Fatalf("did not expect host service to be attributed to a container, got %#v", proc.Container)
	}
	if proc.Namespaces["mnt"] != "mnt:[4026531840]" || proc.Namespaces["pid"] != "pid:[4026531836]" {
		t.Fatalf("expected namespace context, got %#v", proc)
	}
	if len(proc.Environment) != 4 {
		t.Fatalf("expected process environment summary, got %#v", proc.Environment)
	}
	secret := findEnvironmentVariable(proc.Environment, "AWS_SECRET_ACCESS_KEY")
	if secret == nil || !secret.Redacted || secret.Value != "[REDACTED]" {
		t.Fatalf("expected sensitive environment variable redaction, got %#v", secret)
	}
	preload := findEnvironmentVariable(proc.Environment, "LD_PRELOAD")
	if preload == nil || preload.Value != "/tmp/libhide.so" || !containsString(preload.Tags, "ld_preload") || !containsString(preload.Tags, "temp_path") {
		t.Fatalf("expected LD_PRELOAD environment evidence, got %#v", preload)
	}
	path := findEnvironmentVariable(proc.Environment, "PATH")
	if path == nil || !containsString(path.Tags, "path_temp_directory") {
		t.Fatalf("expected PATH environment evidence, got %#v", path)
	}
	if len(result.FileIdentities) != 1 {
		t.Fatalf("expected one file identity, got %#v", result.FileIdentities)
	}
	identity := result.FileIdentities[0]
	if identity.ID != proc.FileIdentityID || identity.SHA256 != proc.SHA256 {
		t.Fatalf("expected process and identity to reference same digest, got process=%#v identity=%#v", proc, identity)
	}
	if identity.Path != "/usr/bin/suspiciousd" || identity.Basename != "suspiciousd" || identity.HashState != "completed" {
		t.Fatalf("unexpected file identity basics: %#v", identity)
	}
	if identity.SignatureState != "unsupported" || !containsString(identity.EvidenceSources, "process.image") {
		t.Fatalf("unexpected file identity evidence: %#v", identity)
	}
}

func TestCollectLinuxDeletedExecutableAndMappedLibraries(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "proc", "200")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatalf("create proc dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc", "stat"), []byte("btime 1700000000\n"), 0o644); err != nil {
		t.Fatalf("write proc stat: %v", err)
	}
	status := "Name:\tghostd\nPid:\t200\nPPid:\t1\nUid:\t0\t0\t0\t0\nThreads:\t1\n"
	if err := os.WriteFile(filepath.Join(procDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cmdline"), []byte("/tmp/ghostd\x00--stealth"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	if err := os.Symlink("/tmp/ghostd (deleted)", filepath.Join(procDir, "exe")); err != nil {
		t.Fatalf("symlink exe: %v", err)
	}
	maps := "" +
		"55f2b7c00000-55f2b7c21000 r-xp 00000000 08:01 12345 /tmp/ghostd (deleted)\n" +
		"7f2b7c000000-7f2b7c100000 r-xp 00000000 08:01 23456 /tmp/libhide.so (deleted)\n"
	if err := os.WriteFile(filepath.Join(procDir, "maps"), []byte(maps), 0o644); err != nil {
		t.Fatalf("write maps: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect processes: %v", err)
	}

	proc := findProcess(result.Processes, 200)
	if proc == nil {
		t.Fatalf("expected process 200, got %#v", result.Processes)
	}
	if !proc.Deleted || !containsString(proc.RiskTags, "deleted_executable") {
		t.Fatalf("expected deleted process executable risk, got %#v", proc)
	}
	details := result.ProcessDetails["200"]
	module := findModule(details.Modules, "/tmp/libhide.so")
	if module == nil || !module.Deleted || !containsString(module.RiskTags, "deleted_module") {
		t.Fatalf("expected deleted mapped library evidence, got %#v", details.Modules)
	}
	block := findMemoryBlock(details.MemoryBlocks, "/tmp/ghostd")
	if block == nil || !block.Deleted || !containsString(block.RiskTags, "deleted_mapping") {
		t.Fatalf("expected deleted executable memory mapping, got %#v", details.MemoryBlocks)
	}
}

func TestCollectLinuxProcessContainerOwnershipFromCgroup(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "proc", "300")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatalf("create proc dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc", "stat"), []byte("btime 1700000000\n"), 0o644); err != nil {
		t.Fatalf("write proc stat: %v", err)
	}
	status := "Name:\tnginx\nPid:\t300\nPPid:\t1\nUid:\t0\t0\t0\t0\nThreads:\t1\n"
	if err := os.WriteFile(filepath.Join(procDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cmdline"), []byte("nginx\x00-g\x00daemon off;"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	cgroup := "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n"
	if err := os.WriteFile(filepath.Join(procDir, "cgroup"), []byte(cgroup), 0o644); err != nil {
		t.Fatalf("write cgroup: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect processes: %v", err)
	}

	proc := findProcess(result.Processes, 300)
	if proc == nil {
		t.Fatalf("expected process 300, got %#v", result.Processes)
	}
	if proc.Container.Runtime != "containerd" || proc.Container.ID != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("expected containerd ownership from cgroup, got %#v", proc.Container)
	}
	if proc.Container.Orchestrator != "kubernetes" || proc.Container.PodUID != "123" {
		t.Fatalf("expected kubernetes pod ownership, got %#v", proc.Container)
	}
	if !containsString(proc.RiskTags, "container_process") {
		t.Fatalf("expected container process risk tag, got %#v", proc.RiskTags)
	}
}

func TestCollectLinuxSuspiciousMemoryMapRiskTags(t *testing.T) {
	root := t.TempDir()
	procDir := filepath.Join(root, "proc", "400")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatalf("create proc dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc", "stat"), []byte("btime 1700000000\n"), 0o644); err != nil {
		t.Fatalf("write proc stat: %v", err)
	}
	status := "Name:\tloader\nPid:\t400\nPPid:\t1\nUid:\t0\t0\t0\t0\nThreads:\t1\n"
	if err := os.WriteFile(filepath.Join(procDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatalf("write status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "cmdline"), []byte("loader"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}
	maps := "" +
		"7f2b7c000000-7f2b7c010000 rwxp 00000000 00:00 0 \n" +
		"7f2b7d000000-7f2b7d010000 r-xp 00000000 00:00 0 /dev/shm/payload.so\n"
	if err := os.WriteFile(filepath.Join(procDir, "maps"), []byte(maps), 0o644); err != nil {
		t.Fatalf("write maps: %v", err)
	}

	result, err := Collect(root)
	if err != nil {
		t.Fatalf("collect processes: %v", err)
	}

	details := result.ProcessDetails["400"]
	anonymous := findMemoryBlock(details.MemoryBlocks, "")
	if anonymous == nil || !containsString(anonymous.RiskTags, "anonymous_executable_mapping") || !containsString(anonymous.RiskTags, "writable_executable_mapping") {
		t.Fatalf("expected anonymous writable executable memory risk, got %#v", details.MemoryBlocks)
	}
	shmModule := findModule(details.Modules, "/dev/shm/payload.so")
	if shmModule == nil || !containsString(shmModule.RiskTags, "temp_path_module") {
		t.Fatalf("expected temp path module risk, got %#v", details.Modules)
	}
}

func findProcess(processes []Process, pid int) *Process {
	for i := range processes {
		if processes[i].PID == pid {
			return &processes[i]
		}
	}
	return nil
}

func findEnvironmentVariable(values []EnvironmentVariable, key string) *EnvironmentVariable {
	for i := range values {
		if values[i].Key == key {
			return &values[i]
		}
	}
	return nil
}

func findModule(values []Module, path string) *Module {
	for i := range values {
		if values[i].Path == path {
			return &values[i]
		}
	}
	return nil
}

func findMemoryBlock(values []MemoryBlock, owner string) *MemoryBlock {
	for i := range values {
		if values[i].Owner == owner {
			return &values[i]
		}
	}
	return nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
