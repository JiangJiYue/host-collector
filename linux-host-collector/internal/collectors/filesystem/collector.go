package filesystem

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"collector-shared/linuxutil"
)

const (
	defaultMaxEntries = 200000
	defaultMaxDepth   = 128
)

type Options struct {
	MaxEntries int
	MaxDepth   int
}

type Result struct {
	Volumes        []VolumeInfo     `json:"forensicVolumes"`
	DirectoryNodes []DirectoryNode  `json:"forensicDirectoryNodes"`
	FileEntries    []FileEntry      `json:"forensicFileEntries"`
	TimelineEvents []TimelineEvent  `json:"forensicTimelineEvents"`
	Diagnostics    []DiagnosticItem `json:"forensicDiagnostics,omitempty"`
}

type VolumeInfo struct {
	VolumeID             string `json:"volumeId"`
	DevicePath           string `json:"devicePath"`
	DriveLetter          string `json:"driveLetter,omitempty"`
	FileSystem           string `json:"filesystem,omitempty"`
	FilesystemProbeError string `json:"filesystemProbeError,omitempty"`
	SerialNumber         string `json:"serialNumber,omitempty"`
	BytesPerSector       uint16 `json:"bytesPerSector,omitempty"`
	SectorsPerCluster    uint8  `json:"sectorsPerCluster,omitempty"`
	ClusterSize          int64  `json:"clusterSize,omitempty"`
	MFTStartLCN          int64  `json:"mftStartLcn,omitempty"`
	FileRecordSize       int64  `json:"fileRecordSize,omitempty"`
	DeviceID             uint64 `json:"deviceId,omitempty"`
	MountPoint           string `json:"mountPoint,omitempty"`
}

type DirectoryNode struct {
	NodeID         string `json:"nodeId"`
	VolumeID       string `json:"volumeId"`
	MFTEntry       int64  `json:"mftEntry"`
	MFTSequence    int64  `json:"mftSequence,omitempty"`
	ParentMFTEntry int64  `json:"parentMftEntry"`
	Path           string `json:"path"`
	ParentPath     string `json:"parentPath,omitempty"`
	Name           string `json:"name"`
	IsOrphan       bool   `json:"isOrphan,omitempty"`
	Inode          uint64 `json:"inode,omitempty"`
	DeviceID       uint64 `json:"deviceId,omitempty"`
}

type FileEntry struct {
	EntryID                  string   `json:"entryId"`
	VolumeID                 string   `json:"volumeId"`
	MFTEntry                 int64    `json:"mftEntry"`
	MFTSequence              int64    `json:"mftSequence"`
	ParentMFTEntry           int64    `json:"parentMftEntry"`
	Path                     string   `json:"path"`
	ParentPath               string   `json:"parentPath"`
	Name                     string   `json:"name"`
	Extension                string   `json:"extension,omitempty"`
	IsDirectory              bool     `json:"isDirectory"`
	IsDeleted                bool     `json:"isDeleted"`
	IsAllocated              bool     `json:"isAllocated"`
	IsOrphan                 bool     `json:"isOrphan"`
	IsInternalNTFSObject     bool     `json:"isInternalNtfsObject,omitempty"`
	PathReconstructionFailed bool     `json:"pathReconstructionFailed,omitempty"`
	Size                     int64    `json:"size"`
	AllocatedSize            int64    `json:"allocatedSize"`
	MimeType                 string   `json:"mimeType,omitempty"`
	MD5                      string   `json:"md5,omitempty"`
	SHA1                     string   `json:"sha1,omitempty"`
	SHA256                   string   `json:"sha256,omitempty"`
	HashState                string   `json:"hashState"`
	CreatedAt                string   `json:"createdAt,omitempty"`
	ModifiedAt               string   `json:"modifiedAt,omitempty"`
	AccessedAt               string   `json:"accessedAt,omitempty"`
	ChangedAt                string   `json:"changedAt,omitempty"`
	TimestampSource          string   `json:"timestampSource,omitempty"`
	RecordFlags              []string `json:"recordFlags,omitempty"`
	NameType                 string   `json:"nameType,omitempty"`
	ReparseTarget            string   `json:"reparseTarget,omitempty"`
	ADSCount                 int      `json:"adsCount,omitempty"`
	ParseWarnings            []string `json:"parseWarnings,omitempty"`

	Inode            uint64   `json:"inode,omitempty"`
	DeviceID         uint64   `json:"deviceId,omitempty"`
	Mode             string   `json:"mode,omitempty"`
	Permissions      string   `json:"permissions,omitempty"`
	UID              string   `json:"uid,omitempty"`
	GID              string   `json:"gid,omitempty"`
	Nlink            uint64   `json:"nlink,omitempty"`
	FileType         string   `json:"fileType,omitempty"`
	LinkTarget       string   `json:"linkTarget,omitempty"`
	MountPoint       string   `json:"mountPoint,omitempty"`
	FileSystem       string   `json:"filesystem,omitempty"`
	SetUID           bool     `json:"setuid,omitempty"`
	SetGID           bool     `json:"setgid,omitempty"`
	Sticky           bool     `json:"sticky,omitempty"`
	WorldWritable    bool     `json:"worldWritable,omitempty"`
	HiddenName       bool     `json:"hiddenName,omitempty"`
	EvidenceCategory string   `json:"evidenceCategory,omitempty"`
	EvidenceTags     []string `json:"evidenceTags,omitempty"`
	EvidenceReasons  []string `json:"evidenceReasons,omitempty"`
}

type TimelineEvent struct {
	EventID   string `json:"eventId"`
	VolumeID  string `json:"volumeId"`
	EntryID   string `json:"entryId"`
	Path      string `json:"path"`
	EventType string `json:"eventType"`
	Timestamp string `json:"timestamp"`
	Source    string `json:"source,omitempty"`
}

type DiagnosticItem struct {
	DiagnosticType string `json:"diagnosticType"`
	Stage          string `json:"stage"`
	State          string `json:"state"`
	ReasonCode     string `json:"reasonCode"`
	Evidence       string `json:"evidence,omitempty"`
	Message        string `json:"message,omitempty"`
}

type mountInfo struct {
	DevicePath string
	MountPoint string
	FileSystem string
}

func Collect(root string) (Result, error) {
	return CollectWithOptions(root, Options{})
}

func CollectWithOptions(root string, options Options) (Result, error) {
	if options.MaxEntries <= 0 {
		options.MaxEntries = defaultMaxEntries
	}
	if options.MaxDepth <= 0 {
		options.MaxDepth = defaultMaxDepth
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Result{}, err
	}
	rootInfo, err := os.Lstat(absRoot)
	if err != nil {
		return Result{}, err
	}
	rootStat := statOf(rootInfo)
	rootDevice := rootStat.Dev
	volumeID := volumeID(rootDevice)
	mounts := loadMounts(absRoot)
	rootMount := mountForPath(mounts, "/")
	if rootMount.MountPoint == "" {
		rootMount = mountInfo{
			DevicePath: "/",
			MountPoint: "/",
			FileSystem: "unknown",
		}
	}

	result := Result{
		Volumes: []VolumeInfo{{
			VolumeID:   volumeID,
			DevicePath: rootMount.DevicePath,
			FileSystem: rootMount.FileSystem,
			DeviceID:   rootDevice,
			MountPoint: rootMount.MountPoint,
		}},
	}

	entries := 0
	limitReached := false
	err = filepath.WalkDir(absRoot, func(path string, dirEntry fs.DirEntry, walkErr error) error {
		relPath := relativeEvidencePath(absRoot, path)
		if walkErr != nil {
			result.Diagnostics = append(result.Diagnostics, diagnostic("walk_error", relPath, walkErr.Error()))
			if dirEntry != nil && dirEntry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if relPath != "/" && shouldSkipPseudoPath(relPath) {
			result.Diagnostics = append(result.Diagnostics, diagnostic("pseudo_path_skipped", relPath, "pseudo or volatile filesystem path skipped"))
			if dirEntry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if depth(relPath) > options.MaxDepth {
			result.Diagnostics = append(result.Diagnostics, diagnostic("max_depth_reached", relPath, "maximum filesystem scan depth reached"))
			if dirEntry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if limitReached {
			if dirEntry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := os.Lstat(path)
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, diagnostic("lstat_failed", relPath, err.Error()))
			if dirEntry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		stat := statOf(info)
		if stat.Dev != rootDevice && relPath != "/" {
			result.Diagnostics = append(result.Diagnostics, diagnostic("mount_boundary_skipped", relPath, "filesystem device boundary skipped"))
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		entries++
		if entries > options.MaxEntries {
			limitReached = true
			result.Diagnostics = append(result.Diagnostics, diagnostic("max_entries_reached", relPath, "maximum filesystem entry count reached"))
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		entryMount := mountForPath(mounts, relPath)
		if entryMount.MountPoint == "" {
			entryMount = rootMount
		}
		entry := buildFileEntry(volumeID, relPath, path, info, stat, entryMount)
		result.FileEntries = append(result.FileEntries, entry)
		result.TimelineEvents = append(result.TimelineEvents, timelineEvents(entry)...)
		if info.IsDir() {
			result.DirectoryNodes = append(result.DirectoryNodes, directoryNode(volumeID, entry))
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}

	sort.Slice(result.DirectoryNodes, func(i, j int) bool { return result.DirectoryNodes[i].Path < result.DirectoryNodes[j].Path })
	sort.Slice(result.FileEntries, func(i, j int) bool { return result.FileEntries[i].Path < result.FileEntries[j].Path })
	sort.Slice(result.TimelineEvents, func(i, j int) bool {
		if result.TimelineEvents[i].Path == result.TimelineEvents[j].Path {
			return result.TimelineEvents[i].EventType < result.TimelineEvents[j].EventType
		}
		return result.TimelineEvents[i].Path < result.TimelineEvents[j].Path
	})
	return result, nil
}

func buildFileEntry(volumeID string, relPath string, absPath string, info os.FileInfo, stat fileStat, mount mountInfo) FileEntry {
	mode := info.Mode()
	parent := parentEvidencePath(relPath)
	linkTarget := ""
	warnings := []string(nil)
	if mode&os.ModeSymlink != 0 {
		target, err := os.Readlink(absPath)
		if err != nil {
			warnings = append(warnings, "readlink_failed:"+err.Error())
		} else {
			linkTarget = target
		}
	}
	flags := recordFlags(mode, info.Name())
	evidenceCategory, evidenceTags := evidenceTagsForPath(relPath, mode)
	return FileEntry{
		EntryID:          entryID(stat.Dev, stat.Ino),
		VolumeID:         volumeID,
		Path:             relPath,
		ParentPath:       parent,
		Name:             info.Name(),
		Extension:        extension(info.Name()),
		IsDirectory:      info.IsDir(),
		IsDeleted:        false,
		IsAllocated:      true,
		IsOrphan:         false,
		Size:             info.Size(),
		AllocatedSize:    allocatedSize(stat.Blocks),
		HashState:        "not_hashed",
		ModifiedAt:       formatUnixTime(stat.MtimSec, stat.MtimNsec),
		AccessedAt:       formatUnixTime(stat.AtimSec, stat.AtimNsec),
		ChangedAt:        formatUnixTime(stat.CtimSec, stat.CtimNsec),
		TimestampSource:  "stat",
		RecordFlags:      flags,
		NameType:         "posix",
		ReparseTarget:    linkTarget,
		ParseWarnings:    warnings,
		Inode:            stat.Ino,
		DeviceID:         stat.Dev,
		Mode:             fmt.Sprintf("%#o", uint32(mode.Perm())),
		Permissions:      mode.Perm().String(),
		UID:              strconv.FormatUint(uint64(stat.UID), 10),
		GID:              strconv.FormatUint(uint64(stat.GID), 10),
		Nlink:            stat.Nlink,
		FileType:         fileType(mode),
		LinkTarget:       linkTarget,
		MountPoint:       mount.MountPoint,
		FileSystem:       mount.FileSystem,
		SetUID:           mode&os.ModeSetuid != 0,
		SetGID:           mode&os.ModeSetgid != 0,
		Sticky:           mode&os.ModeSticky != 0,
		WorldWritable:    mode.Perm()&0o002 != 0,
		HiddenName:       strings.HasPrefix(info.Name(), ".") && info.Name() != "." && info.Name() != "..",
		EvidenceCategory: evidenceCategory,
		EvidenceTags:     evidenceTags,
		EvidenceReasons:  evidenceReasonsForTags(evidenceTags),
	}
}

func loadMounts(root string) []mountInfo {
	if mounts := parseMountInfoFile(filepath.Join(root, "proc", "self", "mountinfo")); len(mounts) > 0 {
		return mounts
	}
	return parseProcMountsFile(filepath.Join(root, "proc", "mounts"))
}

func parseMountInfoFile(path string) []mountInfo {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var mounts []mountInfo
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+2 >= len(fields) {
			continue
		}
		mountPoint := decodeMountField(fields[4])
		filesystem := fields[separator+1]
		devicePath := decodeMountField(fields[separator+2])
		if shouldSkipMount(filesystem, devicePath, mountPoint) {
			continue
		}
		mounts = append(mounts, mountInfo{
			DevicePath: devicePath,
			MountPoint: cleanMountPoint(mountPoint),
			FileSystem: filesystem,
		})
	}
	return mounts
}

func parseProcMountsFile(path string) []mountInfo {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var mounts []mountInfo
	for _, line := range strings.Split(string(content), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		devicePath := decodeMountField(fields[0])
		mountPoint := decodeMountField(fields[1])
		filesystem := fields[2]
		if shouldSkipMount(filesystem, devicePath, mountPoint) {
			continue
		}
		mounts = append(mounts, mountInfo{
			DevicePath: devicePath,
			MountPoint: cleanMountPoint(mountPoint),
			FileSystem: filesystem,
		})
	}
	return mounts
}

func mountForPath(mounts []mountInfo, evidencePath string) mountInfo {
	cleanPath := cleanMountPoint(evidencePath)
	best := mountInfo{}
	for _, mount := range mounts {
		mountPoint := cleanMountPoint(mount.MountPoint)
		if !pathWithinMount(cleanPath, mountPoint) {
			continue
		}
		if best.MountPoint == "" || len(mountPoint) > len(best.MountPoint) {
			best = mount
		}
	}
	return best
}

func pathWithinMount(path string, mountPoint string) bool {
	if mountPoint == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == mountPoint || strings.HasPrefix(path, mountPoint+"/")
}

func cleanMountPoint(path string) string {
	if path == "" {
		return ""
	}
	cleaned := filepath.ToSlash(filepath.Clean(path))
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned
}

func decodeMountField(value string) string {
	replacer := strings.NewReplacer(
		`\\`, `\`,
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	)
	return replacer.Replace(value)
}

func shouldSkipMount(filesystem string, devicePath string, mountPoint string) bool {
	if linuxutil.IsPseudoFilesystem(filesystem) {
		return true
	}
	if strings.HasPrefix(cleanMountPoint(mountPoint), "/proc") {
		return true
	}
	switch devicePath {
	case "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "securityfs", "pstore", "bpf", "tracefs", "debugfs", "configfs", "mqueue", "hugetlbfs":
		return true
	default:
		return false
	}
}

func directoryNode(volumeID string, entry FileEntry) DirectoryNode {
	return DirectoryNode{
		NodeID:         "dir:" + entry.EntryID,
		VolumeID:       volumeID,
		ParentMFTEntry: 0,
		Path:           entry.Path,
		ParentPath:     entry.ParentPath,
		Name:           entry.Name,
		Inode:          entry.Inode,
		DeviceID:       entry.DeviceID,
	}
}

func timelineEvents(entry FileEntry) []TimelineEvent {
	candidates := []struct {
		eventType string
		timestamp string
		source    string
	}{
		{eventType: "linux.file.modified", timestamp: entry.ModifiedAt, source: "stat.mtime"},
		{eventType: "linux.file.accessed", timestamp: entry.AccessedAt, source: "stat.atime"},
		{eventType: "linux.file.changed", timestamp: entry.ChangedAt, source: "stat.ctime"},
	}
	events := make([]TimelineEvent, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.timestamp == "" {
			continue
		}
		events = append(events, TimelineEvent{
			EventID:   fmt.Sprintf("%s:%s", entry.EntryID, candidate.eventType),
			VolumeID:  entry.VolumeID,
			EntryID:   entry.EntryID,
			Path:      entry.Path,
			EventType: candidate.eventType,
			Timestamp: candidate.timestamp,
			Source:    candidate.source,
		})
	}
	return events
}

func relativeEvidencePath(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return "/"
	}
	return "/" + filepath.ToSlash(rel)
}

func parentEvidencePath(path string) string {
	if path == "/" {
		return ""
	}
	parent := filepath.ToSlash(filepath.Dir(path))
	if parent == "." {
		return "/"
	}
	return parent
}

func depth(path string) int {
	if path == "/" {
		return 0
	}
	return len(strings.Split(strings.Trim(path, "/"), "/"))
}

func shouldSkipPseudoPath(path string) bool {
	first := strings.Split(strings.Trim(path, "/"), "/")[0]
	switch first {
	case "proc", "sys", "dev", "run":
		return true
	default:
		return false
	}
}

func volumeID(device uint64) string {
	return fmt.Sprintf("linux-dev:%d", device)
}

func entryID(device uint64, inode uint64) string {
	return fmt.Sprintf("linux:%d:%d", device, inode)
}

func allocatedSize(blocks int64) int64 {
	if blocks <= 0 {
		return 0
	}
	return blocks * 512
}

func formatUnixTime(sec int64, nsec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, nsec).UTC().Format(time.RFC3339Nano)
}

func extension(name string) string {
	ext := filepath.Ext(name)
	if ext == "" || ext == name {
		return ""
	}
	return strings.TrimPrefix(ext, ".")
}

func fileType(mode os.FileMode) string {
	switch {
	case mode.IsRegular():
		return "file"
	case mode.IsDir():
		return "directory"
	case mode&os.ModeSymlink != 0:
		return "symlink"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeNamedPipe != 0:
		return "fifo"
	case mode&os.ModeDevice != 0:
		return "device"
	default:
		return "other"
	}
}

func recordFlags(mode os.FileMode, name string) []string {
	var flags []string
	if mode&os.ModeSetuid != 0 {
		flags = append(flags, "setuid")
	}
	if mode&os.ModeSetgid != 0 {
		flags = append(flags, "setgid")
	}
	if mode&os.ModeSticky != 0 {
		flags = append(flags, "sticky")
	}
	if mode.Perm()&0o002 != 0 {
		flags = append(flags, "world_writable")
	}
	if strings.HasPrefix(name, ".") && name != "." && name != ".." {
		flags = append(flags, "hidden_name")
	}
	return flags
}

func evidenceTagsForPath(path string, mode os.FileMode) (string, []string) {
	normalized := filepath.ToSlash(filepath.Clean(path))
	tags := []string{}
	category := ""
	if strings.HasPrefix(normalized, "/var/lib/docker/") || strings.HasPrefix(normalized, "/etc/docker/") {
		tags = append(tags, "docker")
	}
	if strings.HasPrefix(normalized, "/var/lib/containerd/") || strings.HasPrefix(normalized, "/etc/containerd/") {
		tags = append(tags, "containerd")
	}
	if strings.HasPrefix(normalized, "/etc/kubernetes/") || strings.HasPrefix(normalized, "/var/lib/kubelet/") || strings.HasPrefix(normalized, "/var/log/pods/") || strings.HasPrefix(normalized, "/var/log/containers/") {
		tags = append(tags, "kubernetes")
	}
	if strings.Contains(normalized, "/containers/") && strings.HasSuffix(normalized, "-json.log") || strings.HasPrefix(normalized, "/var/log/containers/") || strings.HasPrefix(normalized, "/var/log/pods/") {
		tags = append(tags, "container_log")
	}
	if strings.Contains(normalized, "/containers/") && (strings.HasSuffix(normalized, "config.v2.json") || strings.HasSuffix(normalized, "hostconfig.json")) {
		tags = append(tags, "container_config")
	}
	if strings.HasPrefix(normalized, "/etc/kubernetes/") || strings.HasPrefix(normalized, "/var/lib/kubelet/") {
		tags = append(tags, "kubernetes_config")
	}
	if len(tags) > 0 {
		category = "container"
	}
	if mode&os.ModeSetuid != 0 {
		tags = append(tags, "suid")
		category = "privilege_escalation"
		if isTemporaryEvidencePath(normalized) {
			tags = append(tags, "suid_temp_path")
		}
	}
	if mode&os.ModeSetgid != 0 {
		tags = append(tags, "sgid")
		category = "privilege_escalation"
		if isTemporaryEvidencePath(normalized) {
			tags = append(tags, "sgid_temp_path")
		}
	}
	if (mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0) && hasHiddenPathSegment(normalized) {
		tags = append(tags, "hidden_path")
	}
	switch {
	case normalized == "/etc/ld.so.preload":
		tags = append(tags, "ld_so_preload")
		category = "privilege_escalation"
	case normalized == "/etc/sudoers" || strings.HasPrefix(normalized, "/etc/sudoers.d/"):
		tags = append(tags, "sudoers_policy")
		category = "privilege_escalation"
	case strings.HasPrefix(normalized, "/etc/pam.d/"):
		tags = append(tags, "pam_policy")
		category = "authentication"
	case normalized == "/root/.ssh/authorized_keys" || strings.Contains(normalized, "/.ssh/authorized_keys"):
		tags = append(tags, "ssh_authorized_keys")
		category = "authentication"
	case strings.HasPrefix(normalized, "/etc/cron.") || strings.HasPrefix(normalized, "/etc/cron.d/") || normalized == "/etc/crontab":
		tags = append(tags, "cron_policy")
		category = "persistence"
	case strings.HasPrefix(normalized, "/etc/systemd/") || strings.HasPrefix(normalized, "/usr/lib/systemd/"):
		tags = append(tags, "systemd_unit_path")
		category = "persistence"
	}
	if mode.Perm()&0o002 != 0 && (strings.HasPrefix(normalized, "/usr/local/bin/") || strings.HasPrefix(normalized, "/usr/local/sbin/") || strings.HasPrefix(normalized, "/opt/")) {
		tags = append(tags, "world_writable_exec_path")
		if category == "" {
			category = "privilege_escalation"
		}
	}
	tags = uniqueStrings(tags)
	if len(tags) == 0 {
		return "", nil
	}
	return category, tags
}

func evidenceReasonsForTags(tags []string) []string {
	reasonsByTag := map[string]string{
		"ld_so_preload":            "Dynamic linker preload affects process library loading and is a common persistence or hijack point.",
		"sudoers_policy":           "Sudo policy controls privilege elevation and can grant passwordless or broad root access.",
		"pam_policy":               "PAM policy changes can alter authentication, backdoor login flow, or credential handling.",
		"ssh_authorized_keys":      "SSH authorized keys define who can log in without a password and are critical access evidence.",
		"cron_policy":              "Cron policy can launch recurring commands for persistence or delayed execution.",
		"systemd_unit_path":        "Systemd unit paths define services, timers, and startup persistence behavior.",
		"world_writable_exec_path": "World-writable executable search paths can let untrusted users replace commands used by services or scripts.",
		"suid":                     "SUID files execute with owner privileges and are common privilege escalation evidence.",
		"sgid":                     "SGID files execute with group privileges and can expand access unexpectedly.",
		"suid_temp_path":           "SUID files in temporary paths are unusual and often indicate dropped tooling.",
		"sgid_temp_path":           "SGID files in temporary paths are unusual and often indicate dropped tooling.",
		"hidden_path":              "Hidden path segments can indicate concealed files or operator staging.",
		"container_config":         "Container configuration links runtime identity, mounts, images, and execution settings.",
		"container_log":            "Container logs preserve workload command output and runtime behavior evidence.",
		"kubernetes_config":        "Kubernetes configuration can identify cluster access, kubelet state, and workload ownership.",
	}
	var reasons []string
	for _, tag := range tags {
		if reason := reasonsByTag[tag]; reason != "" {
			reasons = append(reasons, reason)
		}
	}
	return uniqueStrings(reasons)
}

func isTemporaryEvidencePath(path string) bool {
	return path == "/tmp" ||
		strings.HasPrefix(path, "/tmp/") ||
		path == "/var/tmp" ||
		strings.HasPrefix(path, "/var/tmp/") ||
		path == "/dev/shm" ||
		strings.HasPrefix(path, "/dev/shm/")
}

func hasHiddenPathSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if strings.HasPrefix(segment, ".") && segment != "." && segment != ".." {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func diagnostic(reason string, evidence string, message string) DiagnosticItem {
	return DiagnosticItem{
		DiagnosticType: "linux_file_system",
		Stage:          "file_system",
		State:          "skipped",
		ReasonCode:     reason,
		Evidence:       evidence,
		Message:        message,
	}
}
