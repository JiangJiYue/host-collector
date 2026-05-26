package process

import (
	"bufio"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Result struct {
	Processes      []Process                 `json:"processes"`
	ProcessTree    []ProcessTreeEdge         `json:"processTree"`
	FileIdentities []FileIdentity            `json:"fileIdentities,omitempty"`
	ProcessDetails map[string]ProcessDetails `json:"processDetails,omitempty"`
	Diagnostics    []DiagnosticItem          `json:"processDiagnostics,omitempty"`
}

type Process struct {
	PID                     int                   `json:"pid"`
	PPID                    int                   `json:"ppid"`
	ParentPid               int                   `json:"parentPid,omitempty"`
	Name                    string                `json:"name"`
	ProcessName             string                `json:"processName,omitempty"`
	UID                     string                `json:"uid,omitempty"`
	User                    string                `json:"user,omitempty"`
	CommandLine             string                `json:"commandLine,omitempty"`
	ImagePath               string                `json:"imagePath,omitempty"`
	ProcessPath             string                `json:"processPath,omitempty"`
	CreateTime              string                `json:"createTime,omitempty"`
	CreatedAt               string                `json:"createdAt,omitempty"`
	ThreadCount             int                   `json:"threadCount,omitempty"`
	HandleCount             int                   `json:"handleCount,omitempty"`
	Is64Bit                 bool                  `json:"is64Bit"`
	Is64BitProcess          bool                  `json:"is64BitProcess"`
	SessionID               string                `json:"sessionId,omitempty"`
	BasePriority            string                `json:"basePriority,omitempty"`
	Domain                  string                `json:"domain,omitempty"`
	DomainName              string                `json:"domainName,omitempty"`
	ParentName              string                `json:"parentName,omitempty"`
	ParentProcessName       string                `json:"parentProcessName,omitempty"`
	ParentCommandLine       string                `json:"parentCommandLine,omitempty"`
	ParentPath              string                `json:"parentPath,omitempty"`
	ParentProcessPath       string                `json:"parentProcessPath,omitempty"`
	ParentProcessFullPath   string                `json:"parentProcessFullPath,omitempty"`
	ProcessFullPath         string                `json:"processFullPath,omitempty"`
	BaseAddress             string                `json:"baseAddress,omitempty"`
	ProcessBaseAddress      string                `json:"processBaseAddress,omitempty"`
	ParentProcessID         int                   `json:"parentProcessId,omitempty"`
	ParentProcessCommandRaw string                `json:"parentProcessCommandRaw,omitempty"`
	FileIdentityID          string                `json:"fileIdentityId,omitempty"`
	SHA256                  string                `json:"sha256,omitempty"`
	HashState               string                `json:"hashState,omitempty"`
	SignatureState          string                `json:"signatureState,omitempty"`
	WorkingDirectory        string                `json:"workingDirectory,omitempty"`
	RootPath                string                `json:"rootPath,omitempty"`
	Cgroups                 []string              `json:"cgroups,omitempty"`
	Container               ContainerContext      `json:"container,omitempty"`
	Namespaces              map[string]string     `json:"namespaces,omitempty"`
	Environment             []EnvironmentVariable `json:"environment,omitempty"`
	Deleted                 bool                  `json:"deleted,omitempty"`
	RiskTags                []string              `json:"riskTags,omitempty"`
}

type ContainerContext struct {
	ID             string `json:"id,omitempty"`
	Runtime        string `json:"runtime,omitempty"`
	Name           string `json:"name,omitempty"`
	Image          string `json:"image,omitempty"`
	Orchestrator   string `json:"orchestrator,omitempty"`
	PodUID         string `json:"podUid,omitempty"`
	RawCgroup      string `json:"rawCgroup,omitempty"`
	MetadataState  string `json:"metadataState,omitempty"`
	MetadataReason string `json:"metadataReason,omitempty"`
}

type EnvironmentVariable struct {
	Key      string   `json:"key"`
	Value    string   `json:"value,omitempty"`
	Redacted bool     `json:"redacted,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

type FileIdentity struct {
	ID              string   `json:"id"`
	Path            string   `json:"path"`
	NormalizedPath  string   `json:"normalizedPath,omitempty"`
	Basename        string   `json:"basename,omitempty"`
	Extension       string   `json:"extension,omitempty"`
	Size            int64    `json:"size,omitempty"`
	ModifiedAt      string   `json:"modifiedAt,omitempty"`
	MD5             string   `json:"md5,omitempty"`
	SHA256          string   `json:"sha256,omitempty"`
	HashState       string   `json:"hashState,omitempty"`
	SignatureState  string   `json:"signatureState,omitempty"`
	EvidenceSources []string `json:"evidenceSources,omitempty"`
	CollectionError string   `json:"collectionError,omitempty"`
}

type ProcessTreeEdge struct {
	PID  int `json:"pid"`
	PPID int `json:"ppid"`
}

type ProcessDetails struct {
	IOStats            *IOStats            `json:"ioStats,omitempty"`
	MemoryBlocks       []MemoryBlock       `json:"memoryBlocks,omitempty"`
	Modules            []Module            `json:"modules,omitempty"`
	Threads            []Thread            `json:"threads,omitempty"`
	Windows            []Window            `json:"windows,omitempty"`
	NetworkConnections []NetworkConnection `json:"networkConnections,omitempty"`
	Handles            []Handle            `json:"handles,omitempty"`
}

type IOStats struct {
	ReadCount          uint64 `json:"readCount,omitempty"`
	WriteCount         uint64 `json:"writeCount,omitempty"`
	OtherCount         uint64 `json:"otherCount,omitempty"`
	ReadTransferCount  uint64 `json:"readTransferCount,omitempty"`
	WriteTransferCount uint64 `json:"writeTransferCount,omitempty"`
	OtherTransferCount uint64 `json:"otherTransferCount,omitempty"`
}

type MemoryBlock struct {
	ID          string   `json:"id,omitempty"`
	BaseAddress string   `json:"baseAddress,omitempty"`
	Size        string   `json:"size,omitempty"`
	BlockType   string   `json:"blockType,omitempty"`
	Protection  string   `json:"protection,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	CanRead     bool     `json:"canRead"`
	CanWrite    bool     `json:"canWrite"`
	CanExecute  bool     `json:"canExecute"`
	Deleted     bool     `json:"deleted,omitempty"`
	RiskTags    []string `json:"riskTags,omitempty"`
}

type Module struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Path        string   `json:"path,omitempty"`
	BaseAddress string   `json:"baseAddress,omitempty"`
	Size        uint64   `json:"size,omitempty"`
	Deleted     bool     `json:"deleted,omitempty"`
	RiskTags    []string `json:"riskTags,omitempty"`
}

type Thread struct {
	ThreadID        int    `json:"threadId,omitempty"`
	State           string `json:"state,omitempty"`
	ContextSwitches uint64 `json:"contextSwitches,omitempty"`
}

type NetworkConnection struct {
	ID            string `json:"id,omitempty"`
	ProcessID     int    `json:"processId,omitempty"`
	ProcessName   string `json:"processName,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	Family        string `json:"family,omitempty"`
	LocalAddress  string `json:"localAddress,omitempty"`
	LocalPort     int    `json:"localPort,omitempty"`
	RemoteAddress string `json:"remoteAddress,omitempty"`
	RemotePort    int    `json:"remotePort,omitempty"`
	StateCode     int    `json:"stateCode,omitempty"`
	StateName     string `json:"stateName,omitempty"`
	Inode         string `json:"inode,omitempty"`
}

type Window struct{}

type Handle struct {
	ID     string `json:"id,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Target string `json:"target,omitempty"`
}

type DiagnosticItem struct {
	Stage      string `json:"stage,omitempty"`
	State      string `json:"state,omitempty"`
	ReasonCode string `json:"reasonCode,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
}

func Collect(root string) (Result, error) {
	procRoot := filepath.Join(root, "proc")
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return Result{}, err
	}

	processes := make([]Process, 0, len(entries))
	details := map[string]ProcessDetails{}
	fileIdentities := map[string]FileIdentity{}
	users := readPasswdUsers(filepath.Join(root, "etc", "passwd"))
	netByInode := readProcNet(root)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		processDir := filepath.Join(procRoot, entry.Name())
		process, identity, err := readProcess(root, processDir, pid, users)
		if err != nil {
			return Result{}, err
		}
		if identity.ID != "" {
			fileIdentities[identity.ID] = identity
		}
		processes = append(processes, process)
		if detail := readProcessDetails(root, processDir, pid, netByInode); hasProcessDetails(detail) {
			details[strconv.Itoa(process.PID)] = detail
		}
	}
	enrichParentProcesses(processes)
	sort.Slice(processes, func(i, j int) bool { return processes[i].PID < processes[j].PID })

	tree := make([]ProcessTreeEdge, 0, len(processes))
	for _, process := range processes {
		tree = append(tree, ProcessTreeEdge{PID: process.PID, PPID: process.PPID})
	}
	return Result{Processes: processes, ProcessTree: tree, FileIdentities: sortedFileIdentities(fileIdentities), ProcessDetails: details}, nil
}

func readProcess(root string, dir string, fallbackPID int, users map[string]string) (Process, FileIdentity, error) {
	fields, err := readStatus(filepath.Join(dir, "status"))
	if err != nil {
		return Process{}, FileIdentity{}, err
	}
	pid := parseInt(fields["Pid"], fallbackPID)
	ppid := parseInt(fields["PPid"], 0)
	uid := firstField(fields["Uid"])
	name := fields["Name"]
	statFields := readStatFields(filepath.Join(dir, "stat"))
	imagePath := imagePath(dir)
	identity := collectProcessFileIdentity(root, imagePath)
	deleted := linuxPathDeleted(imagePath)
	namespaces := readNamespaces(filepath.Join(dir, "ns"))
	baseAddress, is64Bit := processMapProfile(filepath.Join(dir, "maps"))
	createdAt := processCreatedAt(root, statFields["starttime"])
	cgroups := readCgroups(filepath.Join(dir, "cgroup"))
	container := containerContextFromCgroups(root, cgroups)
	return Process{
		PID:                pid,
		PPID:               ppid,
		ParentPid:          ppid,
		ParentProcessID:    ppid,
		Name:               name,
		ProcessName:        name,
		UID:                uid,
		User:               usernameForUID(users, uid),
		CommandLine:        readCmdline(filepath.Join(dir, "cmdline")),
		ImagePath:          imagePath,
		ProcessPath:        imagePath,
		ProcessFullPath:    imagePath,
		CreateTime:         createdAt,
		CreatedAt:          createdAt,
		ThreadCount:        parseInt(fields["Threads"], 0),
		HandleCount:        fdCount(filepath.Join(dir, "fd")),
		Is64Bit:            is64Bit,
		Is64BitProcess:     is64Bit,
		SessionID:          statFields["session"],
		BasePriority:       statFields["priority"],
		Domain:             "linux",
		DomainName:         "linux",
		BaseAddress:        baseAddress,
		ProcessBaseAddress: baseAddress,
		FileIdentityID:     identity.ID,
		SHA256:             identity.SHA256,
		HashState:          identity.HashState,
		SignatureState:     identity.SignatureState,
		WorkingDirectory:   readlink(filepath.Join(dir, "cwd")),
		RootPath:           readlink(filepath.Join(dir, "root")),
		Cgroups:            cgroups,
		Container:          container,
		Namespaces:         namespaces,
		Environment:        readProcessEnvironment(filepath.Join(dir, "environ")),
		Deleted:            deleted,
		RiskTags:           processRiskTags(deleted, container),
	}, identity, nil
}

func enrichParentProcesses(processes []Process) {
	byPID := make(map[int]Process, len(processes))
	for _, process := range processes {
		byPID[process.PID] = process
	}
	for index := range processes {
		parent, ok := byPID[processes[index].PPID]
		if !ok {
			continue
		}
		processes[index].ParentName = parent.Name
		processes[index].ParentProcessName = parent.Name
		processes[index].ParentCommandLine = parent.CommandLine
		processes[index].ParentProcessCommandRaw = parent.CommandLine
		processes[index].ParentPath = parent.ImagePath
		processes[index].ParentProcessPath = parent.ImagePath
		processes[index].ParentProcessFullPath = parent.ImagePath
	}
}

func imagePath(dir string) string {
	if target := readlink(filepath.Join(dir, "exe")); target != "" {
		return target
	}
	return firstField(readCmdline(filepath.Join(dir, "cmdline")))
}

func collectProcessFileIdentity(root string, imagePath string) FileIdentity {
	normalizedPath := normalizeLinuxIdentityPath(imagePath)
	if normalizedPath == "" {
		return FileIdentity{}
	}
	identity := FileIdentity{
		ID:              stableFileIdentityID(normalizedPath),
		Path:            imagePath,
		NormalizedPath:  normalizedPath,
		Basename:        pathpkg.Base(normalizedPath),
		Extension:       pathpkg.Ext(normalizedPath),
		SignatureState:  "unsupported",
		EvidenceSources: []string{"process.image"},
	}

	hostPath := rootPathForLinuxPath(root, normalizedPath)
	info, err := os.Stat(hostPath)
	if err != nil {
		identity.HashState = "read_error"
		identity.CollectionError = err.Error()
		return identity
	}
	identity.Size = info.Size()
	identity.ModifiedAt = info.ModTime().UTC().Format(time.RFC3339)
	if info.IsDir() {
		identity.HashState = "skipped_not_file"
		return identity
	}

	file, err := os.Open(hostPath)
	if err != nil {
		identity.HashState = "read_error"
		identity.CollectionError = err.Error()
		return identity
	}
	defer file.Close()

	md5Hasher := md5.New()
	sha256Hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(md5Hasher, sha256Hasher), file); err != nil {
		identity.HashState = "read_error"
		identity.CollectionError = err.Error()
		return identity
	}
	identity.MD5 = hex.EncodeToString(md5Hasher.Sum(nil))
	identity.SHA256 = hex.EncodeToString(sha256Hasher.Sum(nil))
	identity.HashState = "completed"
	return identity
}

func normalizeLinuxIdentityPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "[") {
		return ""
	}
	value, _ = stripLinuxDeletedSuffix(value)
	cleaned := pathpkg.Clean(strings.ReplaceAll(value, "\\", "/"))
	if !strings.HasPrefix(cleaned, "/") {
		return ""
	}
	return cleaned
}

func linuxPathDeleted(value string) bool {
	_, deleted := stripLinuxDeletedSuffix(value)
	return deleted
}

func stripLinuxDeletedSuffix(value string) (string, bool) {
	const deletedSuffix = " (deleted)"
	if strings.HasSuffix(value, deletedSuffix) {
		return strings.TrimSuffix(value, deletedSuffix), true
	}
	return value, false
}

func processRiskTags(deleted bool, container ContainerContext) []string {
	var tags []string
	if deleted {
		tags = append(tags, "deleted_executable")
	}
	if container.ID != "" {
		tags = append(tags, "container_process")
	}
	return uniqueStrings(tags)
}

func mappingRiskTags(deleted bool, path string, perms string) []string {
	var tags []string
	if deleted {
		tags = append(tags, "deleted_mapping")
	}
	if strings.Contains(perms, "x") && strings.Contains(perms, "w") {
		tags = append(tags, "writable_executable_mapping")
	}
	if strings.Contains(perms, "x") && strings.TrimSpace(path) == "" {
		tags = append(tags, "anonymous_executable_mapping")
	}
	if strings.Contains(perms, "x") && isTempEvidencePath(path) {
		tags = append(tags, "temp_path_mapping")
	}
	return uniqueStrings(tags)
}

func moduleRiskTags(deleted bool, path string) []string {
	var tags []string
	if deleted {
		tags = append(tags, "deleted_module")
	}
	if isTempEvidencePath(path) {
		tags = append(tags, "temp_path_module")
	}
	return uniqueStrings(tags)
}

func rootPathForLinuxPath(root string, normalizedPath string) string {
	return filepath.Join(root, strings.TrimPrefix(normalizedPath, "/"))
}

func stableFileIdentityID(normalizedPath string) string {
	sum := sha256.Sum256([]byte(normalizedPath))
	return "file-" + hex.EncodeToString(sum[:8])
}

func sortedFileIdentities(values map[string]FileIdentity) []FileIdentity {
	if len(values) == 0 {
		return nil
	}
	identities := make([]FileIdentity, 0, len(values))
	for _, identity := range values {
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool {
		return identities[i].ID < identities[j].ID
	})
	return identities
}

func readCgroups(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var rows []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			rows = append(rows, line)
		}
	}
	return rows
}

func containerContextFromCgroups(root string, cgroups []string) ContainerContext {
	for _, row := range cgroups {
		context := parseContainerCgroup(row)
		if context.ID != "" {
			return enrichContainerMetadata(root, context)
		}
	}
	return ContainerContext{}
}

func enrichContainerMetadata(root string, context ContainerContext) ContainerContext {
	if context.ID == "" {
		return context
	}
	if context.Runtime == "docker" {
		if docker, ok := readDockerContainerConfig(root, context.ID); ok {
			if docker.Name != "" {
				context.Name = docker.Name
			}
			if docker.Image != "" {
				context.Image = docker.Image
			}
			context.MetadataState = "available"
			return context
		}
	}
	context.MetadataState = "unavailable"
	context.MetadataReason = containerMetadataUnavailableReason(context.Runtime)
	return context
}

type dockerContainerConfig struct {
	Name   string
	Config struct {
		Image string
	}
}

func readDockerContainerConfig(root string, containerID string) (ContainerContext, bool) {
	data, err := os.ReadFile(filepath.Join(root, "var", "lib", "docker", "containers", containerID, "config.v2.json"))
	if err != nil {
		return ContainerContext{}, false
	}
	var config dockerContainerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return ContainerContext{}, false
	}
	context := ContainerContext{
		Name:  strings.TrimPrefix(config.Name, "/"),
		Image: config.Config.Image,
	}
	return context, context.Name != "" || context.Image != ""
}

func containerMetadataUnavailableReason(runtime string) string {
	switch runtime {
	case "docker":
		return "docker_metadata_not_found"
	case "containerd":
		return "containerd_metadata_requires_runtime_access"
	case "cri-o":
		return "crio_metadata_requires_runtime_access"
	default:
		return "runtime_metadata_not_found"
	}
}

func parseContainerCgroup(row string) ContainerContext {
	parts := strings.Split(row, ":")
	path := row
	if len(parts) >= 3 {
		path = parts[2]
	}
	context := ContainerContext{RawCgroup: row}
	if strings.Contains(path, "kubepods") {
		context.Orchestrator = "kubernetes"
		context.PodUID = cgroupPodUID(path)
	}
	switch {
	case strings.Contains(path, "cri-containerd-"):
		context.Runtime = "containerd"
		context.ID = hexContainerIDAfter(path, "cri-containerd-")
	case strings.Contains(path, "crio-"):
		context.Runtime = "cri-o"
		context.ID = hexContainerIDAfter(path, "crio-")
	case strings.Contains(path, "docker-"):
		context.Runtime = "docker"
		context.ID = hexContainerIDAfter(path, "docker-")
	case strings.Contains(path, "/docker/"):
		context.Runtime = "docker"
		context.ID = hexContainerIDAfter(path, "/docker/")
	case strings.Contains(path, "containerd"):
		context.Runtime = "containerd"
		context.ID = longestHexContainerID(path)
	default:
		context.ID = longestHexContainerID(path)
		if context.ID != "" {
			context.Runtime = "unknown"
		}
	}
	if len(context.ID) < 12 {
		return ContainerContext{}
	}
	return context
}

func hexContainerIDAfter(value string, marker string) string {
	index := strings.Index(value, marker)
	if index < 0 {
		return ""
	}
	return leadingHex(value[index+len(marker):])
}

func longestHexContainerID(value string) string {
	best := ""
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F')
	}) {
		if len(part) > len(best) {
			best = part
		}
	}
	if len(best) < 12 {
		return ""
	}
	return strings.ToLower(best)
}

func leadingHex(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' {
			builder.WriteRune(r)
			continue
		}
		break
	}
	return strings.ToLower(builder.String())
}

func cgroupPodUID(value string) string {
	for _, segment := range strings.Split(value, "/") {
		if strings.Contains(segment, "-pod") {
			after := segment[strings.Index(segment, "-pod")+4:]
			after = strings.TrimSuffix(after, ".slice")
			after = strings.ReplaceAll(after, "_", "-")
			if after != "" {
				return after
			}
			continue
		}
		if strings.HasPrefix(segment, "pod") {
			after := strings.TrimPrefix(segment, "pod")
			after = strings.TrimSuffix(after, ".slice")
			after = strings.ReplaceAll(after, "_", "-")
			if after != "" {
				return after
			}
		}
	}
	return ""
}

func readProcessEnvironment(path string) []EnvironmentVariable {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}
	parts := strings.Split(string(data), "\x00")
	values := make([]EnvironmentVariable, 0, len(parts))
	for _, part := range parts {
		if len(values) >= 64 {
			break
		}
		key, value, ok := strings.Cut(part, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			continue
		}
		redacted := isSensitiveEnvironmentKey(key)
		if redacted {
			value = "[REDACTED]"
		}
		values = append(values, EnvironmentVariable{
			Key:      key,
			Value:    value,
			Redacted: redacted,
			Tags:     environmentTags(key, value),
		})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Key < values[j].Key })
	return values
}

func isSensitiveEnvironmentKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, marker := range []string{"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY", "ACCESS_KEY", "SESSION_KEY"} {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}

func environmentTags(key string, value string) []string {
	var tags []string
	upper := strings.ToUpper(key)
	lowerValue := strings.ToLower(value)
	switch {
	case upper == "LD_PRELOAD":
		tags = append(tags, "ld_preload")
	case upper == "LD_LIBRARY_PATH":
		tags = append(tags, "ld_library_path")
	case upper == "PATH":
		tags = append(tags, "path")
	case strings.Contains(upper, "PROXY"):
		tags = append(tags, "proxy")
	case upper == "CONTAINER" || upper == "container":
		tags = append(tags, "container")
	}
	if strings.Contains(lowerValue, "/tmp/") || strings.HasPrefix(lowerValue, "/tmp") ||
		strings.Contains(lowerValue, "/var/tmp/") || strings.HasPrefix(lowerValue, "/var/tmp") ||
		strings.Contains(lowerValue, "/dev/shm/") || strings.HasPrefix(lowerValue, "/dev/shm") {
		tags = append(tags, "temp_path")
		if upper == "PATH" {
			tags = append(tags, "path_temp_directory")
		}
	}
	return uniqueStrings(tags)
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
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

func readNamespaces(dir string) map[string]string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	values := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		target := readlink(filepath.Join(dir, entry.Name()))
		if target != "" {
			values[entry.Name()] = target
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func readStatFields(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	line := strings.TrimSpace(string(data))
	closeIndex := strings.LastIndex(line, ")")
	if closeIndex < 0 || closeIndex+2 >= len(line) {
		return nil
	}
	fields := strings.Fields(line[closeIndex+2:])
	result := map[string]string{}
	if len(fields) > 15 {
		result["session"] = fields[3]
		result["priority"] = fields[15]
	}
	if len(fields) > 19 {
		result["starttime"] = fields[19]
	}
	return result
}

func processCreatedAt(root string, startTicks string) string {
	ticks, err := strconv.ParseUint(strings.TrimSpace(startTicks), 10, 64)
	if err != nil || ticks == 0 {
		return ""
	}
	bootTime := systemBootTime(filepath.Join(root, "proc", "stat"))
	if bootTime == 0 {
		return startTicks
	}
	startSeconds := float64(ticks) / float64(clockTicksPerSecond())
	created := time.Unix(bootTime, 0).Add(time.Duration(startSeconds * float64(time.Second))).UTC()
	return created.Format(time.RFC3339)
}

func systemBootTime(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "btime" {
			parsed, err := strconv.ParseInt(fields[1], 10, 64)
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}

func clockTicksPerSecond() uint64 {
	return 100
}

func processMapProfile(path string) (string, bool) {
	lines := readMapLines(path)
	if len(lines) == 0 {
		return "", false
	}
	baseAddress := "0x" + strings.Split(lines[0].addressRange, "-")[0]
	is64Bit := false
	for _, line := range lines {
		if line.end > 0xffffffff {
			is64Bit = true
			break
		}
	}
	return baseAddress, is64Bit
}

func fdCount(fdDir string) int {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return 0
	}
	return len(entries)
}

func readProcessDetails(root string, dir string, pid int, netByInode map[string]NetworkConnection) ProcessDetails {
	socketInodes := readSocketInodes(filepath.Join(dir, "fd"))
	connections := make([]NetworkConnection, 0, len(socketInodes))
	fields, _ := readStatus(filepath.Join(dir, "status"))
	processName := fields["Name"]
	for inode := range socketInodes {
		if conn, ok := netByInode[inode]; ok {
			conn.ProcessID = pid
			conn.ProcessName = processName
			connections = append(connections, conn)
		}
	}
	sort.Slice(connections, func(i, j int) bool { return connections[i].ID < connections[j].ID })
	return ProcessDetails{
		IOStats:            readIOStats(filepath.Join(dir, "io")),
		MemoryBlocks:       readMemoryBlocks(filepath.Join(dir, "maps")),
		Modules:            readModules(filepath.Join(dir, "maps")),
		Threads:            readThreads(filepath.Join(dir, "task")),
		NetworkConnections: connections,
		Handles:            readHandles(filepath.Join(dir, "fd")),
	}
}

func hasProcessDetails(details ProcessDetails) bool {
	return details.IOStats != nil || len(details.MemoryBlocks) > 0 || len(details.Modules) > 0 || len(details.Threads) > 0 || len(details.NetworkConnections) > 0
}

func readStatus(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fields := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return fields, scanner.Err()
}

func readCmdline(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	parts := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\x00' || r == '\n'
	})
	return strings.Join(parts, " ")
}

func readIOStats(path string) *IOStats {
	fields := readColonUintFields(path)
	if len(fields) == 0 {
		return nil
	}
	return &IOStats{
		ReadCount:          fields["syscr"],
		WriteCount:         fields["syscw"],
		ReadTransferCount:  fields["read_bytes"],
		WriteTransferCount: fields["write_bytes"],
	}
}

func readColonUintFields(path string) map[string]uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	fields := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err == nil {
			fields[strings.TrimSpace(key)] = parsed
		}
	}
	return fields
}

func readMemoryBlocks(path string) []MemoryBlock {
	lines := readMapLines(path)
	blocks := make([]MemoryBlock, 0, len(lines))
	for _, line := range lines {
		size := line.end - line.start
		blocks = append(blocks, MemoryBlock{
			ID:          line.addressRange,
			BaseAddress: "0x" + strings.Split(line.addressRange, "-")[0],
			Size:        strconv.FormatUint(size, 10),
			BlockType:   line.fsMode,
			Protection:  line.perms,
			Owner:       line.path,
			CanRead:     strings.Contains(line.perms, "r"),
			CanWrite:    strings.Contains(line.perms, "w"),
			CanExecute:  strings.Contains(line.perms, "x"),
			Deleted:     line.deleted,
			RiskTags:    mappingRiskTags(line.deleted, line.path, line.perms),
		})
	}
	return blocks
}

func readModules(path string) []Module {
	lines := readMapLines(path)
	byPath := map[string]Module{}
	for _, line := range lines {
		if line.path == "" || strings.HasPrefix(line.path, "[") {
			continue
		}
		module := byPath[line.path]
		if module.Path == "" {
			module = Module{
				ID:          line.path,
				Name:        filepath.Base(line.path),
				Path:        line.path,
				BaseAddress: "0x" + strings.Split(line.addressRange, "-")[0],
				Deleted:     line.deleted,
				RiskTags:    moduleRiskTags(line.deleted, line.path),
			}
		}
		if line.deleted {
			module.Deleted = true
			module.RiskTags = moduleRiskTags(true, line.path)
		}
		module.Size += line.end - line.start
		byPath[line.path] = module
	}
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	modules := make([]Module, 0, len(paths))
	for _, path := range paths {
		modules = append(modules, byPath[path])
	}
	return modules
}

func isTempEvidencePath(path string) bool {
	return path == "/tmp" || strings.HasPrefix(path, "/tmp/") ||
		path == "/var/tmp" || strings.HasPrefix(path, "/var/tmp/") ||
		path == "/dev/shm" || strings.HasPrefix(path, "/dev/shm/")
}

type mapLine struct {
	addressRange string
	start        uint64
	end          uint64
	perms        string
	fsMode       string
	path         string
	deleted      bool
}

func readMapLines(path string) []mapLine {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var lines []mapLine
	for _, raw := range strings.Split(string(data), "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 5 {
			continue
		}
		startHex, endHex, ok := strings.Cut(fields[0], "-")
		if !ok {
			continue
		}
		start, errStart := strconv.ParseUint(startHex, 16, 64)
		end, errEnd := strconv.ParseUint(endHex, 16, 64)
		if errStart != nil || errEnd != nil || end < start {
			continue
		}
		pathValue := ""
		deleted := false
		if len(fields) >= 6 {
			pathValue = strings.Join(fields[5:], " ")
			pathValue, deleted = stripLinuxDeletedSuffix(pathValue)
		}
		lines = append(lines, mapLine{
			addressRange: fields[0],
			start:        start,
			end:          end,
			perms:        fields[1],
			fsMode:       fields[4],
			path:         pathValue,
			deleted:      deleted,
		})
	}
	return lines
}

func readThreads(taskDir string) []Thread {
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil
	}
	threads := make([]Thread, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		fields, err := readStatus(filepath.Join(taskDir, entry.Name(), "status"))
		if err != nil {
			continue
		}
		threads = append(threads, Thread{
			ThreadID:        tid,
			State:           fields["State"],
			ContextSwitches: parseUint(fields["voluntary_ctxt_switches"]) + parseUint(fields["nonvoluntary_ctxt_switches"]),
		})
	}
	sort.Slice(threads, func(i, j int) bool { return threads[i].ThreadID < threads[j].ThreadID })
	return threads
}

func readSocketInodes(fdDir string) map[string]struct{} {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	inodes := map[string]struct{}{}
	for _, entry := range entries {
		target := readlink(filepath.Join(fdDir, entry.Name()))
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = struct{}{}
		}
	}
	return inodes
}

func readHandles(fdDir string) []Handle {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	handles := make([]Handle, 0, len(entries))
	for _, entry := range entries {
		target := readlink(filepath.Join(fdDir, entry.Name()))
		if target == "" {
			continue
		}
		handles = append(handles, Handle{
			ID:     entry.Name(),
			Kind:   handleKind(target),
			Target: target,
		})
	}
	sort.Slice(handles, func(i, j int) bool { return handles[i].ID < handles[j].ID })
	return handles
}

func handleKind(target string) string {
	switch {
	case strings.HasPrefix(target, "socket:["):
		return "socket"
	case strings.HasPrefix(target, "pipe:["):
		return "pipe"
	case strings.HasPrefix(target, "anon_inode:"):
		return "anon_inode"
	default:
		return "file"
	}
}

func readProcNet(root string) map[string]NetworkConnection {
	result := map[string]NetworkConnection{}
	for _, source := range []struct {
		path     string
		protocol string
	}{
		{path: filepath.Join(root, "proc", "net", "tcp"), protocol: "TCP"},
		{path: filepath.Join(root, "proc", "net", "tcp6"), protocol: "TCP6"},
		{path: filepath.Join(root, "proc", "net", "udp"), protocol: "UDP"},
		{path: filepath.Join(root, "proc", "net", "udp6"), protocol: "UDP6"},
	} {
		for _, conn := range readProcNetFile(source.path, source.protocol) {
			result[conn.Inode] = conn
		}
	}
	return result
}

func readProcNetFile(path string, protocol string) []NetworkConnection {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var connections []NetworkConnection
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] == "sl" {
			continue
		}
		ipv6 := strings.HasSuffix(protocol, "6")
		localAddress, localPort := parseProcNetEndpoint(fields[1], ipv6)
		remoteAddress, remotePort := parseProcNetEndpoint(fields[2], ipv6)
		stateCode, _ := strconv.ParseInt(fields[3], 16, 32)
		inode := fields[9]
		if inode == "" || inode == "0" {
			continue
		}
		connections = append(connections, NetworkConnection{
			ID:            protocol + ":" + inode,
			Protocol:      protocol,
			Family:        procNetFamily(ipv6),
			LocalAddress:  localAddress,
			LocalPort:     localPort,
			RemoteAddress: remoteAddress,
			RemotePort:    remotePort,
			StateCode:     int(stateCode),
			StateName:     tcpStateName(int(stateCode)),
			Inode:         inode,
		})
	}
	return connections
}

func parseProcNetEndpoint(value string, ipv6 bool) (string, int) {
	hostHex, portHex, ok := strings.Cut(value, ":")
	if !ok {
		return "", 0
	}
	port64, _ := strconv.ParseInt(portHex, 16, 32)
	if ipv6 {
		return decodeProcIPv6(hostHex), int(port64)
	}
	return decodeProcIPv4(hostHex), int(port64)
}

func procNetFamily(ipv6 bool) string {
	if ipv6 {
		return "AF_INET6"
	}
	return "AF_INET"
}

func decodeProcIPv6(value string) string {
	if len(value) != 32 {
		return ""
	}
	groups := make([]string, 0, 8)
	for offset := 0; offset < len(value); offset += 8 {
		word := value[offset : offset+8]
		for i := 6; i >= 0; i -= 2 {
			groups = append(groups, word[i:i+2])
		}
	}
	return strings.Join([]string{
		strings.Join(groups[0:2], ""),
		strings.Join(groups[2:4], ""),
		strings.Join(groups[4:6], ""),
		strings.Join(groups[6:8], ""),
		strings.Join(groups[8:10], ""),
		strings.Join(groups[10:12], ""),
		strings.Join(groups[12:14], ""),
		strings.Join(groups[14:16], ""),
	}, ":")
}

func decodeProcIPv4(value string) string {
	if len(value) != 8 {
		return ""
	}
	parts := make([]string, 0, 4)
	for i := 6; i >= 0; i -= 2 {
		part, err := strconv.ParseUint(value[i:i+2], 16, 8)
		if err != nil {
			return ""
		}
		parts = append(parts, strconv.FormatUint(part, 10))
	}
	return strings.Join(parts, ".")
}

func tcpStateName(code int) string {
	switch code {
	case 1:
		return "ESTABLISHED"
	case 7:
		return "CLOSE"
	case 10:
		return "LISTEN"
	default:
		return strconv.Itoa(code)
	}
}

func readPasswdUsers(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	users := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			users[parts[2]] = parts[0]
		}
	}
	return users
}

func usernameForUID(users map[string]string, uid string) string {
	if username := users[uid]; username != "" {
		return username
	}
	return uid
}

func readlink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return target
}

func parseInt(value string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func parseUint(value string) uint64 {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func firstField(value string) string {
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
