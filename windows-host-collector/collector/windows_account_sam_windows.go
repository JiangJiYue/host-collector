//go:build windows

package collector

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"windows-host-collector/models"
)

const (
	samUsersPath             = `SAM\SAM\Domains\Account\Users`
	samRootPath              = `SAM`
	samUsersSubPath          = `SAM\Domains\Account\Users`
	samNamesSubKey           = `Names`
	samBuiltinAliasesPath    = `SAM\SAM\Domains\Builtin\Aliases`
	samBuiltinAliasesSubPath = `SAM\Domains\Builtin\Aliases`
	samBuiltinMembersSubKey  = `Members`
	seBackupPrivilege        = "SeBackupPrivilege"
	regsamRead               = 0x00020019
	regsamBackupRead         = 0x00020019 | 0x00020000
	regOptionBackup          = 0x00000004
	regProcessAppKey         = 0x00000001
)

var watchedBuiltinAliases = map[uint32]string{
	544: "Administrators",
	551: "Backup Operators",
	555: "Remote Desktop Users",
}

var (
	advapi32Proc       = windows.NewLazySystemDLL("advapi32.dll")
	procRegCreateKeyEx = advapi32Proc.NewProc("RegCreateKeyExW")
	procRegSaveKeyW    = advapi32Proc.NewProc("RegSaveKeyW")
	procRegLoadAppKeyW = advapi32Proc.NewProc("RegLoadAppKeyW")
)

type windowsSAMAccountProvider struct{}

type samAccountRecord struct {
	Username         string
	RID              uint32
	RIDKey           bool
	NameIndex        bool
	NameIndexRID     *uint32
	FDigest          string
	VDigest          string
	ParsedUsername   *string
	FullName         *string
	Comment          *string
	Flags            *uint32
	LastLogon        *string
	LoginFailures    *int
	LoginSuccesses   *int
	AliasMemberships []string
}

func (p windowsSAMAccountProvider) collect(ctx context.Context) (sources []accountSourceRecord, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	usersKey, aliasesKey, closeKeys, err := openSAMSnapshotKeys(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := closeKeys(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	var records []samAccountRecord
	records, err = collectSAMRecords(ctx, usersKey, aliasesKey)
	if err != nil {
		return nil, err
	}

	sources = make([]accountSourceRecord, 0, len(records))
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sources = append(sources, samAccountRecordToSource(record))
	}
	return sources, nil
}

func openSAMSnapshotKeys(ctx context.Context) (registry.Key, registry.Key, func() error, error) {
	usersKey, err := openLiveSAMKey(samUsersPath)
	if err == nil {
		aliasesKey, aliasesErr := openLiveSAMKey(samBuiltinAliasesPath)
		if aliasesErr == nil {
			return usersKey, aliasesKey, func() error {
				return joinCleanupErrors(usersKey.Close(), aliasesKey.Close())
			}, nil
		}
		usersKey.Close()
	}
	return openBackupSAMSnapshotKeys(ctx)
}

func openLiveSAMKey(path string) (registry.Key, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return 0, err
	}
	return key, nil
}

func openBackupSAMSnapshotKeys(ctx context.Context) (registry.Key, registry.Key, func() error, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, func() error { return nil }, err
	}

	restore, err := enablePrivilege(seBackupPrivilege)
	if err != nil {
		return 0, 0, func() error { return nil }, err
	}
	restorePending := true
	restoreAndRelease := func() error {
		if !restorePending {
			return nil
		}
		restorePending = false
		return restore()
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, restoreAndRelease())
	}

	rootKey, err := regCreateKeyBackupOpen(registry.LOCAL_MACHINE, samRootPath, regsamBackupRead)
	if err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, restoreAndRelease())
	}
	rootKeyPending := true
	closeRootKey := func() error {
		if !rootKeyPending {
			return nil
		}
		rootKeyPending = false
		return rootKey.Close()
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, joinCleanupErrors(closeRootKey(), restoreAndRelease()))
	}

	tempDir, err := os.MkdirTemp("", "host-collector-sam-*")
	if err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, joinCleanupErrors(closeRootKey(), restoreAndRelease()))
	}
	tempPath := filepath.Join(tempDir, "sam.hiv")
	tempDirPending := true
	removeTempDir := func() error {
		if !tempDirPending {
			return nil
		}
		tempDirPending = false
		return os.RemoveAll(tempDir)
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, joinCleanupErrors(removeTempDir(), closeRootKey(), restoreAndRelease()))
	}

	cleanup := func() error {
		return joinCleanupErrors(removeTempDir(), closeRootKey(), restoreAndRelease())
	}

	if err := regSaveKey(rootKey, tempPath); err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, cleanup())
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, cleanup())
	}

	appKey, err := regLoadAppKey(tempPath)
	if err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, cleanup())
	}
	appKeyPending := true
	closeAppKey := func() error {
		if !appKeyPending {
			return nil
		}
		appKeyPending = false
		return appKey.Close()
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, joinCleanupErrors(closeAppKey(), cleanup()))
	}

	usersKey, err := registry.OpenKey(appKey, samUsersSubPath, registry.READ)
	if err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, joinCleanupErrors(closeAppKey(), cleanup()))
	}
	usersKeyPending := true
	closeUsersKey := func() error {
		if !usersKeyPending {
			return nil
		}
		usersKeyPending = false
		return usersKey.Close()
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, joinCleanupErrors(closeUsersKey(), closeAppKey(), cleanup()))
	}

	aliasesKey, err := registry.OpenKey(appKey, samBuiltinAliasesSubPath, registry.READ)
	if err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, joinCleanupErrors(closeUsersKey(), closeAppKey(), cleanup()))
	}
	aliasesKeyPending := true
	closeAliasesKey := func() error {
		if !aliasesKeyPending {
			return nil
		}
		aliasesKeyPending = false
		return aliasesKey.Close()
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, func() error { return nil }, combineCleanupError(err, joinCleanupErrors(closeAliasesKey(), closeUsersKey(), closeAppKey(), cleanup()))
	}

	closeKeys := func() error {
		return joinCleanupErrors(closeAliasesKey(), closeUsersKey(), closeAppKey(), cleanup())
	}

	return usersKey, aliasesKey, closeKeys, nil
}

func collectSAMRecords(ctx context.Context, usersKey registry.Key, aliasesKey registry.Key) ([]samAccountRecord, error) {
	ridRecords, err := readSAMRIDRecords(ctx, usersKey)
	if err != nil {
		return nil, err
	}
	nameRecords, err := readSAMNameRecords(ctx, usersKey)
	if err != nil {
		return nil, err
	}
	aliasMemberships, localDomainSID, err := readBuiltinAliasMemberships(ctx, aliasesKey)
	if err != nil {
		return nil, err
	}

	recordsByRID := make(map[uint32]*samAccountRecord, len(ridRecords)+len(nameRecords))
	order := make([]uint32, 0, len(ridRecords)+len(nameRecords))
	unresolvedNameRecords := make([]samAccountRecord, 0)

	for _, record := range ridRecords {
		recordCopy := record
		recordsByRID[record.RID] = &recordCopy
		order = append(order, record.RID)
	}

	for _, record := range nameRecords {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if record.NameIndexRID == nil {
			unresolvedNameRecords = append(unresolvedNameRecords, record)
			continue
		}
		existing, ok := recordsByRID[record.RID]
		if !ok {
			recordCopy := record
			recordsByRID[record.RID] = &recordCopy
			order = append(order, record.RID)
			continue
		}
		if strings.TrimSpace(existing.Username) == "" && strings.TrimSpace(record.Username) != "" {
			existing.Username = strings.TrimSpace(record.Username)
		}
		existing.NameIndex = existing.NameIndex || record.NameIndex
		if existing.NameIndexRID == nil && record.NameIndexRID != nil {
			ridCopy := *record.NameIndexRID
			existing.NameIndexRID = &ridCopy
		}
	}

	result := make([]samAccountRecord, 0, len(order))
	for _, rid := range order {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		record := *recordsByRID[rid]
		if strings.TrimSpace(record.Username) == "" {
			record.Username = fmt.Sprintf("RID-%08X", record.RID)
		}
		result = append(result, record)
	}
	for _, record := range unresolvedNameRecords {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	mergeAliasMemberships(result, aliasMemberships, localDomainSID)
	return result, nil
}

func readBuiltinAliasMemberships(ctx context.Context, aliasesKey registry.Key) (map[string][]string, string, error) {
	membersKey, err := registry.OpenKey(aliasesKey, samBuiltinMembersSubKey, registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return map[string][]string{}, "", nil
		}
		return nil, "", err
	}
	defer membersKey.Close()

	domainNames, err := membersKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, "", err
	}

	aliasMemberships := make(map[string][]string)
	localDomainSID := ""
	for _, domainName := range domainNames {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		domainKey, openErr := registry.OpenKey(membersKey, domainName, registry.READ)
		if openErr != nil {
			continue
		}

		if localDomainSID == "" && strings.HasPrefix(domainName, "S-1-5-21-") {
			localDomainSID = domainName
		}

		memberNames, readErr := domainKey.ReadSubKeyNames(-1)
		if readErr != nil {
			domainKey.Close()
			return nil, "", readErr
		}
		for _, memberName := range memberNames {
			if err := ctx.Err(); err != nil {
				domainKey.Close()
				return nil, "", err
			}
			memberRID, ok := parseSAMRIDKeyName(memberName)
			if !ok {
				continue
			}
			memberKey, memberErr := registry.OpenKey(domainKey, memberName, registry.QUERY_VALUE)
			if memberErr != nil {
				continue
			}
			aliasRIDs, parseErr := readAliasMembershipRIDs(memberKey)
			memberKey.Close()
			if parseErr != nil {
				domainKey.Close()
				return nil, "", parseErr
			}
			if len(aliasRIDs) == 0 {
				continue
			}
			memberSID := fmt.Sprintf("%s-%d", strings.TrimSpace(domainName), memberRID)
			aliasNames := aliasMemberships[memberSID]
			for _, aliasRID := range aliasRIDs {
				aliasName, watched := watchedBuiltinAliases[aliasRID]
				if !watched {
					continue
				}
				aliasNames = appendUniqueString(aliasNames, aliasName)
			}
			if len(aliasNames) > 0 {
				aliasMemberships[memberSID] = aliasNames
			}
		}
		domainKey.Close()
	}

	return aliasMemberships, localDomainSID, nil
}

func mergeAliasMemberships(records []samAccountRecord, aliasMemberships map[string][]string, localDomainSID string) {
	if len(aliasMemberships) == 0 || strings.TrimSpace(localDomainSID) == "" {
		return
	}
	for i := range records {
		if records[i].RID == 0 {
			continue
		}
		sid := fmt.Sprintf("%s-%d", strings.TrimSpace(localDomainSID), records[i].RID)
		if aliases, ok := aliasMemberships[sid]; ok && len(aliases) > 0 {
			records[i].AliasMemberships = append([]string{}, aliases...)
		}
	}
}

func readAliasMembershipRIDs(key registry.Key) ([]uint32, error) {
	n, valueType, err := key.GetValue("", nil)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return nil, nil
		}
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	n, valueType, err = key.GetValue("", buf)
	if err != nil {
		return nil, err
	}
	return parseAliasMembershipRIDsRaw(buf[:n], valueType), nil
}

func readSAMRIDRecords(ctx context.Context, usersKey registry.Key) ([]samAccountRecord, error) {
	names, err := usersKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	records := make([]samAccountRecord, 0, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rid, ok := parseSAMRIDKeyName(name)
		if !ok {
			continue
		}
		record := samAccountRecord{
			RID:    rid,
			RIDKey: true,
		}
		if userKey, openErr := registry.OpenKey(usersKey, name, registry.QUERY_VALUE); openErr == nil {
			fValue, _ := readSAMUserBinary(userKey, "F")
			vValue, _ := readSAMUserBinary(userKey, "V")
			record.FDigest = digestSAMValue("sha256:", fValue)
			record.VDigest = digestSAMValue("sha256:", vValue)
			mergeParsedSAMFValue(&record, parseSAMFValue(fValue))
			mergeParsedSAMVValue(&record, parseSAMVValue(vValue))
			if record.ParsedUsername != nil && strings.TrimSpace(*record.ParsedUsername) != "" {
				record.Username = strings.TrimSpace(*record.ParsedUsername)
			}
			userKey.Close()
		}
		records = append(records, record)
	}
	return records, nil
}

func readSAMUserBinary(key registry.Key, valueName string) ([]byte, error) {
	n, valueType, err := key.GetValue(valueName, nil)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return nil, nil
		}
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	n, valueType, err = key.GetValue(valueName, buf)
	if err != nil {
		return nil, err
	}
	if valueType != registry.BINARY {
		return nil, nil
	}
	return append([]byte(nil), buf[:n]...), nil
}

func digestSAMValue(prefix string, data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return prefix + hex.EncodeToString(sum[:])
}

type parsedSAMFValue struct {
	Flags          *uint32
	LastLogon      *string
	LoginFailures  *int
	LoginSuccesses *int
}

type parsedSAMVValue struct {
	Username *string
	FullName *string
	Comment  *string
}

func parseSAMFValue(data []byte) parsedSAMFValue {
	if len(data) < 68 {
		return parsedSAMFValue{}
	}

	flags := uint32(binary.LittleEndian.Uint16(data[56:58]))
	loginFailuresValue := int(binary.LittleEndian.Uint16(data[64:66]))
	loginSuccessesValue := int(binary.LittleEndian.Uint16(data[66:68]))

	return parsedSAMFValue{
		Flags:          &flags,
		LastLogon:      formatSAMFiletime(binary.LittleEndian.Uint64(data[8:16])),
		LoginFailures:  &loginFailuresValue,
		LoginSuccesses: &loginSuccessesValue,
	}
}

func parseSAMVValue(data []byte) parsedSAMVValue {
	if len(data) < 0xCC {
		return parsedSAMVValue{}
	}
	return parsedSAMVValue{
		Username: readSAMVUTF16Field(data, 0x0C, 0x10),
		FullName: readSAMVUTF16Field(data, 0x18, 0x1C),
		Comment:  readSAMVUTF16Field(data, 0x24, 0x28),
	}
}

func mergeParsedSAMFValue(record *samAccountRecord, parsed parsedSAMFValue) {
	if parsed.Flags != nil {
		record.Flags = copyUint32Ptr(parsed.Flags)
	}
	if parsed.LastLogon != nil {
		record.LastLogon = copyStringPtr(parsed.LastLogon)
	}
	if parsed.LoginFailures != nil {
		record.LoginFailures = copyIntPtr(parsed.LoginFailures)
	}
	if parsed.LoginSuccesses != nil {
		record.LoginSuccesses = copyIntPtr(parsed.LoginSuccesses)
	}
}

func mergeParsedSAMVValue(record *samAccountRecord, parsed parsedSAMVValue) {
	record.ParsedUsername = copyStringPtr(parsed.Username)
	record.FullName = copyStringPtr(parsed.FullName)
	record.Comment = copyStringPtr(parsed.Comment)
}

func readSAMVUTF16Field(data []byte, offsetOffset uint32, lengthOffset uint32) *string {
	if int(lengthOffset+4) > len(data) || int(offsetOffset+4) > len(data) {
		return nil
	}
	fieldOffset := binary.LittleEndian.Uint32(data[offsetOffset:offsetOffset+4]) + 0xCC
	fieldLength := binary.LittleEndian.Uint32(data[lengthOffset:lengthOffset+4])
	if fieldLength == 0 {
		return nil
	}
	end := fieldOffset + fieldLength
	if end > uint32(len(data)) || fieldOffset >= uint32(len(data)) {
		return nil
	}
	return decodeUTF16LEString(data[fieldOffset:end])
}

func decodeUTF16LEString(data []byte) *string {
	if len(data) < 2 {
		return nil
	}
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	if len(data) == 0 {
		return nil
	}
	words := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		words = append(words, binary.LittleEndian.Uint16(data[i:i+2]))
	}
	decoded := strings.TrimSpace(string(utf16.Decode(words)))
	if decoded == "" {
		return nil
	}
	return &decoded
}

func formatSAMFiletime(filetime uint64) *string {
	if filetime == 0 || filetime == ^uint64(0) {
		return nil
	}
	const windowsToUnixEpochTicks = uint64(116444736000000000)
	if filetime < windowsToUnixEpochTicks {
		return nil
	}
	nanos := int64((filetime - windowsToUnixEpochTicks) * 100)
	timestamp := time.Unix(0, nanos).UTC().Format(time.RFC3339)
	return &timestamp
}

func parseAliasMembershipRIDsRaw(data []byte, valueType uint32) []uint32 {
	if len(data) == 0 {
		return nil
	}

	set := map[uint32]struct{}{}
	if valueType == registry.DWORD && len(data) >= 4 {
		set[binary.LittleEndian.Uint32(data[:4])] = struct{}{}
	}
	if valueType == registry.QWORD && len(data) >= 8 {
		value := binary.LittleEndian.Uint64(data[:8])
		if value <= uint64(^uint32(0)) {
			set[uint32(value)] = struct{}{}
		}
	}
	if len(data)%2 == 0 {
		for i := 0; i+1 < len(data); i += 2 {
			value := uint32(binary.LittleEndian.Uint16(data[i : i+2]))
			if value != 0 {
				set[value] = struct{}{}
			}
		}
	}
	if len(data)%4 == 0 {
		for i := 0; i+3 < len(data); i += 4 {
			value := binary.LittleEndian.Uint32(data[i : i+4])
			if value != 0 {
				set[value] = struct{}{}
			}
		}
	}

	values := make([]uint32, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	return values
}

func appendUniqueString(values []string, next string) []string {
	next = strings.TrimSpace(next)
	if next == "" {
		return values
	}
	for _, existing := range values {
		if strings.EqualFold(strings.TrimSpace(existing), next) {
			return values
		}
	}
	return append(values, next)
}

func readSAMNameRecords(ctx context.Context, usersKey registry.Key) ([]samAccountRecord, error) {
	namesKey, err := registry.OpenKey(usersKey, samNamesSubKey, registry.READ)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
			return []samAccountRecord{}, nil
		}
		return nil, err
	}
	defer namesKey.Close()

	names, err := namesKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	records := make([]samAccountRecord, 0, len(names))
	for _, username := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		nameKey, err := registry.OpenKey(namesKey, username, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		record := samAccountRecord{
			Username:  strings.TrimSpace(username),
			NameIndex: true,
		}
		if rid := bestEffortNameIndexRID(nameKey); rid != nil {
			record.RID = *rid
			record.NameIndexRID = rid
		}
		nameKey.Close()
		records = append(records, record)
	}
	return records, nil
}

func bestEffortNameIndexRID(key registry.Key) *uint32 {
	if rid := samRIDFromKeyClass(key); rid != nil {
		return rid
	}

	intVal, _, err := key.GetIntegerValue("")
	if err == nil {
		rid := uint32(intVal)
		return &rid
	}

	n, valueType, err := key.GetValue("", nil)
	if err != nil || n <= 0 {
		return nil
	}
	buf := make([]byte, n)
	n, valueType, err = key.GetValue("", buf)
	if err != nil {
		return nil
	}
	buf = buf[:n]

	switch valueType {
	case registry.DWORD:
		if len(buf) < 4 {
			return nil
		}
		rid := uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24
		return &rid
	case registry.QWORD:
		if len(buf) < 8 {
			return nil
		}
		rid64 := uint64(buf[0]) |
			uint64(buf[1])<<8 |
			uint64(buf[2])<<16 |
			uint64(buf[3])<<24 |
			uint64(buf[4])<<32 |
			uint64(buf[5])<<40 |
			uint64(buf[6])<<48 |
			uint64(buf[7])<<56
		rid := uint32(rid64)
		return &rid
	default:
		return nil
	}
}

func samRIDFromKeyClass(key registry.Key) *uint32 {
	className, err := regQueryKeyClass(key)
	if err != nil {
		return nil
	}
	rid, ok := parseSAMRIDFromClassString(className)
	if !ok {
		return nil
	}
	return &rid
}

func parseSAMRIDKeyName(name string) (uint32, bool) {
	if len(name) != 8 {
		return 0, false
	}
	parsed, err := strconv.ParseUint(name, 16, 32)
	if err != nil {
		return 0, false
	}
	return uint32(parsed), true
}

func parseSAMRIDFromClassString(className string) (uint32, bool) {
	return parseSAMRIDKeyName(strings.TrimSpace(className))
}

func samAccountRecordToSource(record samAccountRecord) accountSourceRecord {
	username := strings.TrimSpace(record.Username)
	if username == "" {
		username = fmt.Sprintf("RID-%08X", record.RID)
	}

	source := accountSourceRecord{
		Username:           username,
		AccountType:        "local",
		Privilege:          "User",
		LocalGroups:        []string{},
		GlobalGroups:       []string{},
		Source:             accountSourceSAM,
		SAMAliasMembership: len(record.AliasMemberships) > 0,
		SAMRidKey:          record.RIDKey,
		SAMNameIndex:       record.NameIndex,
		NameIndexRID:       copyUint32Ptr(record.NameIndexRID),
		RIDKeyPresent:      record.RIDKey,
		NameIndexPresent:   record.NameIndex,
		SAM: &models.SAMAccountEvidence{
			NameIndexRID:            copyUint32Ptr(record.NameIndexRID),
			RIDKeyPresent:           record.RIDKey,
			NameIndexPresent:        record.NameIndex,
			FDigest:                 strings.TrimSpace(record.FDigest),
			VDigest:                 strings.TrimSpace(record.VDigest),
			ParsedUsername:          copyStringPtr(record.ParsedUsername),
			ParsedFullName:          copyStringPtr(record.FullName),
			ParsedComment:           copyStringPtr(record.Comment),
			Flags:                   copyUint32Ptr(record.Flags),
			LastLogon:               copyStringPtr(record.LastLogon),
			LoginFailures:           copyIntPtr(record.LoginFailures),
			LoginSuccesses:          copyIntPtr(record.LoginSuccesses),
			BuiltinAliasMemberships: append([]string{}, record.AliasMemberships...),
		},
	}
	if record.RID != 0 || record.RIDKey || record.NameIndexRID != nil {
		rid := record.RID
		source.RID = &rid
	}
	return source
}

func regSaveKey(key registry.Key, path string) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r1, _, _ := procRegSaveKeyW.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(pathPtr)),
		0,
	)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func regLoadAppKey(path string) (registry.Key, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	var handle windows.Handle
	r1, _, _ := procRegLoadAppKeyW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&handle)),
		uintptr(regsamRead),
		0,
		uintptr(regProcessAppKey),
	)
	if r1 != 0 {
		return 0, syscall.Errno(r1)
	}
	return registry.Key(handle), nil
}

func regCreateKeyBackupOpen(parent registry.Key, path string, access uint32) (registry.Key, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	var handle windows.Handle
	var disposition uint32
	r1, _, _ := procRegCreateKeyEx.Call(
		uintptr(parent),
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		0,
		uintptr(regOptionBackup),
		uintptr(access),
		0,
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(&disposition)),
	)
	if r1 != 0 {
		return 0, syscall.Errno(r1)
	}
	return registry.Key(handle), nil
}

func regQueryKeyClass(key registry.Key) (string, error) {
	classLen := uint32(0)
	if err := windows.RegQueryInfoKey(windows.Handle(key), nil, &classLen, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		if err != syscall.ERROR_MORE_DATA && err != windows.ERROR_SUCCESS {
			return "", err
		}
	}
	if classLen == 0 {
		return "", nil
	}

	buf := make([]uint16, classLen+1)
	if err := windows.RegQueryInfoKey(windows.Handle(key), &buf[0], &classLen, nil, nil, nil, nil, nil, nil, nil, nil, nil); err != nil {
		return "", err
	}
	return syscall.UTF16ToString(buf[:classLen]), nil
}

func combineCleanupError(mainErr error, cleanupErr error) error {
	if mainErr == nil {
		return cleanupErr
	}
	if cleanupErr == nil {
		return mainErr
	}
	return fmt.Errorf("%w; cleanup error: %v", mainErr, cleanupErr)
}

func joinCleanupErrors(errs ...error) error {
	var joined error
	for _, err := range errs {
		if err == nil {
			continue
		}
		if joined == nil {
			joined = err
			continue
		}
		joined = fmt.Errorf("%w; %v", joined, err)
	}
	return joined
}
