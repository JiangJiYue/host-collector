//go:build windows

package collector

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsNetAPIAccountProvider struct{}

func (p windowsNetAPIAccountProvider) collect(ctx context.Context) ([]accountSourceRecord, error) {
	usernames, err := netUserEnumNames(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	records := make([]accountSourceRecord, 0, len(usernames))
	for _, username := range usernames {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		rec := accountSourceRecord{
			Username:      username,
			AccountType:   "local",
			Privilege:     "User",
			LocalGroups:   []string{},
			GlobalGroups:  []string{},
			Source:        accountSourceNetAPI,
			NetAPIVisible: true,
		}

		// Best-effort SID lookup; non-fatal.
		if sidStr, sidErr := lookupLocalAccountSID(username); sidErr == nil {
			sidStr = strings.TrimSpace(sidStr)
			if sidStr != "" {
				sidCopy := sidStr
				rec.SID = &sidCopy
			}
		}

		info, infoErr := netUserGetInfo(username)
		if infoErr != nil {
			records = append(records, rec)
			continue
		}

		rec.FullName = info.FullName
		rec.Comment = info.Comment
		rec.LogonScript = info.ScriptPath
		rec.Privilege = netUserPrivilege(info.Priv)
		rec.LoginFailures = int(info.BadPwCount)
		rec.LoginSuccesses = int(info.NumLogons)
		rec.LocalGroups = netUserGetGroups(username)
		rec.Disabled = info.Flags&0x0002 != 0

		if info.UserID != 0 {
			rid := info.UserID
			rec.RID = &rid
		}
		rec.LastLogon = winTimeToRFC3339(info.LastLogon)
		if info.AcctExpires != 0xFFFFFFFF {
			rec.ExpiresAt = winTimeToRFC3339(info.AcctExpires)
		}

		records = append(records, rec)
	}

	return records, nil
}

// netUserInfo is a materialized, safe copy of NetUserGetInfo level 3 data.
// The underlying NetAPI buffer is freed before returning.
type netUserInfo struct {
	FullName   *string
	Comment    *string
	ScriptPath *string

	Priv       uint32
	Flags      uint32
	LastLogon  uint32
	AcctExpires uint32
	BadPwCount uint32
	NumLogons  uint32
	UserID     uint32
}

var (
	netapi32                  = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserEnum           = netapi32.NewProc("NetUserEnum")
	procNetApiBufferFree      = netapi32.NewProc("NetApiBufferFree")
	procNetUserGetInfo        = netapi32.NewProc("NetUserGetInfo")
	procNetUserGetLocalGroups = netapi32.NewProc("NetUserGetLocalGroups")
)

const (
	filterNormalAccount  = 0x0002
	errorMoreData        = 234
	maxPreferredLength   = 0xFFFFFFFF
	netUserInfoLevel0    = 0
	netUserInfoLevel3    = 3
	localGroupInfoLevel0 = 0
)

type userInfo0 struct {
	Name *uint16
}

type userInfo3 struct {
	Name            *uint16
	Password        *uint16
	PasswordAge     uint32
	Priv            uint32
	HomeDir         *uint16
	Comment         *uint16
	Flags           uint32
	ScriptPath      *uint16
	AuthFlags       uint32
	FullName        *uint16
	UsrComment      *uint16
	Parms           *uint16
	Workstations    *uint16
	LastLogon       uint32
	LastLogoff      uint32
	AcctExpires     uint32
	MaxStorage      uint32
	UnitsPerWeek    uint32
	LogonHours      *byte
	BadPwCount      uint32
	NumLogons       uint32
	LogonServer     *uint16
	CountryCode     uint32
	CodePage        uint32
	UserID          uint32
	PrimaryGroupID  uint32
	Profile         *uint16
	HomeDirDrive    *uint16
	PasswordExpired uint32
}

type localGroupUsersInfo0 struct {
	Name *uint16
}

func netUserEnumNames(ctx context.Context) ([]string, error) {
	result := []string{}
	var resumeHandle uint32

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for {
		var bufptr *byte
		var entriesRead, totalEntries uint32

		r1, _, _ := procNetUserEnum.Call(
			0,
			uintptr(netUserInfoLevel0),
			uintptr(filterNormalAccount),
			uintptr(unsafe.Pointer(&bufptr)),
			uintptr(maxPreferredLength),
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)
		if r1 != 0 && r1 != errorMoreData {
			return nil, fmt.Errorf("NetUserEnum failed with error %d", r1)
		}

		if bufptr != nil {
			size := unsafe.Sizeof(userInfo0{})
			for i := uint32(0); i < entriesRead; i++ {
				entry := (*userInfo0)(unsafe.Pointer(uintptr(unsafe.Pointer(bufptr)) + uintptr(i)*size))
				name := windows.UTF16PtrToString(entry.Name)
				if name != "" {
					result = append(result, name)
				}
			}
			procNetApiBufferFree.Call(uintptr(unsafe.Pointer(bufptr)))
			bufptr = nil
		}

		if r1 == errorMoreData {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			continue
		}
		break
	}

	return result, nil
}

func netUserGetInfo(username string) (*netUserInfo, error) {
	userName, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return nil, err
	}

	var bufptr *byte
	r1, _, _ := procNetUserGetInfo.Call(
		0,
		uintptr(unsafe.Pointer(userName)),
		uintptr(netUserInfoLevel3),
		uintptr(unsafe.Pointer(&bufptr)),
	)
	if r1 != 0 {
		return nil, fmt.Errorf("NetUserGetInfo failed with error %d", r1)
	}
	if bufptr == nil {
		return nil, fmt.Errorf("NetUserGetInfo returned nil buffer")
	}
	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(bufptr)))

	info := (*userInfo3)(unsafe.Pointer(bufptr))
	// Materialize all required fields before the NetAPI buffer is freed.
	out := &netUserInfo{
		FullName:    utf16PtrOrNil(info.FullName),
		Comment:     utf16PtrOrNil(info.Comment),
		ScriptPath:  utf16PtrOrNil(info.ScriptPath),
		Priv:        info.Priv,
		Flags:       info.Flags,
		LastLogon:   info.LastLogon,
		AcctExpires: info.AcctExpires,
		BadPwCount:  info.BadPwCount,
		NumLogons:   info.NumLogons,
		UserID:      info.UserID,
	}
	return out, nil
}

func netUserGetGroups(username string) []string {
	userName, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		return []string{}
	}

	var bufptr *byte
	var entriesRead, totalEntries uint32
	r1, _, _ := procNetUserGetLocalGroups.Call(
		0,
		uintptr(unsafe.Pointer(userName)),
		uintptr(localGroupInfoLevel0),
		0,
		uintptr(unsafe.Pointer(&bufptr)),
		uintptr(maxPreferredLength),
		uintptr(unsafe.Pointer(&entriesRead)),
		uintptr(unsafe.Pointer(&totalEntries)),
	)
	if r1 != 0 || bufptr == nil {
		return []string{}
	}
	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(bufptr)))

	size := unsafe.Sizeof(localGroupUsersInfo0{})
	groups := make([]string, 0, entriesRead)
	for i := uint32(0); i < entriesRead; i++ {
		entry := (*localGroupUsersInfo0)(unsafe.Pointer(uintptr(unsafe.Pointer(bufptr)) + uintptr(i)*size))
		name := windows.UTF16PtrToString(entry.Name)
		if name != "" {
			groups = append(groups, name)
		}
	}
	return groups
}

func netUserPrivilege(value uint32) string {
	switch value {
	case 0:
		return "Guest"
	case 1:
		return "User"
	case 2:
		return "Administrator"
	default:
		return "User"
	}
}

func lookupLocalAccountSID(username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("username is empty")
	}

	// Prefer explicit local account lookup (.\name) to avoid domain ambiguity.
	if sid, err := lookupAccountSID(".\\" + username); err == nil {
		return sid, nil
	}
	return lookupAccountSID(username)
}

func lookupAccountSID(name string) (string, error) {
	accountName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}

	var sidLen uint32
	var domainLen uint32
	var use uint32
	err = windows.LookupAccountName(nil, accountName, nil, &sidLen, nil, &domainLen, &use)
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return "", err
	}
	if sidLen == 0 {
		return "", fmt.Errorf("LookupAccountName returned sidLen=0 for %q", name)
	}

	sidBuf := make([]byte, sidLen)
	sid := (*windows.SID)(unsafe.Pointer(&sidBuf[0]))

	var domainPtr *uint16
	if domainLen > 0 {
		domainBuf := make([]uint16, domainLen)
		domainPtr = &domainBuf[0]
	}

	if err := windows.LookupAccountName(nil, accountName, sid, &sidLen, domainPtr, &domainLen, &use); err != nil {
		return "", err
	}
	return sid.String(), nil
}

func utf16PtrOrNil(p *uint16) *string {
	if p == nil {
		return nil
	}
	s := windows.UTF16PtrToString(p)
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

func winTimeToRFC3339(seconds uint32) *string {
	if seconds == 0 || seconds == 0xFFFFFFFF {
		return nil
	}
	s := time.Unix(int64(seconds), 0).Format(time.RFC3339)
	return &s
}
