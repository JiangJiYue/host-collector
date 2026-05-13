//go:build windows

package collector

import (
	"context"
	"strconv"
	"strings"

	"github.com/StackExchange/wmi"
)

type windowsWMIAccountProvider struct{}

func (p windowsWMIAccountProvider) collect(ctx context.Context) ([]accountSourceRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	type wmiUser struct {
		Name     string
		FullName *string
		SID      *string
		Disabled bool
	}

	var users []wmiUser
	query := "SELECT Name, FullName, SID, Disabled FROM Win32_UserAccount WHERE LocalAccount = TRUE"
	if err := wmi.Query(query, &users); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	records := make([]accountSourceRecord, 0, len(users))
	for _, u := range users {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		rec := accountSourceRecord{
			Username:     strings.TrimSpace(u.Name),
			AccountType:  "local",
			Privilege:    "User",
			Disabled:     u.Disabled,
			LocalGroups:  []string{},
			GlobalGroups: []string{},
			Source:       accountSourceWMI,
			WMIVisible:   true,
		}

		if u.FullName != nil && strings.TrimSpace(*u.FullName) != "" {
			full := strings.TrimSpace(*u.FullName)
			rec.FullName = &full
		}
		if u.SID != nil && strings.TrimSpace(*u.SID) != "" {
			sid := strings.TrimSpace(*u.SID)
			rec.SID = &sid
			if rid := ridFromSID(sid); rid != nil {
				rec.RID = rid
			}
		}

		records = append(records, rec)
	}

	return records, nil
}

func ridFromSID(sid string) *uint32 {
	sid = strings.TrimSpace(sid)
	if sid == "" {
		return nil
	}
	lastDash := strings.LastIndexByte(sid, '-')
	if lastDash < 0 || lastDash+1 >= len(sid) {
		return nil
	}
	part := strings.TrimSpace(sid[lastDash+1:])
	if part == "" {
		return nil
	}
	parsed, err := strconv.ParseUint(part, 10, 32)
	if err != nil {
		return nil
	}
	v := uint32(parsed)
	return &v
}
