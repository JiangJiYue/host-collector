//go:build windows

package collector

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

type windowsNetCommandAccountProvider struct{}

func (p windowsNetCommandAccountProvider) collect(ctx context.Context) ([]accountSourceRecord, error) {
	output, err := runHiddenNetUserList(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	usernames := parseNetUserListOutput(output)
	records := make([]accountSourceRecord, 0, len(usernames))
	for _, username := range usernames {
		username = strings.TrimSpace(username)
		if username == "" {
			continue
		}
		records = append(records, accountSourceRecord{
			Username:          username,
			AccountType:       "local",
			Privilege:         "User",
			LocalGroups:       []string{},
			GlobalGroups:      []string{},
			Source:            accountSourceNetCmd,
			NetCommandVisible: true,
		})
	}

	return records, nil
}

func runHiddenNetUserList(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "cmd", "/C", "chcp 65001>nul && net user")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run hidden net user failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func runHiddenNetCommand(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "net", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run hidden net %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
