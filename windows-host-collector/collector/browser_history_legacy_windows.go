//go:build windows && legacyruntime

package collector

import (
	"context"
	"fmt"
)

func queryBrowserHistory(ctx context.Context, definition browserDefinition, profilePath string) ([]historyRow, error) {
	return nil, fmt.Errorf("browser history sqlite collection is disabled in the Windows legacy runtime")
}

func formatVisitTime(mode browserTimeMode, raw int64) string {
	return ""
}
