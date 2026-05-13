//go:build windows && !legacyruntime

package collector

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const chromeEpochDiffSeconds = 11644473600

func queryBrowserHistory(ctx context.Context, definition browserDefinition, profilePath string) ([]historyRow, error) {
	sourcePath := filepath.Join(profilePath, definition.HistoryFile)
	tempPath, cleanup, err := copyHistoryDatabase(sourcePath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	db, err := sql.Open("sqlite", tempPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, definition.Query, definition.MaxRowsPerProfile)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]historyRow, 0)
	for rows.Next() {
		var row historyRow
		if err := rows.Scan(&row.URL, &row.Title, &row.VisitTime); err != nil {
			return nil, err
		}
		results = append(results, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func copyHistoryDatabase(sourcePath string) (string, func(), error) {
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return "", nil, err
	}
	tempDir, err := os.MkdirTemp("", "browser-history-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
	}
	tempPath := filepath.Join(tempDir, filepath.Base(sourcePath))
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		cleanup()
		return "", nil, err
	}

	for _, suffix := range []string{"-wal", "-shm"} {
		sidecarSourcePath := sourcePath + suffix
		sidecarData, err := os.ReadFile(sidecarSourcePath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			// The shared-memory sidecar is transient for live browsers.
			// Keep it best-effort so a locked/unreadable -shm does not block history collection.
			if suffix == "-shm" {
				continue
			}
			cleanup()
			return "", nil, err
		}
		sidecarTempPath := tempPath + suffix
		if err := os.WriteFile(sidecarTempPath, sidecarData, 0o600); err != nil {
			if suffix == "-shm" {
				continue
			}
			cleanup()
			return "", nil, err
		}
	}

	return tempPath, cleanup, nil
}

func formatVisitTime(mode browserTimeMode, raw int64) string {
	if raw <= 0 {
		return ""
	}

	switch mode {
	case chromiumTimeMode:
		unixSeconds := raw/1_000_000 - chromeEpochDiffSeconds
		if unixSeconds <= 0 {
			return ""
		}
		return time.Unix(unixSeconds, 0).UTC().Format(time.RFC3339)
	case firefoxTimeMode:
		unixSeconds := raw / 1_000_000
		if unixSeconds <= 0 {
			return ""
		}
		return time.Unix(unixSeconds, 0).UTC().Format(time.RFC3339)
	default:
		return ""
	}
}
