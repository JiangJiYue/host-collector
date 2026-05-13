//go:build windows

package collector

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestCollectBrowserHistoryContinuesOnBrowserFailure(t *testing.T) {
	collector := BrowserHistoryCollector{
		definitions: func() []browserDefinition {
			return []browserDefinition{
				{Name: "Chrome", RootPath: "broken", HistoryFile: "History", ProfileMode: chromiumProfileMode, TimeMode: chromiumTimeMode},
				{Name: "Firefox", RootPath: "ok", HistoryFile: "places.sqlite", ProfileMode: firefoxProfileMode, TimeMode: firefoxTimeMode},
			}
		},
		discoverProfiles: func(def browserDefinition) []string {
			if def.Name == "Firefox" {
				return []string{"profile"}
			}
			return []string{"broken-profile"}
		},
		queryProfile: func(ctx context.Context, def browserDefinition, profile string) ([]historyRow, error) {
			if def.Name == "Chrome" {
				return nil, errors.New("boom")
			}
			return []historyRow{{URL: "https://example.com", Title: "Example", VisitTime: 1745193600000000}}, nil
		},
	}

	got := collector.collectBrowserHistory(context.Background())
	if len(got) != 1 {
		t.Fatalf("expected 1 entry after partial failure, got %d: %#v", len(got), got)
	}
	if got[0].Browser != "Firefox" {
		t.Fatalf("expected surviving firefox entry, got %#v", got[0])
	}
}

func TestCollectBrowserHistoryKeepsDistinctSameSecondVisits(t *testing.T) {
	collector := BrowserHistoryCollector{
		definitions: func() []browserDefinition {
			return []browserDefinition{
				{Name: "Firefox", RootPath: "ok", HistoryFile: "places.sqlite", ProfileMode: firefoxProfileMode, TimeMode: firefoxTimeMode},
			}
		},
		discoverProfiles: func(def browserDefinition) []string {
			return []string{"profile"}
		},
		queryProfile: func(ctx context.Context, def browserDefinition, profile string) ([]historyRow, error) {
			return []historyRow{
				{URL: "https://example.com", Title: "Example", VisitTime: 1745193600000000},
				{URL: "https://example.com", Title: "Example", VisitTime: 1745193600999999},
			}, nil
		},
	}

	got := collector.collectBrowserHistory(context.Background())
	if len(got) != 2 {
		t.Fatalf("expected 2 entries for distinct visits in same second, got %d: %#v", len(got), got)
	}
	for i, entry := range got {
		if entry.VisitTime != "2025-04-21T00:00:00Z" {
			t.Fatalf("entry %d has unexpected visit time %q", i, entry.VisitTime)
		}
	}
}

func TestQueryBrowserHistoryChromium(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "History")
	createChromiumHistoryFixture(t, dbPath)

	def := browserDefinition{
		Name:              "Chrome",
		HistoryFile:       "History",
		TimeMode:          chromiumTimeMode,
		Query:             chromiumHistoryQuery,
		MaxRowsPerProfile: 10,
	}

	rows, err := queryBrowserHistory(context.Background(), def, filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("query chromium history: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 chromium row, got %d", len(rows))
	}
	if rows[0].URL != "https://example.com" {
		t.Fatalf("unexpected chromium URL: %q", rows[0].URL)
	}
}

func TestCopyHistoryDatabaseCopiesMainAndSidecars(t *testing.T) {
	profileDir := t.TempDir()
	sourcePath := filepath.Join(profileDir, "History")
	mainData := []byte("main-db")
	walData := []byte("wal-data")
	shmData := []byte("shm-data")

	if err := os.WriteFile(sourcePath, mainData, 0o600); err != nil {
		t.Fatalf("write main db: %v", err)
	}
	if err := os.WriteFile(sourcePath+"-wal", walData, 0o600); err != nil {
		t.Fatalf("write wal: %v", err)
	}
	if err := os.WriteFile(sourcePath+"-shm", shmData, 0o600); err != nil {
		t.Fatalf("write shm: %v", err)
	}

	tempPath, cleanup, err := copyHistoryDatabase(sourcePath)
	if err != nil {
		t.Fatalf("copy history db: %v", err)
	}

	checkFileData(t, tempPath, mainData)
	checkFileData(t, tempPath+"-wal", walData)
	checkFileData(t, tempPath+"-shm", shmData)

	tempDir := filepath.Dir(tempPath)
	cleanup()
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Fatalf("expected temp dir %q to be removed, stat err=%v", tempDir, err)
	}
}

func checkFileData(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("unexpected contents for %s: got %q want %q", path, string(got), string(want))
	}
}

func TestQueryBrowserHistoryFirefox(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "places.sqlite")
	createFirefoxHistoryFixture(t, dbPath)

	def := browserDefinition{
		Name:              "Firefox",
		HistoryFile:       "places.sqlite",
		TimeMode:          firefoxTimeMode,
		Query:             firefoxHistoryQuery,
		MaxRowsPerProfile: 10,
	}

	rows, err := queryBrowserHistory(context.Background(), def, filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("query firefox history: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 firefox row, got %d", len(rows))
	}
	if rows[0].Title != "Example" {
		t.Fatalf("unexpected firefox title: %q", rows[0].Title)
	}
}

func createChromiumHistoryFixture(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open chromium fixture db: %v", err)
	}
	defer db.Close()

	statements := []string{
		`CREATE TABLE urls (id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR);`,
		`CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);`,
		`INSERT INTO urls (id, url, title) VALUES (1, 'https://example.com', 'Example');`,
		`INSERT INTO visits (id, url, visit_time) VALUES (1, 1, 13388832000000000);`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("exec chromium fixture statement %q: %v", statement, err)
		}
	}
}

func createFirefoxHistoryFixture(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open firefox fixture db: %v", err)
	}
	defer db.Close()

	statements := []string{
		`CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT);`,
		`CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER);`,
		`INSERT INTO moz_places (id, url, title) VALUES (1, 'https://example.com', 'Example');`,
		`INSERT INTO moz_historyvisits (id, place_id, visit_date) VALUES (1, 1, 1745193600000000);`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("exec firefox fixture statement %q: %v", statement, err)
		}
	}
}
