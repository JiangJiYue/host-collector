//go:build !windows

package collector

type browserProfileMode string
type browserTimeMode string

type browserDefinition struct {
	Name              string
	RootPath          string
	HistoryFile       string
	ProfileMode       browserProfileMode
	TimeMode          browserTimeMode
	Query             string
	MaxRowsPerProfile int
}

type historyRow struct {
	URL       string
	Title     string
	VisitTime int64
}
