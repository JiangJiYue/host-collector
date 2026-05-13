package collector

import (
	"context"
	"strconv"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

type browserDefinitionProvider func() []browserDefinition
type browserProfileDiscoverer func(browserDefinition) []string
type browserProfileQuery func(context.Context, browserDefinition, string) ([]historyRow, error)

// BrowserHistoryCollector 浏览器历史采集器
type BrowserHistoryCollector struct {
	definitions      browserDefinitionProvider
	discoverProfiles browserProfileDiscoverer
	queryProfile     browserProfileQuery
}

func NewBrowserHistoryCollector() *BrowserHistoryCollector {
	return &BrowserHistoryCollector{}
}

func (bhc *BrowserHistoryCollector) Name() string {
	return "browser_history"
}

// BrowserHistoryCollectionResult 浏览器历史采集结果
type BrowserHistoryCollectionResult struct {
	Entries []models.BrowserHistoryEntry `json:"entries"`
	Total   int                          `json:"total"`
}

type browserHistoryVisit struct {
	Browser            string
	URL                string
	Title              string
	RawVisitTime       int64
	FormattedVisitTime string
}

func dedupeBrowserHistoryVisits(visits []browserHistoryVisit) []browserHistoryVisit {
	seen := make(map[string]struct{}, len(visits))
	result := make([]browserHistoryVisit, 0, len(visits))
	for _, visit := range visits {
		key := visit.Browser + "\x00" + visit.URL + "\x00" + visit.Title + "\x00" + strconv.FormatInt(visit.RawVisitTime, 10)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, visit)
	}
	return result
}

func (bhc *BrowserHistoryCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info("Collector", "开始采集浏览器历史...")
	entries := bhc.collectBrowserHistory(ctx)

	utils.Info("Collector", "浏览器历史采集完成: %d条记录", len(entries))

	return &BrowserHistoryCollectionResult{
		Entries: entries,
		Total:   len(entries),
	}, nil
}
