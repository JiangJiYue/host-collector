//go:build windows

package collector

import (
	"context"
	"sort"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

func (bhc *BrowserHistoryCollector) collectBrowserHistory(ctx context.Context) []models.BrowserHistoryEntry {
	definitions := bhc.definitions
	if definitions == nil {
		definitions = browserDefinitions
	}
	discoverProfiles := bhc.discoverProfiles
	if discoverProfiles == nil {
		discoverProfiles = defaultDiscoverProfiles
	}
	queryProfile := bhc.queryProfile
	if queryProfile == nil {
		queryProfile = queryBrowserHistory
	}

	visits := make([]browserHistoryVisit, 0)
	for _, definition := range definitions() {
		profiles := discoverProfiles(definition)
		for _, profile := range profiles {
			rows, err := queryProfile(ctx, definition, profile)
			if err != nil {
				utils.LogError("Collector", "读取 %s 配置文件 %s 历史失败: %v", definition.Name, profile, err)
				continue
			}
			for _, row := range rows {
				visits = append(visits, browserHistoryVisit{
					URL:                row.URL,
					Title:              row.Title,
					RawVisitTime:       row.VisitTime,
					FormattedVisitTime: formatVisitTime(definition.TimeMode, row.VisitTime),
					Browser:            definition.Name,
				})
			}
		}
	}

	visits = dedupeBrowserHistoryVisits(visits)
	entries := make([]models.BrowserHistoryEntry, 0, len(visits))
	for _, visit := range visits {
		entries = append(entries, models.BrowserHistoryEntry{
			URL:       visit.URL,
			Title:     visit.Title,
			VisitTime: visit.FormattedVisitTime,
			Browser:   visit.Browser,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].VisitTime > entries[j].VisitTime
	})
	return entries
}

func defaultDiscoverProfiles(def browserDefinition) []string {
	switch def.ProfileMode {
	case chromiumProfileMode:
		return discoverChromiumProfiles(def.RootPath, def.HistoryFile)
	case firefoxProfileMode:
		return discoverFirefoxProfiles(def.RootPath, def.HistoryFile)
	default:
		return nil
	}
}
