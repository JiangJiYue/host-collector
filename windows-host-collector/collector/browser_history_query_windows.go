//go:build windows

package collector

type historyRow struct {
	URL       string
	Title     string
	VisitTime int64
}

const chromiumHistoryQuery = `
SELECT
    urls.url,
    COALESCE(urls.title, ''),
    visits.visit_time
FROM visits
JOIN urls ON urls.id = visits.url
WHERE urls.url IS NOT NULL
  AND urls.url != ''
  AND visits.visit_time > 0
ORDER BY visits.visit_time DESC
LIMIT ?;
`

const firefoxHistoryQuery = `
SELECT
    moz_places.url,
    COALESCE(moz_places.title, ''),
    moz_historyvisits.visit_date
FROM moz_historyvisits
JOIN moz_places ON moz_places.id = moz_historyvisits.place_id
WHERE moz_places.url IS NOT NULL
  AND moz_places.url != ''
  AND moz_historyvisits.visit_date > 0
ORDER BY moz_historyvisits.visit_date DESC
LIMIT ?;
`
