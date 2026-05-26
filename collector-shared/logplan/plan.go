package logplan

type Mode string

const (
	ModeFull               Mode = "full"
	ModeWindow             Mode = "window"
	ModeWindowWithBackfill Mode = "window_with_backfill"
)

type SourceStatus string

const (
	SourceAvailable        SourceStatus = "available"
	SourceMissing          SourceStatus = "missing"
	SourceEmpty            SourceStatus = "empty"
	SourcePermissionDenied SourceStatus = "permission_denied"
	SourceError            SourceStatus = "error"
)

const (
	ReasonWithinBudget  = "within_budget"
	ReasonExceedsBudget = "exceeds_budget"
	ReasonNoSources     = "no_sources"
)

type Thresholds struct {
	MaxFullBytes  int64 `json:"maxFullBytes,omitempty"`
	MaxFullEvents int64 `json:"maxFullEvents,omitempty"`
}

type SourceEstimate struct {
	Path       string       `json:"path"`
	SizeBytes  int64        `json:"sizeBytes,omitempty"`
	EventCount int64        `json:"eventCount,omitempty"`
	Status     SourceStatus `json:"status"`
	Reason     string       `json:"reason,omitempty"`
}

type BackfillPolicy struct {
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason,omitempty"`
}

type Request struct {
	Domain     string           `json:"domain"`
	Sources    []SourceEstimate `json:"sources"`
	Thresholds Thresholds       `json:"thresholds"`
	Backfill   BackfillPolicy   `json:"backfill,omitempty"`
}

type Plan struct {
	Domain      string           `json:"domain"`
	Mode        Mode             `json:"mode"`
	Reason      string           `json:"reason"`
	TotalBytes  int64            `json:"totalBytes"`
	TotalEvents int64            `json:"totalEvents"`
	Thresholds  Thresholds       `json:"thresholds"`
	Sources     []SourceEstimate `json:"sources"`
	Backfill    BackfillPolicy   `json:"backfill,omitempty"`
}

func Decide(request Request) Plan {
	plan := Plan{
		Domain:     request.Domain,
		Thresholds: request.Thresholds,
		Sources:    append([]SourceEstimate(nil), request.Sources...),
		Backfill:   request.Backfill,
	}
	if len(request.Sources) == 0 {
		plan.Mode = ModeWindow
		plan.Reason = ReasonNoSources
		return plan
	}
	for _, source := range request.Sources {
		if source.Status != SourceAvailable && source.Status != SourceEmpty {
			continue
		}
		plan.TotalBytes += source.SizeBytes
		plan.TotalEvents += source.EventCount
	}
	if withinBudget(plan.TotalBytes, plan.TotalEvents, request.Thresholds) {
		plan.Mode = ModeFull
		plan.Reason = ReasonWithinBudget
		return plan
	}
	plan.Reason = ReasonExceedsBudget
	if request.Backfill.Enabled {
		plan.Mode = ModeWindowWithBackfill
		return plan
	}
	plan.Mode = ModeWindow
	return plan
}

func withinBudget(totalBytes int64, totalEvents int64, thresholds Thresholds) bool {
	if thresholds.MaxFullBytes > 0 && totalBytes > thresholds.MaxFullBytes {
		return false
	}
	if thresholds.MaxFullEvents > 0 && totalEvents > thresholds.MaxFullEvents {
		return false
	}
	return true
}
