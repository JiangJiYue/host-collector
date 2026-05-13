package scanner

import (
	"context"

	"collector-shared/authpolicy"
	"windows-host-collector/models"
)

// HostScanner is the single public policy-driven host collection entrypoint.
type HostScanner struct {
	scanner *QuickScanner
}

func NewHostScanner() *HostScanner {
	return &HostScanner{scanner: NewQuickScanner()}
}

func (hs *HostScanner) WithProgress(fn func(ScanProgress)) *HostScanner {
	hs.scanner = hs.scanner.WithProgress(fn)
	return hs
}

func (hs *HostScanner) WithScope(scope []string) *HostScanner {
	hs.scanner = hs.scanner.WithScope(scope)
	return hs
}

func (hs *HostScanner) WithPolicy(policy *authpolicy.Policy) *HostScanner {
	hs.scanner = hs.scanner.WithPolicy(policy)
	return hs
}

func (hs *HostScanner) shouldRunStage(stageKey string) bool {
	return hs.scanner.shouldRunStage(stageKey)
}

func (hs *HostScanner) stageRowsSnapshot() map[string]models.ScanStageSummary {
	return hs.scanner.stageRows
}

func (hs *HostScanner) Scan(ctx context.Context) (*models.ScanEnvelope, error) {
	return hs.scanner.Scan(ctx)
}
