package authpolicy

type Policy struct {
	LogWindowDays int      `json:"log_window_days"`
	ScanScope     []string `json:"scan_scope"`
}
