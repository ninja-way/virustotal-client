package responses

type Scan struct {
	ResponseCode int    `json:"response_code"`
	ScanDate     string `json:"scan_date,omitempty"`
	ScanID       string `json:"scan_id"`
	VerboseMsg   string `json:"verbose_msg"`
}

type Report struct {
	ScanID       string `json:"scan_id"`
	ResponseCode int    `json:"response_code"`
	ScanDate     string `json:"scan_date,omitempty"`
	VerboseMsg   string `json:"verbose_msg"`

	Positives int                 `json:"positives"`
	Total     int                 `json:"total"`
	Scans     map[string]Resource `json:"scans"`
}

type Resource struct {
	Detected bool   `json:"detected"`
	Result   string `json:"result"`
}
