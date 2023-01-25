package responses

const (
	ResourceStillAnalyzed = iota - 2
	InvalidURL
	ResourceNotExist
	OK
)

type Scan struct {
	ResponseCode int    `json:"response_code"`
	ScanDate     string `json:"scan_date"`
	ScanID       string `json:"scan_id"`
	VerboseMsg   string `json:"verbose_msg"`
}

type Report struct {
	ScanID       string `json:"scan_id"`
	ResponseCode int    `json:"response_code"`
	ScanDate     string `json:"scan_date"`
	VerboseMsg   string `json:"verbose_msg"`

	Positives int                 `json:"positives"`
	Total     int                 `json:"total"`
	Scans     map[string]Resource `json:"scans"`
}

type Resource struct {
	Detected bool   `json:"detected"`
	Result   string `json:"result"`
}
