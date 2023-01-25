package responses

// Response codes
const (
	ResourceStillAnalyzed = iota - 2
	InvalidURL
	ResourceNotExist
	OK
)

// Scan is response received at sending the url for checking
type Scan struct {
	ResponseCode int    `json:"response_code"`
	ScanDate     string `json:"scan_date"`
	ScanID       string `json:"scan_id"`
	VerboseMsg   string `json:"verbose_msg"`
}

// Report is response received at getting url check info
type Report struct {
	ScanID       string `json:"scan_id"`
	ResponseCode int    `json:"response_code"`
	ScanDate     string `json:"scan_date"`
	VerboseMsg   string `json:"verbose_msg"`

	Positives int                 `json:"positives"`
	Total     int                 `json:"total"`
	Scans     map[string]Resource `json:"scans"`
}

// Resource contains the scan conclusion of each antivirus resources
type Resource struct {
	Detected bool   `json:"detected"`
	Result   string `json:"result"`
}
