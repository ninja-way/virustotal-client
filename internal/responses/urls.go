package responses

import "fmt"

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

// Report is response that contains url check info
type Report struct {
	ScanID       string `json:"scan_id"`
	URL          string `json:"url"`
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

// String return report in readable format
func (r Report) String() string {
	report := fmt.Sprintf("[REPORT] URL: %s DATE: %s\n", r.URL, r.ScanDate)
	report += fmt.Sprintf("\t\t    CHECK COUNT: %d \t CONCLUSION: ", r.Total)

	if r.Positives == 0 {
		report += "NO VIRUSES\n"
		return report
	}

	report += fmt.Sprintf("VIRUSES DETECTED BY !!!%d!!! RESOURCES\n", r.Positives)
	report += "\t\t    RESOURCES:\n"

	for resource, conclusion := range r.Scans {
		if conclusion.Detected {
			report += fmt.Sprintf("%s: %s\n", resource, conclusion.Result)
		}
	}

	return report
}
