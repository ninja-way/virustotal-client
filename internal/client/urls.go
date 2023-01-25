package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ninja-way/virustotal-client/internal/responses"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	urlScan   = "/url/scan"
	urlReport = "/url/report"

	paramAPIkey   = "apikey="
	paramURL      = "&url="
	paramResource = "&resource="

	postContentType = "application/x-www-form-urlencoded"

	requestLimitExceeded = "request rate limit exceeded"
)

func (c Client) checkResponseStatus(resp *http.Response) error {
	// return error if VirusTotal request rate limit exceeded (4/minute, 500/day)
	if resp.StatusCode == http.StatusNoContent {
		return fmt.Errorf("%s %s", resp.Request.Method, requestLimitExceeded)
	}
	// return error if status not 200
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s %s", resp.Request.Method, resp.Status, resp.Request.URL)
	}
	return nil
}

// postUrl send url at checking
func (c Client) postUrl(url string) (*responses.Scan, error) {
	requestUrl := c.apiUrl + urlScan
	params := strings.NewReader(paramAPIkey + c.apiKey + paramURL + url)

	// send url
	resp, err := c.client.Post(requestUrl, postContentType, params)
	if err != nil {
		return &responses.Scan{}, err
	}
	defer resp.Body.Close()

	err = c.checkResponseStatus(resp)
	if err != nil {
		return &responses.Scan{}, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &responses.Scan{}, err
	}

	// parse response
	var scan responses.Scan
	err = json.Unmarshal(body, &scan)
	if err != nil {
		return &responses.Scan{}, err
	}

	// if the response not successful
	if scan.ResponseCode != responses.OK {
		return &responses.Scan{}, errors.New(scan.VerboseMsg)
	}

	return &scan, nil
}

// getUrlReport receives url checking report
func (c Client) getUrlReport(scanID string) (*responses.Report, error) {
	requestUrl := c.apiUrl + urlReport
	params := paramAPIkey + c.apiKey + paramResource + scanID

	// get report
	resp, err := c.client.Get(requestUrl + "?" + params)
	if err != nil {
		return &responses.Report{}, err
	}
	defer resp.Body.Close()

	err = c.checkResponseStatus(resp)
	if err != nil {
		return &responses.Report{}, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &responses.Report{}, err
	}

	var report responses.Report
	err = json.Unmarshal(body, &report)
	if err != nil {
		return &responses.Report{}, err
	}

	// if the response not successful or checks not yet passed
	if report.ResponseCode != responses.OK || report.Total == 0 {
		// send a new request after a timeout
		time.Sleep(requestTimeout)
		return c.getUrlReport(scanID)
	}

	return &report, nil
}
