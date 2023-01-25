package client

import (
	"encoding/json"
	"fmt"
	"github.com/ninja-way/virustotal-client/internal/responses"
	"io"
	"net/http"
	"strings"
	"time"
)

// TODO: decompose requests

func (c Client) postUrl(url string) (responses.Scan, error) {
	requestUrl := c.apiUrl + "/url/scan"

	payload := strings.NewReader(fmt.Sprintf("apikey=%s&url=%s", c.apiKey, url))

	resp, err := c.client.Post(requestUrl, "application/x-www-form-urlencoded", payload)
	if err != nil {
		return responses.Scan{}, err
	}
	defer resp.Body.Close()

	// return error if virustotal request rate limit exceeded (4/minute, 500/day)
	if resp.StatusCode == http.StatusNoContent {
		return responses.Scan{}, fmt.Errorf("[ERROR] %s %s", resp.Request.Method, "request rate limit exceeded")
	}

	// return error if status not 200
	if resp.StatusCode != http.StatusOK {
		return responses.Scan{}, fmt.Errorf("[ERROR] %s %s %s", resp.Request.Method, resp.Status, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return responses.Scan{}, err
	}

	var scan responses.Scan
	err = json.Unmarshal(body, &scan)
	if err != nil {
		return responses.Scan{}, err
	}

	// if the response is different from successful
	if scan.ResponseCode != responses.OK {
		return responses.Scan{}, fmt.Errorf("[ERROR] %s", scan.VerboseMsg)
	}

	return scan, nil
}

func (c Client) getUrlReport(scanID string) (responses.Report, error) {
	requestUrl := c.apiUrl + "/url/report"

	payload := fmt.Sprintf("?apikey=%s&resource=%s", c.apiKey, scanID)

	resp, err := c.client.Get(requestUrl + payload)
	if err != nil {
		return responses.Report{}, err
	}
	defer resp.Body.Close()

	// return error if virustotal request rate limit exceeded (4/minute, 500/day)
	if resp.StatusCode == http.StatusNoContent {
		return responses.Report{}, fmt.Errorf("[ERROR] %s %s", resp.Request.Method, "request rate limit exceeded")
	}

	// return error if status not 200
	if resp.StatusCode != http.StatusOK {
		return responses.Report{}, fmt.Errorf("[ERROR] %s %s %s",
			resp.Request.Method, resp.Status, resp.Request.URL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return responses.Report{}, err
	}

	var report responses.Report
	err = json.Unmarshal(body, &report)
	if err != nil {
		return responses.Report{}, err
	}

	// if the response is different from successful
	if report.ResponseCode != responses.OK || report.Total == 0 {
		fmt.Println("not ok", report.VerboseMsg)
		time.Sleep(requestTimeout)
		return c.getUrlReport(scanID)
	}

	return report, nil
}
