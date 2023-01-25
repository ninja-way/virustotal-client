package client

import (
	"encoding/json"
	"fmt"
	"github.com/ninja-way/virustotal-client/internal/responses"
	"io"
	"net/http"
	"strings"
)

// TODO: decompose requests
// TODO: get request: add context to cancel the request if the id is invalid

func (c Client) postUrl(url string) (responses.Scan, error) {
	requestUrl := c.apiUrl + "/url/scan"

	payload := strings.NewReader(fmt.Sprintf("apikey=%s&url=%s", c.apiKey, url))

	resp, err := c.client.Post(requestUrl, "application/x-www-form-urlencoded", payload)
	if err != nil {
		return responses.Scan{}, err
	}
	defer resp.Body.Close()

	// return error if status not 200
	if resp.StatusCode != http.StatusOK {
		return responses.Scan{}, fmt.Errorf("[ERROR] %s %s %s", resp.Request.Method, resp.Status, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return responses.Scan{}, err
	}

	var scanResponse responses.Scan
	err = json.Unmarshal(body, &scanResponse)
	if err != nil {
		return responses.Scan{}, err
	}

	// if the response is different from successful
	if scanResponse.ResponseCode != responses.OK {
		return responses.Scan{}, fmt.Errorf("[ERROR] %s", scanResponse.VerboseMsg)
	}

	return scanResponse, nil
}

func (c Client) getUrlReport(scanID string) (responses.Report, error) {
	requestUrl := c.apiUrl + "/url/report"

	payload := fmt.Sprintf("?apikey=%s&resource=%s", c.apiKey, scanID)

	resp, err := c.client.Get(requestUrl + payload)
	if err != nil {
		return responses.Report{}, err
	}
	defer resp.Body.Close()

	// return error if status not 200
	if resp.StatusCode != http.StatusOK {
		return responses.Report{}, fmt.Errorf("[ERROR] %s %s %s",
			resp.Request.Method, resp.Status, resp.Request.URL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return responses.Report{}, err
	}

	fmt.Println(string(body))

	var reportResponse responses.Report
	err = json.Unmarshal(body, &reportResponse)
	if err != nil {
		return responses.Report{}, err
	}

	return reportResponse, nil
}
