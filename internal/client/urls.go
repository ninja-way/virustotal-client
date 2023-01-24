package client

import (
	"encoding/json"
	"fmt"
	"github.com/ninja-way/virustotal-client/internal/responses"
	"io"
	"net/http"
	"strings"
)

func (c Client) postUrl(url string) (responses.Scan, error) {
	requestUrl := c.baseUrl + "/url/scan"

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

	return scanResponse, err
}
