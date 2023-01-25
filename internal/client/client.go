package client

import (
	"errors"
	"github.com/ninja-way/virustotal-client/internal/responses"
	"net/http"
	"time"
)

const (
	apiKeyNotSpecified string = "api key not specified"
	virusTotalAPIUrl   string = "https://www.virustotal.com/vtapi/v2"
	requestTimeout            = 5 * time.Second
)

type Client struct {
	apiKey string
	client *http.Client
	apiUrl string
}

func NewClient(APIkey string) (*Client, error) {
	if APIkey == "" {
		return nil, errors.New(apiKeyNotSpecified)
	}
	return &Client{
		apiKey: APIkey,
		client: &http.Client{},
		apiUrl: virusTotalAPIUrl,
	}, nil
}

func (c Client) ScanUrl(url string) (responses.Report, error) {
	scanResp, err := c.postUrl(url)
	if err != nil {
		return responses.Report{}, err
	}

	// wait for url to be checked
	time.Sleep(requestTimeout)
	return c.getUrlReport(scanResp.ScanID)
}
