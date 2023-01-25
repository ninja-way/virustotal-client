package client

import (
	"errors"
	"github.com/ninja-way/virustotal-client/internal/responses"
	"net/http"
	"time"
)

// Default settings
const (
	apiKeyNotSpecified string = "api key not specified"
	virusTotalAPIUrl   string = "https://www.virustotal.com/vtapi/v2"
	requestTimeout            = 5 * time.Second
)

// Client is custom VirusTotal client containing api link and api key
type Client struct {
	apiKey string
	client *http.Client
	apiUrl string
}

// NewClient return VirusTotal client with passed API key and default settings
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

// ScanUrl send url to checking and waits until the report returns
func (c Client) ScanUrl(url string) (responses.Report, error) {
	scanResp, err := c.postUrl(url)
	if err != nil {
		return responses.Report{}, err
	}

	// wait for url to be checked
	time.Sleep(requestTimeout)
	return c.getUrlReport(scanResp.ScanID)
}
