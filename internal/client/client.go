package client

import (
	"fmt"
	"github.com/ninja-way/virustotal-client/internal/responses"
	"log"
	"net/http"
	"time"
)

// Default settings
const (
	virusTotalAPIUrl = "https://www.virustotal.com/vtapi/v2"
	requestTimeout   = 5 * time.Second

	okMsg              = "[OK]"
	errorMsg           = "[ERROR]"
	successSubmit      = "successfully submitted for checking, wait for the report!"
	apiKeyNotSpecified = "api key not specified"
	urlNotSpecified    = "url not specified"
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
		return nil, fmt.Errorf("%s %s", errorMsg, apiKeyNotSpecified)
	}
	return &Client{
		apiKey: APIkey,
		client: &http.Client{},
		apiUrl: virusTotalAPIUrl,
	}, nil
}

// ScanUrl send url to checking and waits until the report returns
func (c Client) ScanUrl(url string) (*responses.Report, error) {
	if url == "" {
		return nil, fmt.Errorf("%s %s", errorMsg, urlNotSpecified)
	}

	scanResp, err := c.postUrl(url)
	if err != nil {
		return &responses.Report{}, fmt.Errorf("%s %s", errorMsg, err.Error())
	}

	log.Printf("%s %s %s", okMsg, url, successSubmit)

	// wait for url to be checked and get report
	time.Sleep(requestTimeout)
	report, err := c.getUrlReport(scanResp.ScanID)
	if err != nil {
		return &responses.Report{}, fmt.Errorf("%s %s", errorMsg, err.Error())
	}

	return report, nil
}
