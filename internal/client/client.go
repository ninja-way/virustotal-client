package client

import (
	"errors"
	"github.com/ninja-way/virustotal-client/internal/responses"
	"net/http"
)

const (
	apiKeyNotSpecified string = "api key not specified"
	virusTotalAPIUrl   string = "https://www.virustotal.com/vtapi/v2"
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

	return c.getUrlReport(scanResp.ScanID)
}
