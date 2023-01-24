package client

import (
	"errors"
	"github.com/ninja-way/virustotal-client/internal/responses"
	"net/http"
)

type Client struct {
	apiKey  string
	client  *http.Client
	baseUrl string
}

func NewClient(APIkey string) (*Client, error) {
	if APIkey == "" {
		return nil, errors.New("api key not specified")
	}
	return &Client{
		apiKey:  APIkey,
		client:  &http.Client{},
		baseUrl: "https://www.virustotal.com/vtapi/v2",
	}, nil
}

func (c Client) ScanUrl(url string) (responses.Scan, error) {
	return c.postUrl(url)
}
