package virustotal

import (
	"github.com/ninja-way/virustotal-client/internal/client"
)

// New return VirusTotal client
func New(APIkey string) (*client.Client, error) {
	return client.NewClient(APIkey)
}
