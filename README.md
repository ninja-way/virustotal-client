# virustotal-client
Simple API client for virus detection

```
go get -u github.com/ninja-way/virustotal-client
```

```go
// New return VirusTotal client
func New(APIkey string) (*Client, error)

// Client is custom VirusTotal client containing api link and api key
type Client struct
    // ScanUrl send url to checking and waits until the report returns
    ScanUrl(url string) (*Report, error)

// Report is response that contains url check info
type Report struct
    // String return report in readable format
    String() string
```

***Example: [cmd/main.go](./cmd/main.go)***