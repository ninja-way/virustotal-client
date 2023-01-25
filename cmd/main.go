package main

import (
	"flag"
	"github.com/ninja-way/virustotal-client/pkg/virustotal"
	"log"
)

var (
	APIkey = flag.String("k", "", "API key for authorization")
	URL    = flag.String("u", "", "URL to check")
)

func main() {
	flag.Parse()

	// Init client with API key
	vt, err := virustotal.New(*APIkey)
	if err != nil {
		log.Fatal(err)
	}

	// Send url to checking
	report, err := vt.ScanUrl(*URL)
	if err != nil {
		log.Fatal(err)
	}

	// Print readable report
	log.Println(report.String())
}
