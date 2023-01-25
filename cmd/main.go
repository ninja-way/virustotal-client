package main

import (
	"flag"
	"github.com/ninja-way/virustotal-client/internal/client"
	"log"
)

var APIkey = flag.String("k", "", "API key for authorization")

func main() {
	flag.Parse()
	vt, err := client.NewClient(*APIkey)
	if err != nil {
		log.Fatal(err)
	}

	result, err := vt.ScanUrl("amongus.io")
	if err != nil {
		log.Fatal(err)
	}

	log.Println(result.String())
}
