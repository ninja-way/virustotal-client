package main

import (
	"flag"
	"fmt"
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

	fmt.Println(vt.ScanUrl("youtube.com"))
}
