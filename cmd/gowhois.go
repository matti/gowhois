package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/matti/gowhois"
)

func main() {
	flag.Parse()

	switch flag.Arg(0) {
	case "ip":
		ipResult := gowhois.QueryIp(flag.Arg(1))
		sJSON, err := json.MarshalIndent(ipResult, "", "  ")
		if err != nil {
			log.Panicln(err)
		}

		fmt.Println(string(sJSON))
	default:
		log.Println("wat?")
	}
}
