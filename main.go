package main

import (
	"log"

	"github.com/vitalvas/gopass/cmd"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := cmd.Execute(version, commit, date); err != nil {
		log.Fatal(err)
	}

}
