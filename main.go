package main

import (
	"log"

	"github.com/vitalvas/gopass/internal/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		log.Fatal(err)
	}
}
