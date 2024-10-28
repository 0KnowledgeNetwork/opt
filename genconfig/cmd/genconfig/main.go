package main

import (
	"log"

	"github.com/0KnowledgeNetwork/opt/genconfig"
)

func main() {
	gi := genconfig.ParseFlags()
	if err := genconfig.Genconfig(gi); err != nil {
		log.Fatalf("Error generating config: %v", err)
	}
}
