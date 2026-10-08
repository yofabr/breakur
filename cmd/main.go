package main

import (
	"log"
	"os"

	"breakur/internal/router"
)

// addr is the listen address, override with the PORT environment variable.
func addr() string {
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":8080"
}

func main() {
	r := router.New()

	log.Printf("breakur listening on %s", addr())
	if err := r.Run(addr()); err != nil {
		log.Fatal(err)
	}
}
