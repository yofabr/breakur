package main

import (
	"context"
	"log"
	"os"

	"breakur/internal/db"
	"breakur/internal/router"
)

// addr is the listen address, override with the PORT environment variable.
func addr() string {
	if port := os.Getenv("PORT"); port != "" {
		return ":" + port
	}
	return ":8080"
}

// databaseURL is the Postgres DSN, override with the DATABASE_URL environment
// variable; it defaults to the local dev database from compose.yaml.
func databaseURL() string {
	if u := os.Getenv("DATABASE_URL"); u != "" {
		return u
	}
	return "postgres://breakur:breakur@localhost:5432/breakur?sslmode=disable"
}

func main() {
	ctx := context.Background()

	// Connect to Postgres and bring the schema up to date before serving.
	conn, err := db.Open(ctx, databaseURL())
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer conn.Close()

	if err := db.Migrate(conn); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	r := router.New(conn)

	log.Printf("breakur listening on %s", addr())
	if err := r.Run(addr()); err != nil {
		log.Fatal(err)
	}
}
