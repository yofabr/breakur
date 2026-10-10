package main

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"breakur/internal/cache"
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

// redisAddr returns the configured Redis address, or "" when caching is
// disabled. An empty value means: run PostgreSQL-only.
func redisAddr() string {
	return strings.TrimSpace(os.Getenv("REDIS_ADDR"))
}

// envDuration parses a duration environment variable, falling back to a default
// (and warning) when it is missing or malformed.
func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		log.Printf("%s=%q is not a duration; using %s", key, v, fallback)
	}
	return fallback
}

// envInt parses an integer environment variable, falling back to a default
// (and warning) when it is malformed.
func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		log.Printf("%s=%q is not a number; using %d", key, v, fallback)
	}
	return fallback
}

// buildCache returns a PostgreSQL-only (no-op) cache unless Redis is explicitly
// configured AND reachable. It never returns an error and never stops startup,
// so a missing or unreachable Redis can only degrade to PostgreSQL.
func buildCache(ctx context.Context) cache.LinkCache {
	addr := redisAddr()
	if addr == "" {
		log.Print("REDIS_ADDR is not set; running without a cache (PostgreSQL only).")
		return cache.Nop{}
	}

	cfg := cache.Config{
		Addr:        addr,
		Password:    os.Getenv("REDIS_PASSWORD"),
		DB:          envInt("REDIS_DB", 0),
		TTL:         envDuration("LINK_CACHE_TTL", time.Hour),
		NegativeTTL: envDuration("LINK_CACHE_NEGATIVE_TTL", time.Minute),
		Timeout:     envDuration("LINK_CACHE_TIMEOUT", 100*time.Millisecond),
	}

	linkCache := cache.NewRedisOrNop(ctx, cfg)
	if _, ok := linkCache.(cache.Nop); ok {
		log.Printf("redis unavailable at %s; running without a cache (PostgreSQL only)", addr)
		return linkCache
	}
	log.Printf("redis cache enabled at %s", addr)
	return linkCache
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

	// Redis is optional: with REDIS_ADDR unset (or Redis unreachable) this is a
	// no-op cache and every request is served from PostgreSQL.
	linkCache := buildCache(ctx)
	defer linkCache.Close()

	r := router.New(conn, linkCache)

	log.Printf("breakur listening on %s", addr())
	if err := r.Run(addr()); err != nil {
		log.Fatal(err)
	}
}
