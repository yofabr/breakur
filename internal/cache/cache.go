// Package cache provides an optional cache for short_code -> destination URL
// lookups. Redis is a pure optimization: when it is unavailable the router
// falls back to PostgreSQL, so implementations must never be required to serve
// a request.
package cache

import "context"

// Lookup is the result of a cache read.
type Lookup int

const (
	// LookupMiss means the code is not cached: consult Postgres.
	LookupMiss Lookup = iota
	// LookupHit means destination is valid.
	LookupHit
	// LookupNegative means the code is cached as "does not exist": return 404.
	LookupNegative
)

// LinkCache stores short_code -> destination URL mappings.
type LinkCache interface {
	Get(ctx context.Context, code string) (destination string, result Lookup, err error)
	Set(ctx context.Context, code, destination string) error
	SetMissing(ctx context.Context, code string) error
	Delete(ctx context.Context, code string) error
	Close() error
}
