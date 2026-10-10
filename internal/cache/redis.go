package cache

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	linkKeyPrefix    = "breakur:link:v1:"
	missingKeyPrefix = "breakur:missing:v1:"
)

// Config configures the Redis-backed LinkCache.
type Config struct {
	Addr        string
	Password    string
	DB          int
	TTL         time.Duration // sliding TTL for positive entries
	NegativeTTL time.Duration // fixed TTL for negative entries
	Timeout     time.Duration // per-operation timeout
}

// Redis is the Redis-backed LinkCache. Every operation is bounded by a short
// timeout so a slow cache can never stall a redirect.
type Redis struct {
	client      *redis.Client
	ttl         time.Duration
	negativeTTL time.Duration
	timeout     time.Duration
}

// NewRedis connects to Redis and verifies the connection with a ping. A failed
// ping returns an error and closes the client; callers decide how to degrade.
func NewRedis(ctx context.Context, cfg Config) (*Redis, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  cfg.Timeout,
		ReadTimeout:  cfg.Timeout,
		WriteTimeout: cfg.Timeout,
	})
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	return &Redis{client: client, ttl: cfg.TTL, negativeTTL: cfg.NegativeTTL, timeout: cfg.Timeout}, nil
}

// NewRedisOrNop returns a working Redis cache when cfg.Addr is set and
// reachable, and a Nop cache otherwise. It never returns an error, so callers
// can enable caching without risking startup.
func NewRedisOrNop(ctx context.Context, cfg Config) LinkCache {
	if cfg.Addr == "" {
		return Nop{}
	}
	r, err := NewRedis(ctx, cfg)
	if err != nil {
		return Nop{}
	}
	return r
}

// Get returns the cached destination for code. A hit refreshes the sliding TTL.
func (r *Redis) Get(ctx context.Context, code string) (string, Lookup, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// GETEX atomically returns the value and refreshes the sliding TTL, which
	// keeps frequently requested links resident.
	value, err := r.client.GetEx(ctx, linkKeyPrefix+code, r.ttl).Result()
	if err == nil {
		return value, LookupHit, nil
	}
	if !errors.Is(err, redis.Nil) {
		return "", LookupMiss, err
	}

	exists, err := r.client.Exists(ctx, missingKeyPrefix+code).Result()
	if err != nil {
		return "", LookupMiss, err
	}
	if exists > 0 {
		return "", LookupNegative, nil
	}
	return "", LookupMiss, nil
}

// Set caches a destination, clearing any stale negative entry for the code.
func (r *Redis) Set(ctx context.Context, code, destination string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	pipe := r.client.Pipeline()
	pipe.Del(ctx, missingKeyPrefix+code)
	pipe.Set(ctx, linkKeyPrefix+code, destination, r.ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// SetMissing records a short-lived negative entry for an unknown code.
func (r *Redis) SetMissing(ctx context.Context, code string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.client.Set(ctx, missingKeyPrefix+code, "1", r.negativeTTL).Err()
}

// Delete removes both the positive and negative entries for a code so every
// instance stops serving it.
func (r *Redis) Delete(ctx context.Context, code string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.client.Del(ctx, linkKeyPrefix+code, missingKeyPrefix+code).Err()
}

// Close releases the underlying Redis client.
func (r *Redis) Close() error { return r.client.Close() }
