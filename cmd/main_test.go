package main

import (
	"context"
	"testing"
	"time"

	"breakur/internal/cache"
)

// TestBuildCacheDisabledWithoutRedisAddr proves that with REDIS_ADDR unset the
// app runs PostgreSQL-only: buildCache returns a Nop cache and no connection
// is attempted.
func TestBuildCacheDisabledWithoutRedisAddr(t *testing.T) {
	t.Setenv("REDIS_ADDR", "")
	t.Setenv("LINK_CACHE_TIMEOUT", "10ms")

	c := buildCache(context.Background())
	if _, ok := c.(cache.Nop); !ok {
		t.Fatalf("buildCache with empty REDIS_ADDR = %T, want cache.Nop", c)
	}
	if _, result, err := c.Get(context.Background(), "x"); result != cache.LookupMiss || err != nil {
		t.Fatalf("Nop Get = (%v, %v), want (LookupMiss, nil)", result, err)
	}
}

// TestBuildCacheFallsBackWhenRedisUnreachable proves that a configured but
// unreachable Redis degrades to PostgreSQL instead of failing startup.
func TestBuildCacheFallsBackWhenRedisUnreachable(t *testing.T) {
	t.Setenv("REDIS_ADDR", "127.0.0.1:1") // nothing listens here
	t.Setenv("LINK_CACHE_TIMEOUT", "50ms")

	c := buildCache(context.Background())
	if _, ok := c.(cache.Nop); !ok {
		t.Fatalf("buildCache with unreachable Redis = %T, want cache.Nop", c)
	}
	if _, result, err := c.Get(context.Background(), "x"); result != cache.LookupMiss || err != nil {
		t.Fatalf("fallback Get = (%v, %v), want (LookupMiss, nil)", result, err)
	}
}

// TestEnvDurationParsing covers the env helpers' fallback behaviour.
func TestEnvDurationParsing(t *testing.T) {
	t.Setenv("TEST_DURATION", "5m")
	if got := envDuration("TEST_DURATION", time.Hour); got != 5*time.Minute {
		t.Fatalf("envDuration = %v, want 5m", got)
	}

	t.Setenv("TEST_DURATION", "not-a-duration")
	if got := envDuration("TEST_DURATION", time.Hour); got != time.Hour {
		t.Fatalf("envDuration on bad value = %v, want fallback 1h", got)
	}

	t.Setenv("TEST_DURATION_NIL", "")
	if got := envDuration("TEST_DURATION_NIL", time.Minute); got != time.Minute {
		t.Fatalf("envDuration on empty = %v, want fallback 1m", got)
	}
}
