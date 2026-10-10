package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// newTestRedis starts an in-memory Redis and returns a connected Redis cache.
func newTestRedis(t *testing.T, ttl, negativeTTL time.Duration) (*Redis, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)

	c, err := NewRedis(context.Background(), Config{
		Addr:        mr.Addr(),
		TTL:         ttl,
		NegativeTTL: negativeTTL,
		Timeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("NewRedis: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

func TestRedisSetThenGet(t *testing.T) {
	c, _ := newTestRedis(t, time.Hour, time.Minute)
	ctx := context.Background()

	if err := c.Set(ctx, "abc", "https://example.com"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, result, err := c.Get(ctx, "abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if result != LookupHit {
		t.Fatalf("result = %v, want LookupHit", result)
	}
	if got != "https://example.com" {
		t.Fatalf("destination = %q, want https://example.com", got)
	}
}

func TestRedisGetUnknownIsMiss(t *testing.T) {
	c, _ := newTestRedis(t, time.Hour, time.Minute)

	_, result, err := c.Get(context.Background(), "nope")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if result != LookupMiss {
		t.Fatalf("result = %v, want LookupMiss", result)
	}
}

func TestRedisSetMissingThenGet(t *testing.T) {
	c, _ := newTestRedis(t, time.Hour, time.Minute)
	ctx := context.Background()

	if err := c.SetMissing(ctx, "gone"); err != nil {
		t.Fatalf("SetMissing: %v", err)
	}

	_, result, err := c.Get(ctx, "gone")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if result != LookupNegative {
		t.Fatalf("result = %v, want LookupNegative", result)
	}
}

func TestRedisDeleteRemovesPositiveAndNegative(t *testing.T) {
	c, _ := newTestRedis(t, time.Hour, time.Minute)
	ctx := context.Background()

	if err := c.Set(ctx, "pos", "https://example.com"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := c.SetMissing(ctx, "neg"); err != nil {
		t.Fatalf("SetMissing: %v", err)
	}

	if err := c.Delete(ctx, "pos"); err != nil {
		t.Fatalf("Delete positive: %v", err)
	}
	if err := c.Delete(ctx, "neg"); err != nil {
		t.Fatalf("Delete negative: %v", err)
	}

	if _, result, _ := c.Get(ctx, "pos"); result != LookupMiss {
		t.Fatalf("positive result = %v, want LookupMiss", result)
	}
	if _, result, _ := c.Get(ctx, "neg"); result != LookupMiss {
		t.Fatalf("negative result = %v, want LookupMiss", result)
	}
}

func TestRedisSetClearsNegativeEntry(t *testing.T) {
	c, _ := newTestRedis(t, time.Hour, time.Minute)
	ctx := context.Background()

	if err := c.SetMissing(ctx, "code"); err != nil {
		t.Fatalf("SetMissing: %v", err)
	}
	if err := c.Set(ctx, "code", "https://example.com"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, result, err := c.Get(ctx, "code")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if result != LookupHit || got != "https://example.com" {
		t.Fatalf("got (%q, %v), want (https://example.com, LookupHit)", got, result)
	}
}

// TestRedisGetRefreshesSlidingTTL proves popular links stay resident: a hit
// resets the expiry so the key outlives its original TTL.
func TestRedisGetRefreshesSlidingTTL(t *testing.T) {
	c, mr := newTestRedis(t, time.Hour, time.Minute)
	ctx := context.Background()

	if err := c.Set(ctx, "hot", "https://example.com"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Advance to just before expiry, then refresh with a hit.
	mr.FastForward(50 * time.Minute)
	if _, result, err := c.Get(ctx, "hot"); err != nil || result != LookupHit {
		t.Fatalf("Get before expiry = (%v, %v), want (LookupHit, nil)", result, err)
	}

	// 50 more minutes is past the original TTL but within the refreshed TTL.
	mr.FastForward(50 * time.Minute)
	got, result, err := c.Get(ctx, "hot")
	if err != nil {
		t.Fatalf("Get after refresh: %v", err)
	}
	if result != LookupHit || got != "https://example.com" {
		t.Fatalf("got (%q, %v), want (https://example.com, LookupHit)", got, result)
	}
}

func TestNewRedisOrNopWithEmptyAddrIsNop(t *testing.T) {
	c := NewRedisOrNop(context.Background(), Config{})
	if _, ok := c.(Nop); !ok {
		t.Fatalf("NewRedisOrNop(empty) = %T, want cache.Nop", c)
	}
	if _, result, err := c.Get(context.Background(), "x"); result != LookupMiss || err != nil {
		t.Fatalf("Nop Get = (%v, %v), want (LookupMiss, nil)", result, err)
	}
}

// TestNewRedisOrNopWithUnreachableAddr proves startup never fails when Redis is
// configured but down.
func TestNewRedisOrNopWithUnreachableAddr(t *testing.T) {
	c := NewRedisOrNop(context.Background(), Config{
		Addr:    "127.0.0.1:1", // nothing listens here
		Timeout: 100 * time.Millisecond,
	})
	if _, ok := c.(Nop); !ok {
		t.Fatalf("NewRedisOrNop(unreachable) = %T, want cache.Nop", c)
	}
	if _, result, err := c.Get(context.Background(), "x"); result != LookupMiss || err != nil {
		t.Fatalf("fallback Get = (%v, %v), want (LookupMiss, nil)", result, err)
	}
}
