package cache

import "context"

// Nop is a disabled cache: every read misses and every write is ignored. It is
// used when Redis is not configured or unreachable, so the application runs
// entirely from PostgreSQL.
type Nop struct{}

func (Nop) Get(context.Context, string) (string, Lookup, error) { return "", LookupMiss, nil }
func (Nop) Set(context.Context, string, string) error           { return nil }
func (Nop) SetMissing(context.Context, string) error            { return nil }
func (Nop) Delete(context.Context, string) error                { return nil }
func (Nop) Close() error                                        { return nil }
