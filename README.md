# breakur
Fast URL shortner

Set `AUTH_SESSION_SECRET` in production to keep signed login sessions valid across application restarts.

## Optional Redis cache

Short-link redirects are served from Redis when it is configured, falling back
to PostgreSQL for anything not cached. Redis is strictly optional:

- **Not configured** (`REDIS_ADDR` unset) — the app runs PostgreSQL-only and
  never attempts a connection.
- **Configured but unreachable** (down, wrong port, auth failure) — startup
  logs a warning and keeps running PostgreSQL-only. Request-time Redis failures
  are logged and degrades to PostgreSQL, never to a 5xx.

For host-side work, start Redis alone with `make redis` and enable caching by
running the app with `REDIS_ADDR=localhost:6379 make run`. Docker Compose
enables caching automatically via `REDIS_ADDR=redis:6379`.

| Env var | Default | Meaning |
| --- | --- | --- |
| `REDIS_ADDR` | unset = cache disabled | `host:port` of Redis |
| `REDIS_PASSWORD` | empty | Redis AUTH password |
| `REDIS_DB` | `0` | Redis logical database index |
| `LINK_CACHE_TTL` | `1h` | sliding TTL for cached links (reset on every hit) |
| `LINK_CACHE_NEGATIVE_TTL` | `60s` | fixed TTL for unknown-code negative entries |
| `LINK_CACHE_TIMEOUT` | `100ms` | per-operation timeout |

To disable caching in an emergency, unset `REDIS_ADDR` (or set
`LINK_CACHE_TIMEOUT=1ns` to make cache operations fail fast). The cache can be
flushed safely at any time:

```sh
redis-cli --scan --pattern 'breakur:*' | xargs redis-cli del
```