# ADR-0001: Write-Path Rate Limiting (Community Baseline)

Date: 2026-02-16  
Status: Accepted

## Context
Public/self-hosted deployments need abuse controls on write endpoints to reduce:
- automated spam submissions
- accidental refresh storms
- resource exhaustion from repeated ingest/generation triggers

Constraints:
- keep current architecture (single FastAPI service, no Redis dependency)
- minimal behavior change for normal analyst usage
- reversible and tunable via environment variables

## Decision
Implement application-layer, per-client, sliding-window rate limiting for write methods:
- methods: `POST`, `PUT`, `PATCH`, `DELETE`
- client identity: first IP from `X-Forwarded-For` (if present), else socket peer IP
- buckets:
  - `write_default`: normal write routes
  - `write_heavy`: source/ingest/refresh style routes
- limiter state: in-memory per process (dictionary of timestamp deques)
- response on limit: `429` with `Retry-After` header and JSON error body

Default thresholds (tunable):
- `RATE_LIMIT_DEFAULT_PER_MINUTE=60`
- `RATE_LIMIT_HEAVY_PER_MINUTE=15`
- `RATE_LIMIT_WINDOW_SECONDS=60`
- `RATE_LIMIT_ENABLED=1`

## Options Considered
1. No app-level limiter, rely only on reverse proxy.
- Rejected: not safe for direct/self-hosted deployment.

2. Redis/distributed limiter.
- Rejected for now: better long-term for multi-instance, but adds infra/dependency overhead.

3. In-memory limiter in app (chosen).
- Accepted for Community baseline: lowest complexity, immediate coverage.

## Tradeoffs
Pros:
- fast to deploy
- no new service dependency
- explicit backpressure on high-cost write paths

Cons:
- per-process only (not globally consistent across replicas)
- state resets on restart
- IP-based identity can over-group users behind one NAT

## Guardrails
- only write routes are limited; read routes are unaffected
- thresholds are env-configurable for tuning
- heavy-write routes have stricter limits
- return clear retry guidance to callers

## Future Considerations

If deployment needs change (e.g., multiple app instances or higher concurrency), the limiter may need to move to shared state storage to maintain consistency across processes.

For now, the in-memory implementation provides sufficient protection for single-instance and small self-hosted deployments.

