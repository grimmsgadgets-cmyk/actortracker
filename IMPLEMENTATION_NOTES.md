# Implementation Notes

## Discovery Summary
- Homepage is served by FastAPI route `GET /` in `app.py`.
- Templates/static were previously not configured; homepage returned inline HTML.
- Actor table is `actor_profiles` in SQLite.
- `GET /actors` shape confirmed and preserved: `[{id, display_name, scope_statement, created_at}, ...]`.

## This Change Set
- Added server-rendered Actor Notebook UI using Jinja2 template `templates/index.html`.
- Sidebar now shows only tracked actors; tracking controls live on main page.
- Added URL-based source ingest (single field) and metadata/content derivation.
- Added CTI RSS import endpoint using established feed list.
- Added deterministic question generation plus optional local Ollama augmentation.
- Preserved previous JSON API shapes while extending internal tables minimally.
- Added `pyproject.toml` so project can run with `uv` tooling.

## Security Controls
### Scope
- Fix SSRF risk for user-supplied source URLs.
- Fix stored XSS risk in raw HTML endpoints.

### Non-goals
- No runtime lifecycle redesign.
- No DB performance/migration/index changes.
- No dependency/tooling changes required for runtime.

### Invariants
- Preserve endpoint contracts and request/response shapes.
- Preserve startup behavior and notebook generation flow.
- Restrict code changes to trust-boundary controls only.

### Controls
- `C1` URL policy validation before outbound fetches for user-provided URLs.
- `C2` Redirect-chain re-validation during outbound fetches.
- `C3` HTML escaping for all user/content-derived values in string-built HTML endpoints.

### Verification
- Unit tests: deterministic, offline, focused on `C1-C3`.
- Integration tests: opt-in (`ACTORTRACKER_ONLINE_TESTS=1`) for real network behavior.
