# Implementation Notes

## Overview

- Homepage is served by FastAPI route `GET /` in `app.py`.
- Actor data is stored in SQLite table `actor_profiles`.
- `GET /actors` response shape is preserved: `[{id, display_name, scope_statement, created_at}, ...]`.

## UI and Feature Additions

- Added server-rendered Actor Notebook UI using Jinja2 template `templates/index.html`.
- Sidebar displays tracked actors; tracking controls are on the main page.
- Added URL-based source ingest with metadata/content derivation.
- Added CTI RSS import endpoint using established feed list.
- Added deterministic question generation with optional local Ollama augmentation.
- Preserved existing JSON API shapes while extending internal tables minimally.
- Added `pyproject.toml` for compatibility with `uv` tooling.

## Security Controls

### Scope

- Prevent SSRF risks for user-supplied source URLs.
- Prevent stored XSS risks in raw HTML endpoints.

### Constraints

- Preserve endpoint contracts and request/response shapes.
- Preserve startup behavior and notebook generation flow.
- Restrict changes to trust-boundary controls only.

### Implemented Controls

- URL policy validation before outbound fetches.
- Redirect-chain re-validation during outbound fetches.
- HTML escaping for all user/content-derived values in rendered output.

### Verification

- Unit tests: deterministic, offline, focused on control logic.
- Integration tests: opt-in (`ACTORTRACKER_ONLINE_TESTS=1`) for real network behavior.
