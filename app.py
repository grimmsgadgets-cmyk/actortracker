import html
import json
import os
import re
import socket
import sqlite3
import string
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from urllib.parse import parse_qs, quote, quote_plus, urlparse

import httpx
import actor_state_service
import actor_profile_service
import guidance_catalog
import generation_service
import legacy_ui
import mitre_store
import priority_questions
import routes_api
import routes_actor_ops
import routes_dashboard
import routes_evolution
import routes_notebook
import routes_ui
import source_ingest_service
import source_store_service
import status_service
import timeline_extraction
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from feed_ingest import import_default_feeds_for_actor_core as pipeline_import_default_feeds_for_actor_core
from generation_runner import run_actor_generation_core as pipeline_run_actor_generation_core
from network_safety import safe_http_get, validate_outbound_url
from notebook_builder import build_notebook_core
from notebook_pipeline import build_environment_checks as pipeline_build_environment_checks
from notebook_pipeline import fetch_actor_notebook_core as pipeline_fetch_actor_notebook_core
from notebook_pipeline import build_recent_activity_highlights as pipeline_build_recent_activity_highlights
from notebook_pipeline import latest_reporting_recency_label as pipeline_latest_reporting_recency_label
from notebook_pipeline import recent_change_summary as pipeline_recent_change_summary
from requirements_pipeline import generate_actor_requirements_core as pipeline_generate_actor_requirements_core
from source_derivation import canonical_group_domain as pipeline_canonical_group_domain
from source_derivation import derive_source_from_url_core as pipeline_derive_source_from_url_core
from source_derivation import evidence_source_label_from_source as pipeline_evidence_source_label_from_source
from source_derivation import evidence_title_from_source as pipeline_evidence_title_from_source
from source_derivation import extract_meta as pipeline_extract_meta
from source_derivation import fallback_title_from_url as pipeline_fallback_title_from_url
from source_derivation import strip_html as pipeline_strip_html


@asynccontextmanager
async def app_lifespan(_: FastAPI):
    initialize_sqlite()
    yield


app = FastAPI(lifespan=app_lifespan)
DB_PATH = '/data/app.db'
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / 'templates'))
ATTACK_ENTERPRISE_STIX_URL = (
    'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
)
MITRE_GROUP_CACHE: list[dict[str, object]] | None = None
MITRE_DATASET_CACHE: dict[str, object] | None = None
MITRE_TECHNIQUE_PHASE_CACHE: dict[str, list[str]] | None = None
MITRE_CAMPAIGN_LINK_CACHE: dict[str, dict[str, set[str]]] | None = None
MITRE_TECHNIQUE_INDEX_CACHE: dict[str, dict[str, str]] | None = None
MITRE_SOFTWARE_CACHE: list[dict[str, object]] | None = None
ACTOR_FEED_LOOKBACK_DAYS = int(os.environ.get('ACTOR_FEED_LOOKBACK_DAYS', '540'))

CAPABILITY_GRID_KEYS = [
    'initial_access',
    'persistence',
    'execution',
    'privilege_escalation',
    'defense_evasion',
    'command_and_control',
    'lateral_movement',
    'exfiltration',
    'impact',
    'tooling',
    'infrastructure',
    'targeting',
    'tempo',
]
BEHAVIORAL_MODEL_KEYS = [
    'access_strategy',
    'tool_acquisition',
    'persistence_philosophy',
    'targeting_logic',
    'adaptation_pattern',
    'operational_tempo',
]
ATTACK_TACTIC_TO_CAPABILITY_MAP = {
    'reconnaissance': 'targeting',
    'resource_development': 'infrastructure',
    'initial_access': 'initial_access',
    'execution': 'execution',
    'persistence': 'persistence',
    'privilege_escalation': 'privilege_escalation',
    'defense_evasion': 'defense_evasion',
    'credential_access': 'privilege_escalation',
    'discovery': 'lateral_movement',
    'lateral_movement': 'lateral_movement',
    'collection': 'exfiltration',
    'command_and_control': 'command_and_control',
    'exfiltration': 'exfiltration',
    'impact': 'impact',
}
DEFAULT_CTI_FEEDS = [
    ('CISA Alerts', 'https://www.cisa.gov/cybersecurity-advisories/all.xml'),
    ('CISA News', 'https://www.cisa.gov/news.xml'),
    ('Mandiant Blog', 'https://www.mandiant.com/resources/blog/rss.xml'),
    ('Microsoft Security', 'https://www.microsoft.com/en-us/security/blog/feed/'),
    ('NCSC UK', 'https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml'),
    ('Google Cloud Threat Intelligence', 'https://cloud.google.com/blog/topics/threat-intelligence/rss/'),
    ('Cisco Talos', 'https://blog.talosintelligence.com/rss/'),
    ('Palo Alto Unit 42', 'https://unit42.paloaltonetworks.com/feed/'),
    ('SentinelOne Labs', 'https://www.sentinelone.com/labs/feed/'),
    ('Kaspersky Securelist', 'https://securelist.com/feed/'),
    ('CrowdStrike Blog', 'https://www.crowdstrike.com/en-us/blog/feed/'),
    ('Proofpoint Blog', 'https://www.proofpoint.com/us/blog/rss.xml'),
    ('Red Canary Blog', 'https://redcanary.com/blog/feed/'),
    ('Huntress Blog', 'https://www.huntress.com/blog/rss.xml'),
    ('Arctic Wolf Labs', 'https://arcticwolf.com/resources/blog/feed/'),
    ('Rapid7 Blog', 'https://www.rapid7.com/blog/rss/'),
    ('Sophos News', 'https://news.sophos.com/en-us/feed/'),
    ('Trend Micro Research', 'https://www.trendmicro.com/en_us/research.html/rss.xml'),
    ('ESET WeLiveSecurity', 'https://www.welivesecurity.com/en/rss/feed'),
    ('BleepingComputer', 'https://www.bleepingcomputer.com/feed/'),
    ('The Hacker News', 'https://feeds.feedburner.com/TheHackersNews'),
    ('Krebs on Security', 'https://krebsonsecurity.com/feed/'),
    ('The Record', 'https://therecord.media/feed'),
    ('Dark Reading', 'https://www.darkreading.com/rss.xml'),
    ('SANS Internet Storm Center', 'https://isc.sans.edu/rssfeed_full.xml'),
]
ACTOR_SEARCH_DOMAINS = [
    'cisa.gov',
    'fbi.gov',
    'bleepingcomputer.com',
    'thehackernews.com',
    'therecord.media',
    'mandiant.com',
    'crowdstrike.com',
    'sentinelone.com',
    'talosintelligence.com',
    'unit42.paloaltonetworks.com',
    'microsoft.com',
    'securelist.com',
    'ransomware.live',
]
TRUSTED_ACTIVITY_DOMAINS = set(ACTOR_SEARCH_DOMAINS + ['attack.mitre.org'])
QUESTION_SEED_KEYWORDS = [
    'should review',
    'should detect',
    'organizations should',
    'mitigate',
    'look for',
    'monitor',
    'search for',
    'hunt for',
    'indicator',
    'ioc',
    'cve-',
    'ttp',
    'phish',
    'powershell',
    'wmi',
    'dns',
    'beacon',
    'exploit',
]
OUTBOUND_ALLOWED_DOMAINS = {
    domain.strip().lower()
    for domain in os.environ.get('OUTBOUND_ALLOWED_DOMAINS', '').split(',')
    if domain.strip()
}
DEFAULT_BODY_LIMIT_BYTES = 256 * 1024
SOURCE_UPLOAD_BODY_LIMIT_BYTES = 2 * 1024 * 1024
OBSERVATION_BODY_LIMIT_BYTES = 512 * 1024
RATE_LIMIT_ENABLED = os.environ.get('RATE_LIMIT_ENABLED', '1').strip().lower() not in {
    '0', 'false', 'no', 'off',
}
RATE_LIMIT_WINDOW_SECONDS = max(1, int(os.environ.get('RATE_LIMIT_WINDOW_SECONDS', '60')))
RATE_LIMIT_DEFAULT_PER_MINUTE = max(1, int(os.environ.get('RATE_LIMIT_DEFAULT_PER_MINUTE', '60')))
RATE_LIMIT_HEAVY_PER_MINUTE = max(1, int(os.environ.get('RATE_LIMIT_HEAVY_PER_MINUTE', '15')))
_RATE_LIMIT_STATE: dict[str, deque[float]] = defaultdict(deque)
_RATE_LIMIT_LOCK = Lock()
_RATE_LIMIT_REQUEST_COUNTER = 0
_RATE_LIMIT_CLEANUP_EVERY = 512


def _sync_mitre_cache_to_store() -> None:
    mitre_store.MITRE_GROUP_CACHE = MITRE_GROUP_CACHE
    mitre_store.MITRE_DATASET_CACHE = MITRE_DATASET_CACHE
    mitre_store.MITRE_TECHNIQUE_PHASE_CACHE = MITRE_TECHNIQUE_PHASE_CACHE
    mitre_store.MITRE_CAMPAIGN_LINK_CACHE = MITRE_CAMPAIGN_LINK_CACHE
    mitre_store.MITRE_TECHNIQUE_INDEX_CACHE = MITRE_TECHNIQUE_INDEX_CACHE
    mitre_store.MITRE_SOFTWARE_CACHE = MITRE_SOFTWARE_CACHE


def _sync_mitre_cache_from_store() -> None:
    global MITRE_GROUP_CACHE, MITRE_DATASET_CACHE, MITRE_TECHNIQUE_PHASE_CACHE
    global MITRE_SOFTWARE_CACHE, MITRE_CAMPAIGN_LINK_CACHE, MITRE_TECHNIQUE_INDEX_CACHE
    MITRE_GROUP_CACHE = mitre_store.MITRE_GROUP_CACHE
    MITRE_DATASET_CACHE = mitre_store.MITRE_DATASET_CACHE
    MITRE_TECHNIQUE_PHASE_CACHE = mitre_store.MITRE_TECHNIQUE_PHASE_CACHE
    MITRE_SOFTWARE_CACHE = mitre_store.MITRE_SOFTWARE_CACHE
    MITRE_CAMPAIGN_LINK_CACHE = mitre_store.MITRE_CAMPAIGN_LINK_CACHE
    MITRE_TECHNIQUE_INDEX_CACHE = mitre_store.MITRE_TECHNIQUE_INDEX_CACHE


def _request_body_limit_bytes(method: str, path: str) -> int:
    method_upper = method.upper()
    if method_upper not in {'POST', 'PUT', 'PATCH'}:
        return 0
    if path.startswith('/actors/') and path.endswith('/sources'):
        return SOURCE_UPLOAD_BODY_LIMIT_BYTES
    if path.startswith('/actors/') and path.endswith('/observations'):
        return OBSERVATION_BODY_LIMIT_BYTES
    return DEFAULT_BODY_LIMIT_BYTES


async def _enforce_request_size(request: Request, limit: int) -> None:
    if limit <= 0:
        return
    content_length = request.headers.get('content-length', '').strip()
    if content_length.isdigit() and int(content_length) > limit:
        raise HTTPException(
            status_code=413,
            detail=f'Request body too large. Limit for this endpoint is {limit} bytes.',
        )
    body = await request.body()
    if len(body) > limit:
        raise HTTPException(
            status_code=413,
            detail=f'Request body too large. Limit for this endpoint is {limit} bytes.',
        )


def _rate_limit_bucket(method: str, path: str) -> tuple[str, int] | None:
    method_upper = method.upper()
    if method_upper not in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        return None
    heavy = (
        path.startswith('/actors/') and (
            path.endswith('/sources')
            or path.endswith('/sources/import-feeds')
            or path.endswith('/refresh')
            or path.endswith('/observations')
        )
    )
    if heavy:
        return ('write_heavy', RATE_LIMIT_HEAVY_PER_MINUTE)
    return ('write_default', RATE_LIMIT_DEFAULT_PER_MINUTE)


def _request_client_id(request: Request) -> str:
    forwarded_for = request.headers.get('x-forwarded-for', '').strip()
    if forwarded_for:
        first_hop = forwarded_for.split(',', 1)[0].strip()
        if first_hop:
            return first_hop
    if request.client and request.client.host:
        return request.client.host
    return 'unknown'


def _prune_rate_limit_state(now: float) -> None:
    stale_keys: list[str] = []
    for key, timestamps in _RATE_LIMIT_STATE.items():
        while timestamps and now - timestamps[0] >= RATE_LIMIT_WINDOW_SECONDS:
            timestamps.popleft()
        if not timestamps:
            stale_keys.append(key)
    for key in stale_keys:
        _RATE_LIMIT_STATE.pop(key, None)


def _check_rate_limit(request: Request) -> tuple[bool, int, int]:
    bucket = _rate_limit_bucket(request.method, request.url.path)
    if not RATE_LIMIT_ENABLED or bucket is None:
        return (False, 0, 0)
    bucket_name, limit = bucket
    client_id = _request_client_id(request)
    key = f'{bucket_name}:{client_id}'
    now = time.monotonic()
    with _RATE_LIMIT_LOCK:
        global _RATE_LIMIT_REQUEST_COUNTER
        _RATE_LIMIT_REQUEST_COUNTER += 1
        if _RATE_LIMIT_REQUEST_COUNTER % _RATE_LIMIT_CLEANUP_EVERY == 0:
            _prune_rate_limit_state(now)
        timestamps = _RATE_LIMIT_STATE[key]
        while timestamps and now - timestamps[0] >= RATE_LIMIT_WINDOW_SECONDS:
            timestamps.popleft()
        if len(timestamps) >= limit:
            retry_after = max(1, int(RATE_LIMIT_WINDOW_SECONDS - (now - timestamps[0])) + 1)
            return (True, retry_after, limit)
        timestamps.append(now)
    return (False, 0, limit)


@app.middleware('http')
async def add_security_headers(request: Request, call_next):
    limit = _request_body_limit_bytes(request.method, request.url.path)
    if limit > 0:
        content_length = request.headers.get('content-length', '').strip()
        if content_length.isdigit() and int(content_length) > limit:
            return JSONResponse(
                status_code=413,
                content={
                    'detail': (
                        f'Request body too large. Limit for this endpoint is {limit} bytes.'
                    )
                },
            )

    limited, retry_after, limit = _check_rate_limit(request)
    if limited:
        return JSONResponse(
            status_code=429,
            content={
                'detail': (
                    f'Rate limit exceeded for write requests. Try again in {retry_after} seconds.'
                )
            },
            headers={
                'Retry-After': str(retry_after),
                'X-RateLimit-Limit': str(limit),
            },
        )

    response = await call_next(request)
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers.setdefault('Content-Security-Policy', csp_policy)
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    return response


def _prepare_db_path(path_value: str) -> str:
    db_parent = str(Path(path_value).resolve().parent)
    os.makedirs(db_parent, exist_ok=True)
    return path_value


def _resolve_startup_db_path() -> str:
    try:
        return _prepare_db_path(DB_PATH)
    except PermissionError:
        fallback = str(BASE_DIR / 'app.db')
        return _prepare_db_path(fallback)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def baseline_entry() -> dict[str, str | float | list[str]]:
    return {
        'observed': '',
        'assessed': '',
        'confidence': 0.0,
        'evidence_refs': [],
    }


def baseline_capability_grid() -> dict[str, dict[str, str | float | list[str]]]:
    return {key: baseline_entry() for key in CAPABILITY_GRID_KEYS}


def baseline_behavioral_model() -> dict[str, dict[str, str | float | list[str]]]:
    return {key: baseline_entry() for key in BEHAVIORAL_MODEL_KEYS}


def generate_validation_template(delta_type: str, affected_category: str) -> dict[str, list[str]]:
    if delta_type == 'expansion':
        return {
            'tier1_basic': [
                'Confirm the report explicitly describes technique use (not speculation).',
                f'Confirm {affected_category} is not already present in the baseline.',
                'Identify the strongest evidence snippet/source for this claim.',
            ],
            'tier2_analytic': [
                (
                    f'Does this expand the actor options within {affected_category} '
                    'or just repeat known behavior?'
                ),
                'Does it contradict prior baseline assumptions? If yes, which?',
                'What additional evidence would increase confidence?',
            ],
            'tier3_strategic': [
                (
                    f'Does this {affected_category} shift suggest adaptation to defenses '
                    'or a new operational phase?'
                ),
                'Does this change the tracking priority for this actor?',
            ],
        }
    return {'tier1_basic': [], 'tier2_analytic': [], 'tier3_strategic': []}


def normalize_string_list(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise HTTPException(status_code=400, detail='list fields must be arrays')
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise HTTPException(status_code=400, detail='list values must be strings')
        normalized.append(item)
    return normalized


def _normalize_text(value: str) -> str:
    lowered = value.lower()
    translator = str.maketrans('', '', string.punctuation)
    return lowered.translate(translator)


def _token_set(value: str) -> set[str]:
    return {token for token in _normalize_text(value).split() if len(token) > 2}


def _token_overlap(a: str, b: str) -> float:
    a_tokens = _token_set(a)
    b_tokens = _token_set(b)
    if not a_tokens or not b_tokens:
        return 0.0
    return len(a_tokens.intersection(b_tokens)) / len(a_tokens.union(b_tokens))


def _split_sentences(text: str) -> list[str]:
    sentences = [segment.strip() for segment in re.split(r'(?<=[.!?])\s+', text) if segment.strip()]
    return [sentence for sentence in sentences if len(sentence) >= 25]


def _extract_question_sentences(text: str) -> list[str]:
    matches: list[str] = []
    for sentence in _split_sentences(text):
        lowered = sentence.lower()
        if any(keyword in lowered for keyword in QUESTION_SEED_KEYWORDS):
            matches.append(sentence)
    return matches


def _question_from_sentence(sentence: str) -> str:
    lowered = sentence.lower()
    if any(token in lowered for token in ('phish', 'email')):
        return 'What evidence shows this actor is using email or phishing delivery right now?'
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit')):
        return 'Which exposed systems are most at risk from this actor’s current exploit activity?'
    if any(token in lowered for token in ('powershell', 'wmi', 'scheduled task')):
        return 'Which endpoint execution patterns should we validate for this actor immediately?'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon')):
        return 'What network indicators suggest active command-and-control behavior by this actor?'
    if any(token in lowered for token in ('hash', 'file', 'process', 'command line')):
        return 'Which endpoint artifacts best confirm this actor’s latest operational behavior?'
    compact = ' '.join(sentence.split())
    if len(compact) > 170:
        compact = compact[:170].rsplit(' ', 1)[0] + '...'
    return f'What should analysts verify next based on this report: {compact}'


def _sanitize_question_text(question: str) -> str:
    cleaned = ' '.join(question.strip().split())
    if not cleaned:
        return ''
    for pattern in (
        r'\bPIRs?\b',
        r'\bpriority intelligence requirements?\b',
        r'\bintelligence requirements?\b',
        r'\bcollection requirements?\b',
        r'\bkill chain\b',
    ):
        cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r'\s{2,}', ' ', cleaned).strip()
    if not cleaned:
        return ''
    if not cleaned.endswith('?'):
        cleaned = cleaned.rstrip('.!') + '?'
    if len(cleaned) > 220:
        cleaned = cleaned[:220].rsplit(' ', 1)[0] + '?'
    if not cleaned.lower().startswith(('what ', 'how ', 'which ', 'where ', 'when ', 'who ')):
        cleaned = f'What should we ask next: {cleaned}'
    return cleaned


def _first_sentences(text: str, count: int = 2) -> str:
    sentences = _split_sentences(text)
    if not sentences:
        compact = ' '.join(text.split())
        return compact[:240]
    return ' '.join(sentences[:count])


def _normalize_actor_key(value: str) -> str:
    return ' '.join(re.findall(r'[a-z0-9]+', value.lower()))


def _dedupe_actor_terms(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        key = _normalize_actor_key(text)
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped


def _mitre_alias_values(obj: dict[str, object]) -> list[str]:
    alias_candidates: list[str] = []
    for field in ('aliases', 'x_mitre_aliases'):
        raw = obj.get(field)
        if isinstance(raw, list):
            alias_candidates.extend(str(item).strip() for item in raw if str(item).strip())
    return _dedupe_actor_terms(alias_candidates)


def _candidate_overlap_score(actor_tokens: set[str], search_keys: set[str]) -> float:
    best_score = 0.0
    for search_key in search_keys:
        key_tokens = set(search_key.split())
        if not key_tokens:
            continue
        overlap = len(actor_tokens.intersection(key_tokens)) / len(actor_tokens.union(key_tokens))
        if overlap > best_score:
            best_score = overlap
    return best_score


def _mitre_dataset_path() -> Path:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    path = Path(os.environ.get('MITRE_ATTACK_PATH', '').strip()) if os.environ.get('MITRE_ATTACK_PATH', '').strip() else None
    if path is not None:
        return path
    return Path(DB_PATH).resolve().parent / 'mitre_enterprise_attack.json'


def _ensure_mitre_attack_dataset() -> bool:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.ensure_mitre_attack_dataset()
    finally:
        _sync_mitre_cache_from_store()


def _load_mitre_groups() -> list[dict[str, object]]:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.load_mitre_groups()
    finally:
        _sync_mitre_cache_from_store()


def _load_mitre_dataset() -> dict[str, object]:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.load_mitre_dataset()
    finally:
        _sync_mitre_cache_from_store()


def _mitre_campaign_link_index() -> dict[str, dict[str, set[str]]]:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.mitre_campaign_link_index()
    finally:
        _sync_mitre_cache_from_store()


def _normalize_technique_id(value: str) -> str:
    return mitre_store.normalize_technique_id(value)


def _mitre_technique_index() -> dict[str, dict[str, str]]:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.mitre_technique_index()
    finally:
        _sync_mitre_cache_from_store()


def _mitre_valid_technique_ids() -> set[str]:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.mitre_valid_technique_ids()
    finally:
        _sync_mitre_cache_from_store()


def _mitre_technique_phase_index() -> dict[str, list[str]]:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.mitre_technique_phase_index()
    finally:
        _sync_mitre_cache_from_store()


def _capability_category_from_technique_id(ttp_id: str) -> str | None:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.capability_category_from_technique_id(
            ttp_id,
            attack_tactic_to_capability_map=ATTACK_TACTIC_TO_CAPABILITY_MAP,
            capability_grid_keys=CAPABILITY_GRID_KEYS,
        )
    finally:
        _sync_mitre_cache_from_store()


def _match_mitre_group(actor_name: str) -> dict[str, object] | None:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.match_mitre_group(actor_name)
    finally:
        _sync_mitre_cache_from_store()


def _load_mitre_software() -> list[dict[str, object]]:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.load_mitre_software()
    finally:
        _sync_mitre_cache_from_store()


def _match_mitre_software(name: str) -> dict[str, object] | None:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.match_mitre_software(name)
    finally:
        _sync_mitre_cache_from_store()

def _build_actor_profile_from_mitre(actor_name: str) -> dict[str, str]:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.build_actor_profile_from_mitre(
            actor_name,
            first_sentences=lambda text, count: _first_sentences(text, count=count),
        )
    finally:
        _sync_mitre_cache_from_store()


def _group_top_techniques(group_stix_id: str, limit: int = 6) -> list[dict[str, str]]:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.group_top_techniques(group_stix_id, limit=limit)
    finally:
        _sync_mitre_cache_from_store()


def _known_technique_ids_for_entity(entity_stix_id: str) -> set[str]:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    _sync_mitre_cache_to_store()
    try:
        return mitre_store.known_technique_ids_for_entity(entity_stix_id)
    finally:
        _sync_mitre_cache_from_store()


def _favorite_attack_vectors(techniques: list[dict[str, str]], limit: int = 3) -> list[str]:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    return mitre_store.favorite_attack_vectors(techniques, limit=limit)


def _emerging_techniques_from_timeline(
    timeline_items: list[dict[str, object]],
    known_technique_ids: set[str],
    limit: int = 5,
    min_distinct_sources: int = 2,
    min_event_count: int = 2,
) -> list[dict[str, object]]:
    stats: dict[str, dict[str, object]] = {}
    technique_index = _mitre_technique_index()
    valid_ids = set(technique_index.keys())
    for item in timeline_items:
        occurred_raw = str(item.get('occurred_at') or '')
        occurred_dt = _parse_published_datetime(occurred_raw)
        if occurred_dt is None:
            continue

        source_id = str(item.get('source_id') or '').strip()
        for technique_id in item.get('ttp_ids', []):
            tid = _normalize_technique_id(str(technique_id))
            if valid_ids and tid not in valid_ids:
                continue
            if not tid or tid in known_technique_ids:
                continue
            entry = stats.setdefault(
                tid,
                {
                    'first_seen': occurred_dt,
                    'latest_seen': occurred_dt,
                    'event_count': 0,
                    'source_ids': set(),
                    'categories': set(),
                },
            )
            entry['event_count'] = int(entry.get('event_count') or 0) + 1
            first_seen = entry.get('first_seen')
            if isinstance(first_seen, datetime):
                if occurred_dt < first_seen:
                    entry['first_seen'] = occurred_dt
            else:
                entry['first_seen'] = occurred_dt
            latest_seen = entry.get('latest_seen')
            if isinstance(latest_seen, datetime):
                if occurred_dt > latest_seen:
                    entry['latest_seen'] = occurred_dt
            else:
                entry['latest_seen'] = occurred_dt
            source_ids = entry.get('source_ids')
            if isinstance(source_ids, set) and source_id:
                source_ids.add(source_id)
            category = str(item.get('category') or '').strip().replace('_', ' ')
            categories = entry.get('categories')
            if isinstance(categories, set) and category:
                categories.add(category)

    ranked: list[tuple[str, datetime, int, int, dict[str, object]]] = []
    for tid, entry in stats.items():
        latest_seen = entry.get('latest_seen')
        if not isinstance(latest_seen, datetime):
            continue
        event_count = int(entry.get('event_count') or 0)
        source_ids = entry.get('source_ids')
        source_count = len(source_ids) if isinstance(source_ids, set) else 0
        if source_count < min_distinct_sources and event_count < min_event_count:
            continue
        ranked.append((tid, latest_seen, source_count, event_count, entry))

    ranked.sort(key=lambda item: (item[1], item[2], item[3], item[0]), reverse=True)
    emerging: list[dict[str, object]] = []
    for tid, _latest, source_count, event_count, entry in ranked[:limit]:
        first_seen = entry.get('first_seen')
        latest_seen = entry.get('latest_seen')
        categories = entry.get('categories')
        technique = technique_index.get(tid, {})
        emerging.append(
            {
                'technique_id': tid,
                'technique_name': str(technique.get('name') or ''),
                'technique_url': str(technique.get('url') or ''),
                'first_seen': first_seen.date().isoformat() if isinstance(first_seen, datetime) else '',
                'last_seen': latest_seen.date().isoformat() if isinstance(latest_seen, datetime) else '',
                'source_count': source_count,
                'event_count': event_count,
                'categories': sorted(str(item) for item in categories) if isinstance(categories, set) else [],
            }
        )
    return emerging


def _emerging_technique_ids_from_timeline(
    timeline_items: list[dict[str, object]],
    known_technique_ids: set[str],
    limit: int = 5,
    min_distinct_sources: int = 2,
    min_event_count: int = 2,
) -> list[str]:
    return [
        str(item.get('technique_id') or '')
        for item in _emerging_techniques_from_timeline(
            timeline_items,
            known_technique_ids,
            limit=limit,
            min_distinct_sources=min_distinct_sources,
            min_event_count=min_event_count,
        )
        if str(item.get('technique_id') or '')
    ]


def _extract_ttp_ids(text: str) -> list[str]:
    matches = re.findall(r'\bT\d{4}(?:\.\d{3})?\b', text, flags=re.IGNORECASE)
    valid_ids = _mitre_valid_technique_ids()
    deduped: list[str] = []
    for value in matches:
        norm = value.upper()
        if valid_ids and norm not in valid_ids:
            continue
        if norm not in deduped:
            deduped.append(norm)
    return deduped


def _safe_json_string_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
        if not isinstance(parsed, list):
            return []
        result: list[str] = []
        for item in parsed:
            if isinstance(item, str):
                result.append(item)
        return result
    except Exception:
        return []


def _parse_iso_for_sort(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


def _short_date(value: str) -> str:
    dt = _parse_published_datetime(value)
    if dt is None:
        return value[:10]
    return dt.date().isoformat()


def _format_date_or_unknown(value: str) -> str:
    dt = _parse_published_datetime(value)
    if dt is None:
        return 'Unknown'
    return dt.date().isoformat()


def _freshness_badge(value: str | None) -> tuple[str, str]:
    dt = _parse_published_datetime(value)
    if dt is None:
        return ('unknown', 'freshness-unknown')
    days_old = max(0, (datetime.now(timezone.utc) - dt).days)
    if days_old <= 1:
        return ('<=24h', 'freshness-new')
    if days_old <= 7:
        return (f'{days_old}d', 'freshness-recent')
    if days_old <= 30:
        return (f'{days_old}d stale', 'freshness-stale')
    return (f'{days_old}d old', 'freshness-old')


def _bucket_label(value: str) -> str:
    dt = _parse_iso_for_sort(value)
    if dt == datetime.min.replace(tzinfo=timezone.utc):
        return value[:7]
    return dt.strftime('%Y-%m')


def _timeline_category_color(category: str) -> str:
    palette = {
        'initial_access': '#5b8def',
        'execution': '#49a078',
        'persistence': '#8a6adf',
        'lateral_movement': '#2e8bcb',
        'command_and_control': '#d48a2f',
        'exfiltration': '#c44f4f',
        'impact': '#9f2d2d',
        'defense_evasion': '#6f7d8c',
        'report': '#7b8a97',
    }
    return palette.get(category, '#7b8a97')


def _build_notebook_kpis(
    timeline_items: list[dict[str, object]],
    known_technique_ids: set[str],
    open_questions_count: int,
    sources: list[dict[str, object]],
) -> dict[str, str]:
    now = datetime.now(timezone.utc)
    cutoff_30 = now - timedelta(days=30)
    valid_technique_ids = _mitre_valid_technique_ids()

    activity_30d = 0
    novel_techniques_30d: set[str] = set()
    for item in timeline_items:
        dt = _parse_published_datetime(str(item.get('occurred_at') or ''))
        if dt is None or dt < cutoff_30:
            continue
        activity_30d += 1
        for ttp in item.get('ttp_ids', []):
            tid = str(ttp).upper()
            if valid_technique_ids and tid not in valid_technique_ids:
                continue
            if tid and tid not in known_technique_ids:
                novel_techniques_30d.add(tid)

    latest_source_dt: datetime | None = None
    latest_source_text = ''
    for source in sources:
        candidate_raw = str(source.get('published_at') or source.get('retrieved_at') or '')
        dt = _parse_published_datetime(candidate_raw)
        if dt is None:
            continue
        if latest_source_dt is None or dt > latest_source_dt:
            latest_source_dt = dt
            latest_source_text = dt.date().isoformat()

    return {
        'activity_30d': str(activity_30d),
        'new_techniques_30d': str(len(novel_techniques_30d)),
        'open_priority_questions': str(open_questions_count),
        'last_verified_update': latest_source_text or 'Unknown',
    }


def _build_timeline_graph(timeline_items: list[dict[str, object]]) -> list[dict[str, object]]:
    buckets: dict[str, dict[str, int]] = {}
    for item in timeline_items:
        label = _bucket_label(str(item.get('occurred_at') or ''))
        category = str(item.get('category') or 'report')
        bucket = buckets.setdefault(label, {})
        bucket[category] = bucket.get(category, 0) + 1

    labels = sorted(buckets.keys())
    max_total = 1
    for label in labels:
        max_total = max(max_total, sum(buckets[label].values()))

    graph: list[dict[str, object]] = []
    for label in labels:
        counts = buckets[label]
        total = sum(counts.values())
        segments = []
        for category, count in sorted(counts.items(), key=lambda entry: entry[1], reverse=True):
            segments.append(
                {
                    'category': category.replace('_', ' '),
                    'count': count,
                    'color': _timeline_category_color(category),
                    'flex': count,
                }
            )
        graph.append(
            {
                'label': label,
                'total': total,
                'height_pct': max(8, int((total / max_total) * 100)),
                'segments': segments,
            }
        )
    return graph


def _first_seen_for_techniques(
    timeline_items: list[dict[str, object]],
    technique_ids: list[str],
) -> list[dict[str, str]]:
    first_seen: dict[str, str] = {}
    wanted = {tech.upper() for tech in technique_ids}
    for item in sorted(
        timeline_items,
        key=lambda entry: (
            _parse_published_datetime(str(entry.get('occurred_at') or ''))
            or datetime.min.replace(tzinfo=timezone.utc)
        ),
    ):
        occurred = str(item.get('occurred_at') or '')
        for tech in item.get('ttp_ids', []):
            tech_id = str(tech).upper()
            if tech_id in wanted and tech_id not in first_seen:
                first_seen[tech_id] = _short_date(occurred)
    return [{'technique_id': tid, 'first_seen': first_seen.get(tid, '')} for tid in technique_ids]


def _severity_label(category: str, target_text: str, novelty: bool) -> str:
    weights = {
        'initial_access': 3,
        'execution': 2,
        'persistence': 2,
        'lateral_movement': 2,
        'command_and_control': 2,
        'exfiltration': 3,
        'impact': 3,
        'defense_evasion': 2,
        'report': 1,
    }
    score = weights.get(category, 1)
    if novelty:
        score += 2
    if any(
        token in target_text.lower()
        for token in ('defense', 'government', 'energy', 'health', 'finance', 'critical', 'infrastructure')
    ):
        score += 1
    if score >= 5:
        return 'High'
    if score >= 3:
        return 'Medium'
    return 'Low'


def _action_text(category: str) -> str:
    mapping = {
        'initial_access': 'Gained or attempted entry',
        'execution': 'Executed attacker tooling',
        'persistence': 'Established foothold',
        'lateral_movement': 'Moved across environment',
        'command_and_control': 'Maintained remote control',
        'exfiltration': 'Collected or exfiltrated data',
        'impact': 'Disrupted or encrypted systems',
        'defense_evasion': 'Evaded detection/controls',
        'report': 'Reported notable activity',
    }
    return mapping.get(category, 'Reported notable activity')


def _compact_timeline_rows(
    timeline_items: list[dict[str, object]],
    known_technique_ids: set[str],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    sorted_items = sorted(
        timeline_items,
        key=lambda entry: _parse_iso_for_sort(str(entry.get('occurred_at') or '')),
        reverse=True,
    )
    for item in sorted_items[:14]:
        ttp_ids = [str(t).upper() for t in item.get('ttp_ids', [])]
        novelty = any(tech_id not in known_technique_ids for tech_id in ttp_ids) if ttp_ids else False
        category = str(item.get('category') or 'report')
        target = str(item.get('target_text') or '')
        rows.append(
            {
                'date': _short_date(str(item.get('occurred_at') or '')),
                'category': category.replace('_', ' '),
                'action': _action_text(category),
                'target': target,
                'techniques': ', '.join(ttp_ids),
                'severity': _severity_label(category, target, novelty),
                'summary': str(item.get('summary') or ''),
            }
        )
    return rows


_question_priority_score = priority_questions.question_priority_score
_question_category_hints = priority_questions.question_category_hints
_actor_signal_categories = priority_questions.actor_signal_categories
_question_actor_relevance = priority_questions.question_actor_relevance
_fallback_priority_questions = priority_questions.fallback_priority_questions
_priority_know_focus = priority_questions.priority_know_focus
_priority_hunt_focus = priority_questions.priority_hunt_focus
_priority_decision_to_inform = priority_questions.priority_decision_to_inform
_priority_time_horizon = priority_questions.priority_time_horizon
_priority_disconfirming_signal = priority_questions.priority_disconfirming_signal
_priority_confidence_label = priority_questions.priority_confidence_label
_priority_strongest_evidence = priority_questions.priority_strongest_evidence
_priority_confidence_why = priority_questions.priority_confidence_why
_priority_assumptions = priority_questions.priority_assumptions
_priority_alternative_hypothesis = priority_questions.priority_alternative_hypothesis
_priority_next_best_action = priority_questions.priority_next_best_action
_priority_action_ladder = priority_questions.priority_action_ladder
_phase_label_for_question = priority_questions.phase_label_for_question
_short_decision_trigger = priority_questions.short_decision_trigger
_guidance_line = priority_questions.guidance_line
_priority_update_recency_label = priority_questions.priority_update_recency_label
_priority_recency_points = priority_questions.priority_recency_points
_priority_rank_score = priority_questions.priority_rank_score
_org_context_tokens = priority_questions.org_context_tokens
_org_alignment_label = priority_questions.org_alignment_label
_escalation_threshold_line = priority_questions.escalation_threshold_line
_quick_check_title = priority_questions.quick_check_title


def _priority_where_to_check(guidance_items: list[dict[str, object]], question_text: str) -> str:
    return priority_questions.priority_where_to_check(
        guidance_items,
        question_text,
        platforms_for_question=lambda text: _platforms_for_question(text),
    )


def _telemetry_anchor_line(guidance_items: list[dict[str, object]], question_text: str) -> str:
    return priority_questions.telemetry_anchor_line(
        guidance_items,
        question_text,
        platforms_for_question=lambda text: _platforms_for_question(text),
    )


def _guidance_query_hint(guidance_items: list[dict[str, object]], question_text: str) -> str:
    return priority_questions.guidance_query_hint(
        guidance_items,
        question_text,
        platforms_for_question=lambda text: _platforms_for_question(text),
        guidance_for_platform=lambda platform, text: _guidance_for_platform(platform, text),
    )


def _priority_update_evidence_dt(update: dict[str, object]) -> datetime | None:
    return priority_questions.priority_update_evidence_dt(
        update,
        parse_published_datetime=lambda value: _parse_published_datetime(value),
    )


def _question_org_alignment(question_text: str, org_context: str) -> int:
    return priority_questions.question_org_alignment(
        question_text,
        org_context,
        token_set=lambda text: _token_set(text),
    )


def _latest_reporting_recency_label(timeline_recent_items: list[dict[str, object]]) -> str:
    return pipeline_latest_reporting_recency_label(
        timeline_recent_items,
        parse_published_datetime=lambda value: _parse_published_datetime(value),
    )


def _build_environment_checks(
    timeline_recent_items: list[dict[str, object]],
    recent_activity_highlights: list[dict[str, object]],
    top_techniques: list[dict[str, str]],
) -> list[dict[str, str]]:
    recency_label = _latest_reporting_recency_label(timeline_recent_items)
    return pipeline_build_environment_checks(
        timeline_recent_items,
        recent_activity_highlights,
        top_techniques,
        recency_label=recency_label,
    )


def _recent_change_summary(
    timeline_recent_items: list[dict[str, object]],
    recent_activity_highlights: list[dict[str, object]],
    source_items: list[dict[str, object]],
) -> dict[str, str]:
    return pipeline_recent_change_summary(
        timeline_recent_items,
        recent_activity_highlights,
        source_items,
    )


def _extract_target_hint(sentence: str) -> str:
    return timeline_extraction.extract_target_hint(sentence)


def _sentence_mentions_actor_terms(sentence: str, actor_terms: list[str]) -> bool:
    return timeline_extraction.sentence_mentions_actor_terms(sentence, actor_terms)


def _looks_like_activity_sentence(sentence: str) -> bool:
    return timeline_extraction.looks_like_activity_sentence(sentence)


def _actor_terms(actor_name: str, mitre_group_name: str, aliases_csv: str) -> list[str]:
    raw_terms = [actor_name, mitre_group_name] + [part.strip() for part in aliases_csv.split(',') if part.strip()]
    generic_terms = {
        'apt',
        'group',
        'team',
        'actor',
        'threat actor',
        'intrusion set',
        'cluster',
    }
    terms: list[str] = []
    for raw in raw_terms:
        value = raw.strip().lower()
        if len(value) < 3:
            continue
        if value in generic_terms:
            continue
        if value not in terms:
            terms.append(value)
    return terms


def _text_contains_actor_term(text: str, actor_terms: list[str]) -> bool:
    return _sentence_mentions_actor_terms(text, actor_terms)


def _actor_query_feeds(actor_terms: list[str]) -> list[tuple[str, str]]:
    feeds: list[tuple[str, str]] = []
    added: set[str] = set()
    for term in actor_terms:
        compact = term.strip()
        if len(compact) < 3 or len(compact) > 40:
            continue
        if compact in added:
            continue
        added.add(compact)
        q = quote_plus(f'"{compact}" cybersecurity OR ransomware OR threat actor')
        feeds.append(('Google News Actor Query', f'https://news.google.com/rss/search?q={q}&hl=en-US&gl=US&ceid=US:en'))
        if len(feeds) >= 3:
            break
    return feeds


def _actor_search_queries(actor_terms: list[str]) -> list[str]:
    queries: list[str] = []
    for term in actor_terms:
        compact = term.strip()
        if len(compact) < 3 or len(compact) > 60:
            continue
        queries.extend(
            [
                f'"{compact}" ransomware activity',
                f'"{compact}" threat actor report',
                f'"{compact}" CISA advisory',
            ]
        )
        if len(queries) >= 9:
            break
    return queries[:9]


def _domain_allowed_for_actor_search(url: str) -> bool:
    try:
        hostname = (urlparse(url).hostname or '').strip('.').lower()
    except Exception:
        return False
    if not hostname:
        return False
    return any(
        hostname == domain or hostname.endswith(f'.{domain}')
        for domain in ACTOR_SEARCH_DOMAINS
    )


def _duckduckgo_actor_search_urls(actor_terms: list[str], limit: int = 20) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    headers = {
        'User-Agent': (
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
        )
    }
    for query in _actor_search_queries(actor_terms):
        search_url = f'https://html.duckduckgo.com/html/?q={quote_plus(query)}'
        try:
            response = httpx.get(search_url, timeout=20.0, follow_redirects=True, headers=headers)
            if response.status_code != 200:
                continue
            body = response.text
        except Exception:
            continue

        for match in re.finditer(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"', body):
            candidate = html.unescape(match.group(1)).strip()
            if not candidate.startswith('http'):
                continue
            if candidate in seen:
                continue
            if not _domain_allowed_for_actor_search(candidate):
                continue
            seen.add(candidate)
            urls.append(candidate)
            if len(urls) >= limit:
                return urls
    return urls


def _sentence_mentions_actor(sentence: str, actor_name: str) -> bool:
    lowered = sentence.lower()
    actor_tokens = [token for token in re.findall(r'[a-z0-9]+', actor_name.lower()) if len(token) > 2]
    return bool(actor_tokens and any(token in lowered for token in actor_tokens))


def _looks_like_navigation_noise(sentence: str) -> bool:
    lowered = sentence.lower()
    noise_markers = (
        'contact sales',
        'get started for free',
        'solutions & technology',
        'inside google cloud',
        'developers & practitioners',
        'training & certifications',
        'ecosystem it leaders',
    )
    if any(marker in lowered for marker in noise_markers):
        return True
    if lowered.count('&') >= 4:
        return True
    if len(sentence.split()) > 70:
        return True
    return False


def _build_actor_profile_summary(actor_name: str, source_texts: list[str]) -> str:
    candidate_sentences: list[str] = []
    for text in source_texts:
        for sentence in _split_sentences(text):
            if _looks_like_navigation_noise(sentence):
                continue
            if _sentence_mentions_actor(sentence, actor_name):
                candidate_sentences.append(' '.join(sentence.split()))
            if len(candidate_sentences) >= 24:
                break
        if len(candidate_sentences) >= 24:
            break

    selected: list[str] = []
    for sentence in candidate_sentences:
        normalized = _normalize_text(sentence)
        if any(_token_overlap(normalized, _normalize_text(existing)) >= 0.7 for existing in selected):
            continue
        selected.append(sentence)
        if len(selected) >= 3:
            break

    if selected:
        return ' '.join(selected)
    return (
        f'No actor-specific executive summary is available for {actor_name} yet. '
        'Current sources do not provide clear, attributable details about this actor. '
        'Add a source that explicitly profiles this actor and refresh the notebook.'
    )


def _build_recent_activity_highlights(
    timeline_items: list[dict[str, object]],
    sources: list[dict[str, object]],
    actor_terms: list[str],
) -> list[dict[str, str | None]]:
    def _source_domain(url: str) -> str:
        try:
            return urlparse(url).netloc.lower()
        except Exception:
            return ''

    pipeline_items = pipeline_build_recent_activity_highlights(
        timeline_items,
        sources,
        actor_terms,
        trusted_activity_domains=TRUSTED_ACTIVITY_DOMAINS,
        source_domain=_source_domain,
        canonical_group_domain=_canonical_group_domain,
        looks_like_activity_sentence=_looks_like_activity_sentence,
        sentence_mentions_actor_terms=_sentence_mentions_actor_terms,
        text_contains_actor_term=_text_contains_actor_term,
        normalize_text=_normalize_text,
        parse_published_datetime=lambda value: _parse_published_datetime(value),
        freshness_badge=lambda value: _freshness_badge(value),
        evidence_title_from_source=_evidence_title_from_source,
        fallback_title_from_url=_fallback_title_from_url,
        evidence_source_label_from_source=_evidence_source_label_from_source,
        extract_ttp_ids=_extract_ttp_ids,
        split_sentences=lambda text: _split_sentences(text),
        looks_like_navigation_noise=_looks_like_navigation_noise,
    )

    highlights: list[dict[str, str | None]] = []
    for item in pipeline_items:
        copy_item = dict(item)
        copy_item['date'] = _format_date_or_unknown(str(item.get('date') or ''))
        highlights.append(copy_item)
    return highlights


def _extract_target_from_activity_text(text: str) -> str:
    return timeline_extraction.extract_target_from_activity_text(text)


def _build_recent_activity_synthesis(
    highlights: list[dict[str, str | None]],
) -> list[dict[str, str]]:
    if not highlights:
        return []

    category_counts: dict[str, int] = {}
    targets: list[str] = []
    techniques: list[str] = []
    parsed_dates: list[datetime] = []
    recent_90 = 0
    cutoff_90 = datetime.now(timezone.utc) - timedelta(days=90)

    for item in highlights:
        category = str(item.get('category') or '').strip().lower()
        if category:
            category_counts[category] = category_counts.get(category, 0) + 1

        target = str(item.get('target_text') or '').strip() or _extract_target_from_activity_text(
            str(item.get('text') or '')
        )
        if target and target not in targets:
            targets.append(target)

        ttp_csv = str(item.get('ttp_ids') or '').strip()
        if ttp_csv:
            for part in ttp_csv.split(','):
                token = part.strip().upper()
                if token and token not in techniques:
                    techniques.append(token)

        dt = _parse_published_datetime(str(item.get('date') or ''))
        if dt is not None:
            parsed_dates.append(dt)
            if dt >= cutoff_90:
                recent_90 += 1

    unique_sources = {
        str(item.get('source_url') or '').strip()
        for item in highlights
        if str(item.get('source_url') or '').strip()
    }
    lineage_count = len(unique_sources)
    if lineage_count >= 4 and recent_90 >= 2:
        confidence_label = 'High'
    elif lineage_count >= 2:
        confidence_label = 'Medium'
    else:
        confidence_label = 'Low'

    if parsed_dates:
        newest = max(parsed_dates).date().isoformat()
        oldest = min(parsed_dates).date().isoformat()
        what_changed = (
            f'Observed {len(highlights)} actor-linked signals between {oldest} and {newest}, '
            f'with {recent_90} in the last 90 days.'
        )
    else:
        what_changed = f'Observed {len(highlights)} actor-linked activity signals in current source coverage.'

    if category_counts:
        top_categories = sorted(category_counts.items(), key=lambda item: item[1], reverse=True)[:2]
        category_text = ', '.join(
            f'{name.replace("_", " ")} ({count})' for name, count in top_categories
        )
        what_changed = f'{what_changed} Primary behavior clusters: {category_text}.'

    who_affected = 'Affected organizations/entities are not clearly named in current reporting.'
    if targets:
        who_affected = f'Recently affected organizations/entities include: {", ".join(targets[:4])}.'

    action_parts: list[str] = []
    if techniques:
        action_parts.append(f'Prioritize detections for {", ".join(techniques[:5])}')
    if category_counts:
        dominant = sorted(category_counts.items(), key=lambda item: item[1], reverse=True)[0][0]
        action_parts.append(f'focus hunt workflows on {dominant.replace("_", " ")} behavior')
    if not action_parts:
        action_parts.append('continue actor-specific source collection and validate new events')
    what_to_do_next = 'Next analyst action: ' + '; '.join(action_parts) + '.'

    return [
        {
            'label': 'What changed',
            'text': what_changed,
            'confidence': confidence_label,
            'lineage': f'{lineage_count} sources',
        },
        {
            'label': 'Who is affected',
            'text': who_affected,
            'confidence': confidence_label,
            'lineage': f'{lineage_count} sources',
        },
        {
            'label': 'What to do next',
            'text': what_to_do_next,
            'confidence': confidence_label,
            'lineage': f'{lineage_count} sources',
        },
    ]


def _timeline_category_from_sentence(sentence: str) -> str | None:
    return timeline_extraction.timeline_category_from_sentence(sentence)


def _extract_major_move_events(
    source_name: str,
    source_id: str,
    occurred_at: str,
    text: str,
    actor_terms: list[str],
) -> list[dict[str, object]]:
    return timeline_extraction.extract_major_move_events(
        source_name,
        source_id,
        occurred_at,
        text,
        actor_terms,
        deps={
            'split_sentences': _split_sentences,
            'extract_ttp_ids': _extract_ttp_ids,
            'new_id': lambda: str(uuid.uuid4()),
        },
    )


def _guidance_for_platform(platform: str, question_text: str) -> dict[str, str | None]:
    return guidance_catalog.guidance_for_platform(platform, question_text)


def _platforms_for_question(question_text: str) -> list[str]:
    return guidance_catalog.platforms_for_question(question_text)


def _strip_html(value: str) -> str:
    return pipeline_strip_html(value)


def _extract_meta(content: str, key_patterns: list[str]) -> str | None:
    return pipeline_extract_meta(content, key_patterns)


def _fallback_title_from_url(source_url: str) -> str:
    return pipeline_fallback_title_from_url(source_url)


def _evidence_title_from_source(source: dict[str, object]) -> str:
    return pipeline_evidence_title_from_source(
        source,
        split_sentences=lambda text: _split_sentences(text),
        fallback_title=lambda url: _fallback_title_from_url(url),
    )


def _evidence_source_label_from_source(source: dict[str, object]) -> str:
    return pipeline_evidence_source_label_from_source(
        source,
        evidence_title=lambda item: _evidence_title_from_source(item),
    )


def _canonical_group_domain(source: dict[str, object]) -> str:
    return pipeline_canonical_group_domain(
        source,
        evidence_source_label=lambda item: _evidence_source_label_from_source(item),
    )


def _validate_outbound_url(source_url: str, allowed_domains: set[str] | None = None) -> str:
    effective_allowlist = OUTBOUND_ALLOWED_DOMAINS if allowed_domains is None else allowed_domains
    return validate_outbound_url(
        source_url,
        allowed_domains=effective_allowlist,
        resolve_host=socket.getaddrinfo,
        ipproto_tcp=socket.IPPROTO_TCP,
    )


def _safe_http_get(
    source_url: str,
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
    allowed_domains: set[str] | None = None,
    max_redirects: int = 3,
) -> httpx.Response:
    return safe_http_get(
        source_url,
        timeout=timeout,
        headers=headers,
        allowed_domains=allowed_domains,
        max_redirects=max_redirects,
        validate_url=lambda url, domains: _validate_outbound_url(url, allowed_domains=domains),
        http_get=httpx.get,
    )


def derive_source_from_url(source_url: str, fallback_source_name: str | None = None, published_hint: str | None = None) -> dict[str, str | None]:
    return pipeline_derive_source_from_url_core(
        source_url,
        fallback_source_name=fallback_source_name,
        published_hint=published_hint,
        deps={
            'safe_http_get': _safe_http_get,
            'extract_question_sentences': _extract_question_sentences,
            'first_sentences': _first_sentences,
        },
    )


def _parse_feed_entries(xml_text: str) -> list[dict[str, str | None]]:
    return source_ingest_service.parse_feed_entries_core(xml_text)


def _parse_published_datetime(value: str | None) -> datetime | None:
    return source_ingest_service.parse_published_datetime_core(value)


def _within_lookback(published_at: str | None, lookback_days: int) -> bool:
    return source_ingest_service.within_lookback_core(
        published_at=published_at,
        lookback_days=lookback_days,
    )


def _import_ransomware_live_actor_activity(
    connection: sqlite3.Connection,
    actor_id: str,
    actor_terms: list[str],
) -> int:
    return source_ingest_service.import_ransomware_live_actor_activity_core(
        connection=connection,
        actor_id=actor_id,
        actor_terms=actor_terms,
        deps={
            'http_get': httpx.get,
            'now_iso': utc_now_iso,
            'upsert_source_for_actor': _upsert_source_for_actor,
        },
    )


def _ollama_available() -> bool:
    return status_service.ollama_available_core(
        deps={
            'get_env': os.environ.get,
            'http_get': httpx.get,
        }
    )


def get_ollama_status() -> dict[str, str | bool]:
    return status_service.get_ollama_status_core(
        deps={
            'get_env': os.environ.get,
            'http_get': httpx.get,
        }
    )


def _ollama_generate_questions(actor_name: str, scope_statement: str | None, excerpts: list[str]) -> list[str]:
    if not excerpts or not _ollama_available():
        return []

    model = os.environ.get('OLLAMA_MODEL', 'llama3.1:8b')
    base_url = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434').rstrip('/')
    prompt = (
        'You are helping a cybersecurity analyst write practical intelligence questions. '
        'Return ONLY valid JSON with key "questions" as an array of short plain-language strings. '
        'Avoid military and intelligence-jargon phrasing. '
        'Use plain English a junior analyst can follow. '
        'Focus on what to verify next for defensive operations. '
        f'Actor: {actor_name}. Scope: {scope_statement or "n/a"}. '
        f'Evidence excerpts: {json.dumps(excerpts[:8])}'
    )

    payload = {
        'model': model,
        'prompt': prompt,
        'stream': False,
        'format': 'json',
    }
    try:
        response = httpx.post(f'{base_url}/api/generate', json=payload, timeout=20.0)
        response.raise_for_status()
        content = response.json().get('response', '{}')
        parsed = json.loads(content)
        questions = parsed.get('questions', []) if isinstance(parsed, dict) else []
        clean = [
            _sanitize_question_text(str(item))
            for item in questions
            if isinstance(item, str) and str(item).strip()
        ]
        clean = [item for item in clean if item]
        return clean[:6]
    except Exception:
        return []


def actor_exists(connection: sqlite3.Connection, actor_id: str) -> bool:
    return actor_profile_service.actor_exists_core(connection, actor_id)


def set_actor_notebook_status(actor_id: str, status: str, message: str) -> None:
    actor_profile_service.set_actor_notebook_status_core(
        actor_id=actor_id,
        status=status,
        message=message,
        deps={
            'db_path': lambda: DB_PATH,
            'utc_now_iso': utc_now_iso,
        },
    )


def _format_duration_ms(milliseconds: int | None) -> str:
    return status_service.format_duration_ms_core(milliseconds)


def _mark_actor_generation_started(actor_id: str) -> bool:
    return generation_service.mark_actor_generation_started_core(actor_id)


def _mark_actor_generation_finished(actor_id: str) -> None:
    generation_service.mark_actor_generation_finished_core(actor_id)


def run_actor_generation(actor_id: str) -> None:
    generation_service.run_actor_generation_core(
        actor_id=actor_id,
        deps={
            'mark_started': _mark_actor_generation_started,
            'mark_finished': _mark_actor_generation_finished,
            'pipeline_run_actor_generation_core': pipeline_run_actor_generation_core,
            'db_path': lambda: DB_PATH,
            'set_actor_notebook_status': set_actor_notebook_status,
            'import_default_feeds_for_actor': import_default_feeds_for_actor,
            'build_notebook': build_notebook,
        },
    )


def list_actor_profiles() -> list[dict[str, object]]:
    return actor_profile_service.list_actor_profiles_core(
        deps={
            'db_path': lambda: DB_PATH,
        }
    )


def create_actor_profile(
    display_name: str,
    scope_statement: str | None,
    is_tracked: bool = True,
) -> dict[str, str | None]:
    return actor_profile_service.create_actor_profile_core(
        display_name=display_name,
        scope_statement=scope_statement,
        is_tracked=is_tracked,
        deps={
            'db_path': lambda: DB_PATH,
            'new_id': lambda: str(uuid.uuid4()),
            'utc_now_iso': utc_now_iso,
        },
    )


def _upsert_source_for_actor(
    connection: sqlite3.Connection,
    actor_id: str,
    source_name: str,
    source_url: str,
    published_at: str | None,
    pasted_text: str,
    trigger_excerpt: str | None = None,
    title: str | None = None,
    headline: str | None = None,
    og_title: str | None = None,
    html_title: str | None = None,
    publisher: str | None = None,
    site_name: str | None = None,
) -> str:
    return source_store_service.upsert_source_for_actor_core(
        connection=connection,
        actor_id=actor_id,
        source_name=source_name,
        source_url=source_url,
        published_at=published_at,
        pasted_text=pasted_text,
        trigger_excerpt=trigger_excerpt,
        title=title,
        headline=headline,
        og_title=og_title,
        html_title=html_title,
        publisher=publisher,
        site_name=site_name,
        deps={
            'source_fingerprint': _source_fingerprint,
            'new_id': lambda: str(uuid.uuid4()),
            'now_iso': utc_now_iso,
        },
    )


def _parse_ioc_values(raw: str) -> list[str]:
    return source_ingest_service.parse_ioc_values_core(raw)


def _source_fingerprint(
    title: str | None,
    headline: str | None,
    og_title: str | None,
    html_title: str | None,
    pasted_text: str,
) -> str:
    return source_store_service.source_fingerprint_core(
        title=title,
        headline=headline,
        og_title=og_title,
        html_title=html_title,
        pasted_text=pasted_text,
        deps={
            'normalize_text': _normalize_text,
            'first_sentences': lambda text, count: _first_sentences(text, count=count),
        },
    )


def import_default_feeds_for_actor(actor_id: str) -> int:
    return pipeline_import_default_feeds_for_actor_core(
        actor_id,
        db_path=DB_PATH,
        default_cti_feeds=DEFAULT_CTI_FEEDS,
        actor_feed_lookback_days=ACTOR_FEED_LOOKBACK_DAYS,
        deps={
            'actor_exists': actor_exists,
            'build_actor_profile_from_mitre': _build_actor_profile_from_mitre,
            'actor_terms': _actor_terms,
            'actor_query_feeds': _actor_query_feeds,
            'import_ransomware_live_actor_activity': _import_ransomware_live_actor_activity,
            'safe_http_get': _safe_http_get,
            'parse_feed_entries': _parse_feed_entries,
            'text_contains_actor_term': _text_contains_actor_term,
            'within_lookback': _within_lookback,
            'derive_source_from_url': derive_source_from_url,
            'upsert_source_for_actor': _upsert_source_for_actor,
            'duckduckgo_actor_search_urls': _duckduckgo_actor_search_urls,
        },
    )


def generate_actor_requirements(actor_id: str, org_context: str, priority_mode: str) -> int:
    return pipeline_generate_actor_requirements_core(
        actor_id,
        org_context,
        priority_mode,
        db_path=DB_PATH,
        deps={
            'now_iso': utc_now_iso,
            'actor_exists': actor_exists,
            'build_actor_profile_from_mitre': _build_actor_profile_from_mitre,
            'actor_terms': _actor_terms,
            'split_sentences': _split_sentences,
            'sentence_mentions_actor_terms': _sentence_mentions_actor_terms,
            'looks_like_activity_sentence': _looks_like_activity_sentence,
            'ollama_available': _ollama_available,
            'sanitize_question_text': _sanitize_question_text,
            'question_from_sentence': _question_from_sentence,
            'token_overlap': _token_overlap,
            'normalize_text': _normalize_text,
            'new_id': lambda: str(uuid.uuid4()),
        },
    )


def build_notebook(
    actor_id: str,
    *,
    generate_questions: bool = True,
    rebuild_timeline: bool = True,
) -> None:
    build_notebook_core(
        actor_id,
        db_path=DB_PATH,
        generate_questions=generate_questions,
        rebuild_timeline=rebuild_timeline,
        now_iso=utc_now_iso,
        actor_exists=actor_exists,
        build_actor_profile_from_mitre=_build_actor_profile_from_mitre,
        actor_terms_fn=_actor_terms,
        extract_major_move_events=_extract_major_move_events,
        normalize_text=_normalize_text,
        token_overlap=_token_overlap,
        extract_question_sentences=_extract_question_sentences,
        sentence_mentions_actor_terms=_sentence_mentions_actor_terms,
        sanitize_question_text=_sanitize_question_text,
        question_from_sentence=_question_from_sentence,
        ollama_generate_questions=_ollama_generate_questions,
        platforms_for_question=_platforms_for_question,
        guidance_for_platform=_guidance_for_platform,
    )


def _fetch_actor_notebook(actor_id: str) -> dict[str, object]:
    return pipeline_fetch_actor_notebook_core(
        actor_id,
        db_path=DB_PATH,
        deps={
            'parse_published_datetime': _parse_published_datetime,
            'safe_json_string_list': _safe_json_string_list,
            'actor_signal_categories': _actor_signal_categories,
            'question_actor_relevance': _question_actor_relevance,
            'priority_update_evidence_dt': _priority_update_evidence_dt,
            'question_org_alignment': _question_org_alignment,
            'priority_rank_score': _priority_rank_score,
            'phase_label_for_question': _phase_label_for_question,
            'priority_where_to_check': _priority_where_to_check,
            'priority_confidence_label': _priority_confidence_label,
            'quick_check_title': _quick_check_title,
            'short_decision_trigger': _short_decision_trigger,
            'telemetry_anchor_line': _telemetry_anchor_line,
            'priority_next_best_action': _priority_next_best_action,
            'guidance_line': _guidance_line,
            'guidance_query_hint': _guidance_query_hint,
            'priority_disconfirming_signal': _priority_disconfirming_signal,
            'escalation_threshold_line': _escalation_threshold_line,
            'priority_update_recency_label': _priority_update_recency_label,
            'org_alignment_label': _org_alignment_label,
            'fallback_priority_questions': _fallback_priority_questions,
            'token_overlap': _token_overlap,
            'build_actor_profile_from_mitre': _build_actor_profile_from_mitre,
            'group_top_techniques': _group_top_techniques,
            'favorite_attack_vectors': _favorite_attack_vectors,
            'known_technique_ids_for_entity': _known_technique_ids_for_entity,
            'emerging_techniques_from_timeline': _emerging_techniques_from_timeline,
            'build_timeline_graph': _build_timeline_graph,
            'compact_timeline_rows': _compact_timeline_rows,
            'actor_terms': _actor_terms,
            'build_recent_activity_highlights': _build_recent_activity_highlights,
            'build_recent_activity_synthesis': _build_recent_activity_synthesis,
            'recent_change_summary': _recent_change_summary,
            'build_environment_checks': _build_environment_checks,
            'build_notebook_kpis': _build_notebook_kpis,
            'format_date_or_unknown': _format_date_or_unknown,
        },
    )


def initialize_sqlite() -> None:
    global DB_PATH
    DB_PATH = _resolve_startup_db_path()
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)
    mitre_store.clear_cache()
    global MITRE_GROUP_CACHE, MITRE_DATASET_CACHE, MITRE_TECHNIQUE_PHASE_CACHE
    global MITRE_SOFTWARE_CACHE, MITRE_CAMPAIGN_LINK_CACHE
    global MITRE_TECHNIQUE_INDEX_CACHE
    MITRE_GROUP_CACHE = None
    MITRE_DATASET_CACHE = None
    MITRE_TECHNIQUE_PHASE_CACHE = None
    MITRE_SOFTWARE_CACHE = None
    MITRE_CAMPAIGN_LINK_CACHE = None
    MITRE_TECHNIQUE_INDEX_CACHE = None
    _ensure_mitre_attack_dataset()
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS actor_profiles (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                scope_statement TEXT,
                created_at TEXT NOT NULL
            )
            '''
        )
        actor_cols = connection.execute('PRAGMA table_info(actor_profiles)').fetchall()
        if not any(col[1] == 'is_tracked' for col in actor_cols):
            connection.execute(
                "ALTER TABLE actor_profiles ADD COLUMN is_tracked INTEGER NOT NULL DEFAULT 0"
            )
        if not any(col[1] == 'notebook_status' for col in actor_cols):
            connection.execute(
                "ALTER TABLE actor_profiles ADD COLUMN notebook_status TEXT NOT NULL DEFAULT 'idle'"
            )
        if not any(col[1] == 'notebook_message' for col in actor_cols):
            connection.execute(
                "ALTER TABLE actor_profiles ADD COLUMN notebook_message TEXT NOT NULL DEFAULT 'Waiting for tracking action.'"
            )
        if not any(col[1] == 'notebook_updated_at' for col in actor_cols):
            connection.execute(
                "ALTER TABLE actor_profiles ADD COLUMN notebook_updated_at TEXT"
            )
        if not any(col[1] == 'last_refresh_duration_ms' for col in actor_cols):
            connection.execute(
                "ALTER TABLE actor_profiles ADD COLUMN last_refresh_duration_ms INTEGER"
            )
        if not any(col[1] == 'last_refresh_sources_processed' for col in actor_cols):
            connection.execute(
                "ALTER TABLE actor_profiles ADD COLUMN last_refresh_sources_processed INTEGER"
            )

        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS actor_state (
                actor_id TEXT PRIMARY KEY,
                capability_grid_json TEXT NOT NULL,
                behavioral_model_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            '''
        )
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS observation_records (
                id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_ref TEXT,
                source_date TEXT,
                ttp_json TEXT NOT NULL,
                tools_json TEXT NOT NULL,
                infra_json TEXT NOT NULL,
                targets_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            '''
        )
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS delta_proposals (
                id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                observation_id TEXT NOT NULL,
                delta_type TEXT NOT NULL,
                affected_category TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            '''
        )
        delta_columns = connection.execute('PRAGMA table_info(delta_proposals)').fetchall()
        if not any(column[1] == 'validation_template_json' for column in delta_columns):
            connection.execute(
                "ALTER TABLE delta_proposals ADD COLUMN validation_template_json TEXT NOT NULL DEFAULT '{}'"
            )

        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS state_transition_log (
                id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                delta_id TEXT NOT NULL,
                previous_state_json TEXT NOT NULL,
                new_state_json TEXT NOT NULL,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            '''
        )

        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS sources (
                id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                source_name TEXT NOT NULL,
                url TEXT NOT NULL,
                published_at TEXT,
                retrieved_at TEXT NOT NULL,
                pasted_text TEXT NOT NULL,
                source_fingerprint TEXT
            )
            '''
        )
        source_cols = connection.execute('PRAGMA table_info(sources)').fetchall()
        if not any(col[1] == 'source_fingerprint' for col in source_cols):
            connection.execute("ALTER TABLE sources ADD COLUMN source_fingerprint TEXT")
        if not any(col[1] == 'title' for col in source_cols):
            connection.execute("ALTER TABLE sources ADD COLUMN title TEXT")
        if not any(col[1] == 'headline' for col in source_cols):
            connection.execute("ALTER TABLE sources ADD COLUMN headline TEXT")
        if not any(col[1] == 'og_title' for col in source_cols):
            connection.execute("ALTER TABLE sources ADD COLUMN og_title TEXT")
        if not any(col[1] == 'html_title' for col in source_cols):
            connection.execute("ALTER TABLE sources ADD COLUMN html_title TEXT")
        if not any(col[1] == 'publisher' for col in source_cols):
            connection.execute("ALTER TABLE sources ADD COLUMN publisher TEXT")
        if not any(col[1] == 'site_name' for col in source_cols):
            connection.execute("ALTER TABLE sources ADD COLUMN site_name TEXT")
        connection.execute(
            '''
            CREATE INDEX IF NOT EXISTS idx_sources_actor_fingerprint
            ON sources(actor_id, source_fingerprint)
            '''
        )
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS timeline_events (
                id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                source_id TEXT,
                target_text TEXT NOT NULL DEFAULT '',
                ttp_ids_json TEXT NOT NULL DEFAULT '[]'
            )
            '''
        )
        timeline_cols = connection.execute('PRAGMA table_info(timeline_events)').fetchall()
        if not any(col[1] == 'target_text' for col in timeline_cols):
            connection.execute("ALTER TABLE timeline_events ADD COLUMN target_text TEXT NOT NULL DEFAULT ''")
        if not any(col[1] == 'ttp_ids_json' for col in timeline_cols):
            connection.execute("ALTER TABLE timeline_events ADD COLUMN ttp_ids_json TEXT NOT NULL DEFAULT '[]'")
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS question_threads (
                id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                question_text TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            '''
        )
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS question_updates (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                source_id TEXT NOT NULL,
                trigger_excerpt TEXT NOT NULL,
                update_note TEXT,
                created_at TEXT NOT NULL
            )
            '''
        )
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS environment_guidance (
                id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                thread_id TEXT,
                platform TEXT NOT NULL,
                what_to_look_for TEXT NOT NULL,
                where_to_look TEXT NOT NULL,
                query_hint TEXT,
                created_at TEXT NOT NULL
            )
            '''
        )
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS ioc_items (
                id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                source_ref TEXT,
                created_at TEXT NOT NULL
            )
            '''
        )
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS requirement_context (
                actor_id TEXT PRIMARY KEY,
                org_context TEXT NOT NULL DEFAULT '',
                priority_mode TEXT NOT NULL DEFAULT 'Operational',
                updated_at TEXT NOT NULL
            )
            '''
        )
        connection.execute(
            '''
            CREATE TABLE IF NOT EXISTS requirement_items (
                id TEXT PRIMARY KEY,
                actor_id TEXT NOT NULL,
                req_type TEXT NOT NULL,
                requirement_text TEXT NOT NULL,
                rationale_text TEXT NOT NULL,
                source_name TEXT,
                source_url TEXT,
                source_published_at TEXT,
                validation_score INTEGER NOT NULL DEFAULT 0,
                validation_notes TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL
            )
            '''
        )
        requirement_cols = connection.execute('PRAGMA table_info(requirement_items)').fetchall()
        if not any(col[1] == 'validation_score' for col in requirement_cols):
            connection.execute("ALTER TABLE requirement_items ADD COLUMN validation_score INTEGER NOT NULL DEFAULT 0")
        if not any(col[1] == 'validation_notes' for col in requirement_cols):
            connection.execute("ALTER TABLE requirement_items ADD COLUMN validation_notes TEXT NOT NULL DEFAULT ''")
        connection.commit()
app.include_router(
    routes_dashboard.create_dashboard_router(
        deps={
            'list_actor_profiles': list_actor_profiles,
            'fetch_actor_notebook': _fetch_actor_notebook,
            'set_actor_notebook_status': set_actor_notebook_status,
            'run_actor_generation': run_actor_generation,
            'get_ollama_status': get_ollama_status,
            'format_duration_ms': _format_duration_ms,
            'templates': templates,
        }
    )
)
app.include_router(
    routes_api.create_api_router(
        deps={
            'list_actor_profiles': list_actor_profiles,
            'enforce_request_size': _enforce_request_size,
            'default_body_limit_bytes': DEFAULT_BODY_LIMIT_BYTES,
            'create_actor_profile': create_actor_profile,
            'db_path': lambda: DB_PATH,
            'actor_exists': actor_exists,
            'set_actor_notebook_status': set_actor_notebook_status,
            'run_actor_generation': run_actor_generation,
        }
    )
)
app.include_router(
    routes_ui.create_ui_router(
        deps={
            'enforce_request_size': _enforce_request_size,
            'default_body_limit_bytes': DEFAULT_BODY_LIMIT_BYTES,
            'create_actor_profile': create_actor_profile,
            'set_actor_notebook_status': set_actor_notebook_status,
            'run_actor_generation': run_actor_generation,
            'list_actor_profiles': list_actor_profiles,
        }
    )
)
app.include_router(
    routes_actor_ops.create_actor_ops_router(
        deps={
            'enforce_request_size': _enforce_request_size,
            'source_upload_body_limit_bytes': SOURCE_UPLOAD_BODY_LIMIT_BYTES,
            'default_body_limit_bytes': DEFAULT_BODY_LIMIT_BYTES,
            'db_path': lambda: DB_PATH,
            'actor_exists': actor_exists,
            'derive_source_from_url': derive_source_from_url,
            'upsert_source_for_actor': _upsert_source_for_actor,
            'import_default_feeds_for_actor': import_default_feeds_for_actor,
            'parse_ioc_values': _parse_ioc_values,
            'utc_now_iso': utc_now_iso,
            'set_actor_notebook_status': set_actor_notebook_status,
            'run_actor_generation': run_actor_generation,
        }
    )
)
app.include_router(
    routes_notebook.create_notebook_router(
        deps={
            'enforce_request_size': _enforce_request_size,
            'default_body_limit_bytes': DEFAULT_BODY_LIMIT_BYTES,
            'generate_actor_requirements': generate_actor_requirements,
            'db_path': lambda: DB_PATH,
            'utc_now_iso': utc_now_iso,
            'safe_json_string_list': _safe_json_string_list,
            'fetch_actor_notebook': _fetch_actor_notebook,
            'templates': templates,
        }
    )
)
app.include_router(
    routes_evolution.create_evolution_router(
        deps={
            'enforce_request_size': _enforce_request_size,
            'observation_body_limit_bytes': OBSERVATION_BODY_LIMIT_BYTES,
            'default_body_limit_bytes': DEFAULT_BODY_LIMIT_BYTES,
            'db_path': lambda: DB_PATH,
            'actor_exists': actor_exists,
            'normalize_technique_id': _normalize_technique_id,
            'normalize_string_list': normalize_string_list,
            'utc_now_iso': utc_now_iso,
            'capability_category_from_technique_id': _capability_category_from_technique_id,
            'generate_validation_template': generate_validation_template,
            'baseline_entry': baseline_entry,
            'resolve_delta_action': lambda actor_id, delta_id, requested_action: resolve_delta_action(
                actor_id,
                delta_id,
                requested_action,
            ),
        }
    )
)


def actors_ui() -> str:
    return legacy_ui.render_actors_ui(
        actors=[
            {
                'id': actor['id'],
                'display_name': actor['display_name'],
            }
            for actor in list_actor_profiles()
        ]
    )


def root(
    request: Request,
    background_tasks: BackgroundTasks,
    actor_id: str | None = None,
    notice: str | None = None,
) -> HTMLResponse:
    return routes_dashboard.render_dashboard_root(
        request=request,
        background_tasks=background_tasks,
        actor_id=actor_id,
        notice=notice,
        deps={
            'list_actor_profiles': list_actor_profiles,
            'fetch_actor_notebook': _fetch_actor_notebook,
            'set_actor_notebook_status': set_actor_notebook_status,
            'run_actor_generation': run_actor_generation,
            'get_ollama_status': get_ollama_status,
            'format_duration_ms': _format_duration_ms,
            'templates': templates,
        },
    )


@app.post('/actors/{actor_id}/initialize')
def initialize_actor_state(actor_id: str) -> dict[str, str]:
    return actor_state_service.initialize_actor_state_core(
        actor_id=actor_id,
        deps={
            'utc_now_iso': utc_now_iso,
            'baseline_capability_grid': baseline_capability_grid,
            'baseline_behavioral_model': baseline_behavioral_model,
            'db_path': lambda: DB_PATH,
            'actor_exists': actor_exists,
        },
    )


def resolve_delta_action(actor_id: str, delta_id: str, requested_action: str) -> dict[str, str]:
    return actor_state_service.resolve_delta_action_core(
        actor_id=actor_id,
        delta_id=delta_id,
        requested_action=requested_action,
        deps={
            'utc_now_iso': utc_now_iso,
            'db_path': lambda: DB_PATH,
            'actor_exists': actor_exists,
            'baseline_entry': baseline_entry,
        },
    )
