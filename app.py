import json
import os
import re
import socket
import sqlite3
import string
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from urllib.parse import parse_qs, quote, urlparse

import httpx
import actor_state_service
import actor_profile_service
import guidance_catalog
import generation_service
import feed_import_service
import legacy_ui
import mitre_store
import db_schema_service
import activity_highlight_service
import analyst_text_service
import actor_search_service
import app_wiring_service
import priority_questions
import priority_service
import rate_limit_service
import recent_activity_service
import routes_api
import routes_actor_ops
import routes_dashboard
import routes_evolution
import routes_notebook
import routes_ui
import network_service
import notebook_service
import source_ingest_service
import source_derivation_service
import source_store_service
import requirements_service
import status_service
import timeline_extraction
import timeline_analytics_service
import timeline_view_service
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from feed_ingest import import_default_feeds_for_actor_core as pipeline_import_default_feeds_for_actor_core
from generation_runner import run_actor_generation_core as pipeline_run_actor_generation_core
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


def _reset_mitre_caches() -> None:
    global MITRE_GROUP_CACHE, MITRE_DATASET_CACHE, MITRE_TECHNIQUE_PHASE_CACHE
    global MITRE_SOFTWARE_CACHE, MITRE_CAMPAIGN_LINK_CACHE, MITRE_TECHNIQUE_INDEX_CACHE
    MITRE_GROUP_CACHE = None
    MITRE_DATASET_CACHE = None
    MITRE_TECHNIQUE_PHASE_CACHE = None
    MITRE_SOFTWARE_CACHE = None
    MITRE_CAMPAIGN_LINK_CACHE = None
    MITRE_TECHNIQUE_INDEX_CACHE = None


def _configure_mitre_store() -> None:
    mitre_store.configure(db_path=DB_PATH, attack_url=ATTACK_ENTERPRISE_STIX_URL)


def _with_mitre_store_sync(callback):
    _configure_mitre_store()
    _sync_mitre_cache_to_store()
    try:
        return callback()
    finally:
        _sync_mitre_cache_from_store()


def _request_body_limit_bytes(method: str, path: str) -> int:
    return rate_limit_service.request_body_limit_bytes_core(
        method,
        path,
        SOURCE_UPLOAD_BODY_LIMIT_BYTES,
        OBSERVATION_BODY_LIMIT_BYTES,
        DEFAULT_BODY_LIMIT_BYTES,
    )


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
    return rate_limit_service.rate_limit_bucket_core(
        method,
        path,
        RATE_LIMIT_HEAVY_PER_MINUTE,
        RATE_LIMIT_DEFAULT_PER_MINUTE,
    )


def _request_client_id(request: Request) -> str:
    return rate_limit_service.request_client_id_core(request)


def _prune_rate_limit_state(now: float) -> None:
    rate_limit_service.prune_rate_limit_state_core(
        now=now,
        rate_limit_state=_RATE_LIMIT_STATE,
        rate_limit_window_seconds=RATE_LIMIT_WINDOW_SECONDS,
    )


def _check_rate_limit(request: Request) -> tuple[bool, int, int]:
    global _RATE_LIMIT_REQUEST_COUNTER
    counter_ref = {'value': _RATE_LIMIT_REQUEST_COUNTER}
    limited, retry_after, limit = rate_limit_service.check_rate_limit_core(
        request,
        rate_limit_enabled=RATE_LIMIT_ENABLED,
        rate_limit_window_seconds=RATE_LIMIT_WINDOW_SECONDS,
        rate_limit_state=_RATE_LIMIT_STATE,
        rate_limit_lock=_RATE_LIMIT_LOCK,
        rate_limit_cleanup_every=_RATE_LIMIT_CLEANUP_EVERY,
        rate_limit_request_counter_ref=counter_ref,
        rate_limit_bucket=_rate_limit_bucket,
        request_client_id=_request_client_id,
        prune_rate_limit_state=_prune_rate_limit_state,
    )
    _RATE_LIMIT_REQUEST_COUNTER = int(counter_ref['value'])
    return (limited, retry_after, limit)


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


def _db_path() -> str:
    return DB_PATH


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
    _configure_mitre_store()
    path = Path(os.environ.get('MITRE_ATTACK_PATH', '').strip()) if os.environ.get('MITRE_ATTACK_PATH', '').strip() else None
    if path is not None:
        return path
    return Path(DB_PATH).resolve().parent / 'mitre_enterprise_attack.json'


def _ensure_mitre_attack_dataset() -> bool:
    return _with_mitre_store_sync(lambda: mitre_store.ensure_mitre_attack_dataset())


def _load_mitre_groups() -> list[dict[str, object]]:
    return _with_mitre_store_sync(lambda: mitre_store.load_mitre_groups())


def _load_mitre_dataset() -> dict[str, object]:
    return _with_mitre_store_sync(lambda: mitre_store.load_mitre_dataset())


def _mitre_campaign_link_index() -> dict[str, dict[str, set[str]]]:
    return _with_mitre_store_sync(lambda: mitre_store.mitre_campaign_link_index())


def _normalize_technique_id(value: str) -> str:
    return mitre_store.normalize_technique_id(value)


def _mitre_technique_index() -> dict[str, dict[str, str]]:
    return _with_mitre_store_sync(lambda: mitre_store.mitre_technique_index())


def _mitre_valid_technique_ids() -> set[str]:
    return _with_mitre_store_sync(lambda: mitre_store.mitre_valid_technique_ids())


def _mitre_technique_phase_index() -> dict[str, list[str]]:
    return _with_mitre_store_sync(lambda: mitre_store.mitre_technique_phase_index())


def _capability_category_from_technique_id(ttp_id: str) -> str | None:
    return _with_mitre_store_sync(
        lambda: mitre_store.capability_category_from_technique_id(
            ttp_id,
            attack_tactic_to_capability_map=ATTACK_TACTIC_TO_CAPABILITY_MAP,
            capability_grid_keys=CAPABILITY_GRID_KEYS,
        )
    )


def _match_mitre_group(actor_name: str) -> dict[str, object] | None:
    return _with_mitre_store_sync(lambda: mitre_store.match_mitre_group(actor_name))


def _load_mitre_software() -> list[dict[str, object]]:
    return _with_mitre_store_sync(lambda: mitre_store.load_mitre_software())


def _match_mitre_software(name: str) -> dict[str, object] | None:
    return _with_mitre_store_sync(lambda: mitre_store.match_mitre_software(name))

def _build_actor_profile_from_mitre(actor_name: str) -> dict[str, str]:
    return _with_mitre_store_sync(
        lambda: mitre_store.build_actor_profile_from_mitre(
            actor_name,
            first_sentences=lambda text, count: _first_sentences(text, count=count),
        )
    )


def _group_top_techniques(group_stix_id: str, limit: int = 6) -> list[dict[str, str]]:
    return _with_mitre_store_sync(lambda: mitre_store.group_top_techniques(group_stix_id, limit=limit))


def _known_technique_ids_for_entity(entity_stix_id: str) -> set[str]:
    return _with_mitre_store_sync(lambda: mitre_store.known_technique_ids_for_entity(entity_stix_id))


def _favorite_attack_vectors(techniques: list[dict[str, str]], limit: int = 3) -> list[str]:
    _configure_mitre_store()
    return mitre_store.favorite_attack_vectors(techniques, limit=limit)


def _emerging_techniques_from_timeline(
    timeline_items: list[dict[str, object]],
    known_technique_ids: set[str],
    limit: int = 5,
    min_distinct_sources: int = 2,
    min_event_count: int = 2,
) -> list[dict[str, object]]:
    return timeline_analytics_service.emerging_techniques_from_timeline_core(
        timeline_items,
        known_technique_ids,
        limit=limit,
        min_distinct_sources=min_distinct_sources,
        min_event_count=min_event_count,
        deps={
            'mitre_technique_index': _mitre_technique_index,
            'parse_published_datetime': _parse_published_datetime,
            'normalize_technique_id': _normalize_technique_id,
        },
    )


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
    return timeline_view_service.short_date_core(
        value,
        deps={
            'parse_published_datetime': _parse_published_datetime,
        },
    )


def _format_date_or_unknown(value: str) -> str:
    return timeline_view_service.format_date_or_unknown_core(
        value,
        deps={
            'parse_published_datetime': _parse_published_datetime,
        },
    )


def _freshness_badge(value: str | None) -> tuple[str, str]:
    return timeline_view_service.freshness_badge_core(
        value,
        deps={
            'parse_published_datetime': _parse_published_datetime,
        },
    )


def _bucket_label(value: str) -> str:
    return timeline_view_service.bucket_label_core(
        value,
        deps={
            'parse_iso_for_sort': _parse_iso_for_sort,
        },
    )


def _timeline_category_color(category: str) -> str:
    return timeline_view_service.timeline_category_color_core(category)


def _build_notebook_kpis(
    timeline_items: list[dict[str, object]],
    known_technique_ids: set[str],
    open_questions_count: int,
    sources: list[dict[str, object]],
) -> dict[str, str]:
    return timeline_analytics_service.build_notebook_kpis_core(
        timeline_items,
        known_technique_ids,
        open_questions_count,
        sources,
        deps={
            'parse_published_datetime': _parse_published_datetime,
            'mitre_valid_technique_ids': _mitre_valid_technique_ids,
        },
    )


def _build_timeline_graph(timeline_items: list[dict[str, object]]) -> list[dict[str, object]]:
    return timeline_analytics_service.build_timeline_graph_core(
        timeline_items,
        deps={
            'bucket_label': _bucket_label,
            'timeline_category_color': _timeline_category_color,
        },
    )


def _first_seen_for_techniques(
    timeline_items: list[dict[str, object]],
    technique_ids: list[str],
) -> list[dict[str, str]]:
    return timeline_analytics_service.first_seen_for_techniques_core(
        timeline_items,
        technique_ids,
        deps={
            'parse_published_datetime': _parse_published_datetime,
            'short_date': _short_date,
        },
    )


def _severity_label(category: str, target_text: str, novelty: bool) -> str:
    return timeline_analytics_service.severity_label_core(category, target_text, novelty)


def _action_text(category: str) -> str:
    return timeline_analytics_service.action_text_core(category)


def _compact_timeline_rows(
    timeline_items: list[dict[str, object]],
    known_technique_ids: set[str],
) -> list[dict[str, object]]:
    return timeline_analytics_service.compact_timeline_rows_core(
        timeline_items,
        known_technique_ids,
        parse_iso_for_sort=_parse_iso_for_sort,
        short_date=_short_date,
        action_text=_action_text,
        severity_label=_severity_label,
    )


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
    return priority_service.priority_where_to_check_core(
        guidance_items,
        question_text,
        deps={
            'priority_where_to_check': priority_questions.priority_where_to_check,
            'platforms_for_question': _platforms_for_question,
        },
    )


def _telemetry_anchor_line(guidance_items: list[dict[str, object]], question_text: str) -> str:
    return priority_service.telemetry_anchor_line_core(
        guidance_items,
        question_text,
        deps={
            'telemetry_anchor_line': priority_questions.telemetry_anchor_line,
            'platforms_for_question': _platforms_for_question,
        },
    )


def _guidance_query_hint(guidance_items: list[dict[str, object]], question_text: str) -> str:
    return priority_service.guidance_query_hint_core(
        guidance_items,
        question_text,
        deps={
            'guidance_query_hint': priority_questions.guidance_query_hint,
            'platforms_for_question': _platforms_for_question,
            'guidance_for_platform': _guidance_for_platform,
        },
    )


def _priority_update_evidence_dt(update: dict[str, object]) -> datetime | None:
    return priority_service.priority_update_evidence_dt_core(
        update,
        deps={
            'priority_update_evidence_dt': priority_questions.priority_update_evidence_dt,
            'parse_published_datetime': _parse_published_datetime,
        },
    )


def _question_org_alignment(question_text: str, org_context: str) -> int:
    return priority_service.question_org_alignment_core(
        question_text,
        org_context,
        deps={
            'question_org_alignment': priority_questions.question_org_alignment,
            'token_set': _token_set,
        },
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
    return actor_search_service.actor_terms_core(
        actor_name,
        mitre_group_name,
        aliases_csv,
        deps={
            'dedupe_actor_terms': _dedupe_actor_terms,
        },
    )


def _text_contains_actor_term(text: str, actor_terms: list[str]) -> bool:
    return actor_search_service.text_contains_actor_term_core(
        text,
        actor_terms,
        deps={
            'sentence_mentions_actor_terms': _sentence_mentions_actor_terms,
        },
    )


def _actor_query_feeds(actor_terms: list[str]) -> list[tuple[str, str]]:
    return actor_search_service.actor_query_feeds_core(actor_terms)


def _actor_search_queries(actor_terms: list[str]) -> list[str]:
    return actor_search_service.actor_search_queries_core(actor_terms)


def _domain_allowed_for_actor_search(url: str) -> bool:
    return actor_search_service.domain_allowed_for_actor_search_core(
        url,
        domains=ACTOR_SEARCH_DOMAINS,
    )


def _duckduckgo_actor_search_urls(actor_terms: list[str], limit: int = 20) -> list[str]:
    return actor_search_service.duckduckgo_actor_search_urls_core(
        actor_terms,
        limit=limit,
        deps={
            'actor_search_queries': _actor_search_queries,
            'http_get': httpx.get,
            'domain_allowed_for_actor_search': _domain_allowed_for_actor_search,
            're_finditer': re.finditer,
        },
    )


def _sentence_mentions_actor(sentence: str, actor_name: str) -> bool:
    return analyst_text_service.sentence_mentions_actor_core(
        sentence,
        actor_name,
        deps={
            're_findall': re.findall,
        },
    )


def _looks_like_navigation_noise(sentence: str) -> bool:
    return analyst_text_service.looks_like_navigation_noise_core(sentence)


def _build_actor_profile_summary(actor_name: str, source_texts: list[str]) -> str:
    return analyst_text_service.build_actor_profile_summary_core(
        actor_name,
        source_texts,
        deps={
            'split_sentences': _split_sentences,
            'looks_like_navigation_noise': _looks_like_navigation_noise,
            'sentence_mentions_actor': _sentence_mentions_actor,
            'normalize_text': _normalize_text,
            'token_overlap': _token_overlap,
        },
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

    return activity_highlight_service.build_recent_activity_highlights_core(
        timeline_items,
        sources,
        actor_terms,
        deps={
            'pipeline_build_recent_activity_highlights': pipeline_build_recent_activity_highlights,
            'trusted_activity_domains': TRUSTED_ACTIVITY_DOMAINS,
            'source_domain': _source_domain,
            'canonical_group_domain': _canonical_group_domain,
            'looks_like_activity_sentence': _looks_like_activity_sentence,
            'sentence_mentions_actor_terms': _sentence_mentions_actor_terms,
            'text_contains_actor_term': _text_contains_actor_term,
            'normalize_text': _normalize_text,
            'parse_published_datetime': _parse_published_datetime,
            'freshness_badge': _freshness_badge,
            'evidence_title_from_source': _evidence_title_from_source,
            'fallback_title_from_url': _fallback_title_from_url,
            'evidence_source_label_from_source': _evidence_source_label_from_source,
            'extract_ttp_ids': _extract_ttp_ids,
            'split_sentences': _split_sentences,
            'looks_like_navigation_noise': _looks_like_navigation_noise,
            'format_date_or_unknown': _format_date_or_unknown,
        },
    )


def _extract_target_from_activity_text(text: str) -> str:
    return timeline_extraction.extract_target_from_activity_text(text)


def _build_recent_activity_synthesis(
    highlights: list[dict[str, str | None]],
) -> list[dict[str, str]]:
    return recent_activity_service.build_recent_activity_synthesis_core(
        highlights,
        deps={
            'extract_target_from_activity_text': _extract_target_from_activity_text,
            'parse_published_datetime': _parse_published_datetime,
        },
    )


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
    return network_service.validate_outbound_url_core(
        source_url,
        allowed_domains=allowed_domains,
        deps={
            'outbound_allowed_domains': OUTBOUND_ALLOWED_DOMAINS,
        },
    )


def _safe_http_get(
    source_url: str,
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
    allowed_domains: set[str] | None = None,
    max_redirects: int = 3,
) -> httpx.Response:
    return network_service.safe_http_get_core(
        source_url,
        timeout=timeout,
        headers=headers,
        allowed_domains=allowed_domains,
        max_redirects=max_redirects,
        deps={
            'validate_url': lambda url, domains: _validate_outbound_url(url, allowed_domains=domains),
        },
    )


def derive_source_from_url(source_url: str, fallback_source_name: str | None = None, published_hint: str | None = None) -> dict[str, str | None]:
    return source_derivation_service.derive_source_from_url_core(
        source_url,
        fallback_source_name=fallback_source_name,
        published_hint=published_hint,
        deps={
            'pipeline_derive_source_from_url_core': pipeline_derive_source_from_url_core,
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
    return analyst_text_service.ollama_generate_questions_core(
        actor_name,
        scope_statement,
        excerpts,
        deps={
            'ollama_available': _ollama_available,
            'get_env': os.environ.get,
            'http_post': httpx.post,
            'sanitize_question_text': _sanitize_question_text,
        },
    )


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
    return feed_import_service.import_default_feeds_for_actor_core(
        actor_id=actor_id,
        deps={
            'pipeline_import_default_feeds_for_actor_core': pipeline_import_default_feeds_for_actor_core,
            'db_path': lambda: DB_PATH,
            'default_cti_feeds': DEFAULT_CTI_FEEDS,
            'actor_feed_lookback_days': ACTOR_FEED_LOOKBACK_DAYS,
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
    return requirements_service.generate_actor_requirements_core(
        actor_id=actor_id,
        org_context=org_context,
        priority_mode=priority_mode,
        deps={
            'pipeline_generate_actor_requirements_core': pipeline_generate_actor_requirements_core,
            'db_path': lambda: DB_PATH,
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
    notebook_service.build_notebook_wrapper_core(
        actor_id=actor_id,
        generate_questions=generate_questions,
        rebuild_timeline=rebuild_timeline,
        deps={
            'build_notebook_core': build_notebook_core,
            'db_path': lambda: DB_PATH,
            'now_iso': utc_now_iso,
            'actor_exists': actor_exists,
            'build_actor_profile_from_mitre': _build_actor_profile_from_mitre,
            'actor_terms_fn': _actor_terms,
            'extract_major_move_events': _extract_major_move_events,
            'normalize_text': _normalize_text,
            'token_overlap': _token_overlap,
            'extract_question_sentences': _extract_question_sentences,
            'sentence_mentions_actor_terms': _sentence_mentions_actor_terms,
            'sanitize_question_text': _sanitize_question_text,
            'question_from_sentence': _question_from_sentence,
            'ollama_generate_questions': _ollama_generate_questions,
            'platforms_for_question': _platforms_for_question,
            'guidance_for_platform': _guidance_for_platform,
        },
    )


def _fetch_actor_notebook(actor_id: str) -> dict[str, object]:
    return notebook_service.fetch_actor_notebook_wrapper_core(
        actor_id=actor_id,
        deps=_fetch_actor_notebook_deps(),
    )


def _fetch_actor_notebook_deps() -> dict[str, object]:
    return {
        'pipeline_fetch_actor_notebook_core': pipeline_fetch_actor_notebook_core,
        'db_path': _db_path,
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
    }


def _initialize_sqlite_deps() -> dict[str, object]:
    return {
        'resolve_startup_db_path': _resolve_startup_db_path,
        'configure_mitre_store': lambda db_path: mitre_store.configure(
            db_path=db_path,
            attack_url=ATTACK_ENTERPRISE_STIX_URL,
        ),
        'clear_mitre_store_cache': mitre_store.clear_cache,
        'reset_app_mitre_caches': _reset_mitre_caches,
        'ensure_mitre_attack_dataset': _ensure_mitre_attack_dataset,
        'sqlite_connect': sqlite3.connect,
    }


def initialize_sqlite() -> None:
    global DB_PATH
    DB_PATH = db_schema_service.initialize_sqlite_core(deps=_initialize_sqlite_deps())


def _register_routers() -> None:
    app_wiring_service.register_routers(
        app,
        deps={
            'routes_dashboard': routes_dashboard,
            'routes_api': routes_api,
            'routes_ui': routes_ui,
            'routes_actor_ops': routes_actor_ops,
            'routes_notebook': routes_notebook,
            'routes_evolution': routes_evolution,
            'list_actor_profiles': list_actor_profiles,
            'fetch_actor_notebook': _fetch_actor_notebook,
            'set_actor_notebook_status': set_actor_notebook_status,
            'run_actor_generation': run_actor_generation,
            'get_ollama_status': get_ollama_status,
            'format_duration_ms': _format_duration_ms,
            'templates': templates,
            'enforce_request_size': _enforce_request_size,
            'default_body_limit_bytes': DEFAULT_BODY_LIMIT_BYTES,
            'create_actor_profile': create_actor_profile,
            'db_path': _db_path,
            'actor_exists': actor_exists,
            'source_upload_body_limit_bytes': SOURCE_UPLOAD_BODY_LIMIT_BYTES,
            'derive_source_from_url': derive_source_from_url,
            'upsert_source_for_actor': _upsert_source_for_actor,
            'import_default_feeds_for_actor': import_default_feeds_for_actor,
            'parse_ioc_values': _parse_ioc_values,
            'utc_now_iso': utc_now_iso,
            'generate_actor_requirements': generate_actor_requirements,
            'safe_json_string_list': _safe_json_string_list,
            'observation_body_limit_bytes': OBSERVATION_BODY_LIMIT_BYTES,
            'normalize_technique_id': _normalize_technique_id,
            'normalize_string_list': normalize_string_list,
            'capability_category_from_technique_id': _capability_category_from_technique_id,
            'generate_validation_template': generate_validation_template,
            'baseline_entry': baseline_entry,
            'resolve_delta_action': lambda actor_id, delta_id, requested_action: resolve_delta_action(
                actor_id,
                delta_id,
                requested_action,
            ),
        },
    )


_register_routers()


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
