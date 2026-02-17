import html
import ipaddress
import json
import os
import re
import socket
import sqlite3
import string
import time
import uuid
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from threading import Lock
from urllib.parse import parse_qs, quote, quote_plus, urljoin, urlparse

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates


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
TTP_CATEGORY_MAP = {
    'T1059': 'execution',
    'T1547': 'persistence',
    'T1566': 'initial_access',
    'T1021': 'lateral_movement',
    'T1071': 'command_and_control',
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


def _mitre_dataset_path() -> Path:
    configured = os.environ.get('MITRE_ATTACK_PATH', '').strip()
    if configured:
        return Path(configured)
    return Path(DB_PATH).resolve().parent / 'mitre_enterprise_attack.json'


def _ensure_mitre_attack_dataset() -> bool:
    dataset_path = _mitre_dataset_path()
    if dataset_path.exists() and dataset_path.stat().st_size > 0:
        return True

    dataset_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        response = httpx.get(ATTACK_ENTERPRISE_STIX_URL, timeout=45.0, follow_redirects=True)
        response.raise_for_status()
        parsed = response.json()
        objects = parsed.get('objects')
        if not isinstance(objects, list):
            return False
        dataset_path.write_text(json.dumps(parsed), encoding='utf-8')
        return True
    except Exception:
        return False


def _load_mitre_groups() -> list[dict[str, object]]:
    global MITRE_GROUP_CACHE
    if MITRE_GROUP_CACHE is not None:
        return MITRE_GROUP_CACHE

    dataset_path = _mitre_dataset_path()
    if not dataset_path.exists():
        MITRE_GROUP_CACHE = []
        return MITRE_GROUP_CACHE

    parsed = _load_mitre_dataset()
    if not parsed:
        MITRE_GROUP_CACHE = []
        return MITRE_GROUP_CACHE

    groups: list[dict[str, object]] = []
    for obj in parsed.get('objects', []):
        if not isinstance(obj, dict):
            continue
        if obj.get('type') != 'intrusion-set':
            continue
        if bool(obj.get('revoked')) or bool(obj.get('x_mitre_deprecated')):
            continue

        name = str(obj.get('name') or '').strip()
        description = str(obj.get('description') or '').strip()
        aliases = [str(alias).strip() for alias in obj.get('aliases', []) if str(alias).strip()]
        ext_refs = obj.get('external_references', [])
        attack_id: str | None = None
        attack_url: str | None = None
        if isinstance(ext_refs, list):
            for ref in ext_refs:
                if not isinstance(ref, dict):
                    continue
                source_name = str(ref.get('source_name') or '')
                external_id = str(ref.get('external_id') or '')
                ref_url = str(ref.get('url') or '')
                if source_name == 'mitre-attack' and external_id.startswith('G'):
                    attack_id = external_id
                    attack_url = ref_url or f'https://attack.mitre.org/groups/{external_id}/'
                    break

        search_keys = {_normalize_actor_key(name)}
        for alias in aliases:
            search_keys.add(_normalize_actor_key(alias))

        groups.append(
            {
                'stix_id': str(obj.get('id') or ''),
                'name': name,
                'description': description,
                'aliases': aliases,
                'attack_id': attack_id,
                'attack_url': attack_url,
                'search_keys': search_keys,
            }
        )

    MITRE_GROUP_CACHE = groups
    return groups


def _load_mitre_dataset() -> dict[str, object]:
    global MITRE_DATASET_CACHE
    if MITRE_DATASET_CACHE is not None:
        return MITRE_DATASET_CACHE

    dataset_path = _mitre_dataset_path()
    if not dataset_path.exists():
        MITRE_DATASET_CACHE = {}
        return MITRE_DATASET_CACHE

    try:
        parsed = json.loads(dataset_path.read_text(encoding='utf-8'))
        if not isinstance(parsed, dict):
            parsed = {}
    except Exception:
        parsed = {}

    MITRE_DATASET_CACHE = parsed
    return MITRE_DATASET_CACHE


def _match_mitre_group(actor_name: str) -> dict[str, object] | None:
    actor_key = _normalize_actor_key(actor_name)
    if not actor_key:
        return None

    groups = _load_mitre_groups()
    for group in groups:
        if actor_key in group['search_keys']:
            return group

    actor_tokens = set(actor_key.split())
    if not actor_tokens:
        return None

    best: dict[str, object] | None = None
    best_score = 0.0
    for group in groups:
        group_tokens = set(_normalize_actor_key(str(group['name'])).split())
        if not group_tokens:
            continue
        overlap = len(actor_tokens.intersection(group_tokens)) / len(actor_tokens.union(group_tokens))
        if overlap > best_score:
            best_score = overlap
            best = group
    if best is not None and best_score >= 0.6:
        return best
    return None

MITRE_SOFTWARE_CACHE: list[dict[str, object]] | None = None


def _load_mitre_software() -> list[dict[str, object]]:
    """Load ATT&CK Software (malware + tool) entries for name matching."""
    global MITRE_SOFTWARE_CACHE
    if MITRE_SOFTWARE_CACHE is not None:
        return MITRE_SOFTWARE_CACHE

    dataset_path = _mitre_dataset_path()
    if not dataset_path.exists():
        MITRE_SOFTWARE_CACHE = []
        return MITRE_SOFTWARE_CACHE

    parsed = _load_mitre_dataset()
    if not parsed or not isinstance(parsed, dict):
        MITRE_SOFTWARE_CACHE = []
        return MITRE_SOFTWARE_CACHE

    software: list[dict[str, object]] = []
    for obj in parsed.get("objects", []):
        if not isinstance(obj, dict):
            continue

        obj_type = str(obj.get("type") or "")
        if obj_type not in {"malware", "tool"}:
            continue

        if bool(obj.get("revoked")) or bool(obj.get("x_mitre_deprecated")):
            continue

        name = str(obj.get("name") or "").strip()
        if not name:
            continue

        description = str(obj.get("description") or "").strip()

        # aliases for software are commonly in x_mitre_aliases
        aliases: list[str] = []
        x_aliases = obj.get("x_mitre_aliases", [])
        if isinstance(x_aliases, list):
            aliases = [str(a).strip() for a in x_aliases if str(a).strip()]

        attack_id: str | None = None
        attack_url: str | None = None
        ext_refs = obj.get("external_references", [])
        if isinstance(ext_refs, list):
            for ref in ext_refs:
                if not isinstance(ref, dict):
                    continue
                if str(ref.get("source_name") or "") != "mitre-attack":
                    continue
                external_id = str(ref.get("external_id") or "")
                if external_id.startswith("S"):
                    attack_id = external_id
                    attack_url = str(ref.get("url") or "").strip()
                    if not attack_url:
                        attack_url = f"https://attack.mitre.org/software/{external_id}/"
                    break

        search_keys = {_normalize_actor_key(name)}
        for alias in aliases:
            search_keys.add(_normalize_actor_key(alias))

        software.append(
            {
                "stix_id": str(obj.get("id") or ""),
                "type": obj_type,  # malware/tool
                "name": name,
                "description": description,
                "aliases": aliases,
                "attack_id": attack_id,
                "attack_url": attack_url,
                "search_keys": search_keys,
            }
        )

    MITRE_SOFTWARE_CACHE = software
    return MITRE_SOFTWARE_CACHE


def _match_mitre_software(name: str) -> dict[str, object] | None:
    actor_key = _normalize_actor_key(name)
    if not actor_key:
        return None

    items = _load_mitre_software()

    # exact match first
    for it in items:
        if actor_key in it["search_keys"]:
            return it

    # fuzzy fallback
    actor_tokens = set(actor_key.split())
    if not actor_tokens:
        return None

    best = None
    best_score = 0.0
    for it in items:
        nkey = _normalize_actor_key(str(it.get("name") or ""))
        it_tokens = set(nkey.split())
        if not it_tokens:
            continue
        overlap = len(actor_tokens & it_tokens) / len(actor_tokens | it_tokens)
        if overlap > best_score:
            best_score = overlap
            best = it

    if best is not None and best_score >= 0.6:
        return best
    return None

def _build_actor_profile_from_mitre(actor_name: str) -> dict[str, str]:
    group = _match_mitre_group(actor_name)
    if group is None:
        sw = _match_mitre_software(actor_name)
        if sw is None:
            return {
                'summary': (
                    f'No MITRE ATT&CK entry found for "{actor_name}". '
                    'Try the exact name used in ATT&CK (group or software).'
                ),
                'source_label': 'MITRE ATT&CK Enterprise',
                'source_url': 'https://attack.mitre.org/',
                'group_name': actor_name,
                'aliases_csv': '',
            }

        description = str(sw.get('description') or '').strip()
        description = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', description)
        description = re.sub(r'\(Citation:[^)]+\)', '', description, flags=re.IGNORECASE)
        description = re.sub(r'\s{2,}', ' ', description).strip()
        if description:
            summary = _first_sentences(description, count=3)
        else:
            summary = f'MITRE ATT&CK has a software record for {sw["name"]}, but no description text was available.'

        source_url = str(sw.get('attack_url') or 'https://attack.mitre.org/software/')
        attack_id = str(sw.get('attack_id') or '').strip()
        return {
            'summary': summary,
            'source_label': f'MITRE ATT&CK Software {attack_id}'.strip(),
            'source_url': source_url,
            'group_name': str(sw.get('name') or actor_name),
            'stix_id': str(sw.get('stix_id') or ''),
            'aliases_csv': ', '.join(str(alias) for alias in sw.get('aliases', []) if str(alias).strip()),
        }


    description = str(group.get('description') or '').strip()
    description = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', description)
    description = re.sub(r'\(Citation:[^)]+\)', '', description, flags=re.IGNORECASE)
    description = re.sub(r'\s{2,}', ' ', description).strip()
    if description:
        summary = _first_sentences(description, count=3)
    else:
        summary = f'MITRE ATT&CK has a group record for {group["name"]}, but no description text was available.'

    source_url = str(group.get('attack_url') or 'https://attack.mitre.org/groups/')
    return {
        'summary': summary,
        'source_label': f'MITRE ATT&CK {group.get("attack_id") or ""}'.strip(),
        'source_url': source_url,
        'group_name': str(group.get('name') or actor_name),
        'stix_id': str(group.get('stix_id') or ''),
        'aliases_csv': ', '.join(str(alias) for alias in group.get('aliases', []) if str(alias).strip()),
    }


def _group_top_techniques(group_stix_id: str, limit: int = 6) -> list[dict[str, str]]:
    if not group_stix_id:
        return []

    dataset = _load_mitre_dataset()
    objects = dataset.get('objects', []) if isinstance(dataset, dict) else []
    if not isinstance(objects, list):
        return []

    attack_patterns: dict[str, dict[str, object]] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get('type') != 'attack-pattern':
            continue
        if bool(obj.get('revoked')) or bool(obj.get('x_mitre_deprecated')):
            continue
        attack_patterns[str(obj.get('id') or '')] = obj

    counts: dict[str, int] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get('type') != 'relationship':
            continue
        if obj.get('relationship_type') != 'uses':
            continue
        if str(obj.get('source_ref') or '') != group_stix_id:
            continue
        target_ref = str(obj.get('target_ref') or '')
        if target_ref in attack_patterns:
            counts[target_ref] = counts.get(target_ref, 0) + 1

    ranked: list[tuple[str, int]] = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    results: list[dict[str, str]] = []
    for attack_pattern_id, _ in ranked:
        attack_obj = attack_patterns.get(attack_pattern_id, {})
        name = str(attack_obj.get('name') or '').strip()
        if not name:
            continue

        technique_id = ''
        technique_url = ''
        refs = attack_obj.get('external_references', [])
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                external_id = str(ref.get('external_id') or '')
                if external_id.startswith('T'):
                    technique_id = external_id
                    technique_url = str(ref.get('url') or '')
                    break
        if technique_id and not technique_url:
            technique_url = f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}/'

        phase = ''
        phases = attack_obj.get('kill_chain_phases', [])
        if isinstance(phases, list) and phases:
            first = phases[0]
            if isinstance(first, dict):
                phase = str(first.get('phase_name') or '').replace('-', ' ')

        results.append(
            {
                'technique_id': technique_id,
                'name': name,
                'phase': phase,
                'technique_url': technique_url,
            }
        )
        if len(results) >= limit:
            break
    return results


def _favorite_attack_vectors(techniques: list[dict[str, str]], limit: int = 3) -> list[str]:
    phase_counts: dict[str, int] = {}
    for item in techniques:
        phase = str(item.get('phase') or '').strip().lower()
        if not phase:
            continue
        phase_counts[phase] = phase_counts.get(phase, 0) + 1
    ranked = sorted(phase_counts.items(), key=lambda entry: entry[1], reverse=True)
    return [phase.replace('_', ' ') for phase, _ in ranked[:limit]]


def _emerging_technique_ids_from_timeline(
    timeline_items: list[dict[str, object]],
    known_technique_ids: set[str],
    limit: int = 5,
) -> list[str]:
    observed: list[str] = []
    for item in sorted(timeline_items, key=lambda entry: str(entry.get('occurred_at') or ''), reverse=True):
        for technique_id in item.get('ttp_ids', []):
            tid = str(technique_id).upper()
            if tid in known_technique_ids:
                continue
            if tid not in observed:
                observed.append(tid)
            if len(observed) >= limit:
                return observed
    return observed


def _extract_ttp_ids(text: str) -> list[str]:
    matches = re.findall(r'\bT\d{4}(?:\.\d{3})?\b', text, flags=re.IGNORECASE)
    deduped: list[str] = []
    for value in matches:
        norm = value.upper()
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
    dt = _parse_iso_for_sort(value)
    if dt == datetime.min.replace(tzinfo=timezone.utc):
        return value[:10]
    return dt.strftime('%Y-%m-%d')


def _format_date_or_unknown(value: str) -> str:
    dt = _parse_published_datetime(value)
    if dt is None:
        return 'Unknown'
    return dt.date().isoformat()


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

    activity_30d = 0
    novel_techniques_30d: set[str] = set()
    for item in timeline_items:
        dt = _parse_published_datetime(str(item.get('occurred_at') or ''))
        if dt is None or dt < cutoff_30:
            continue
        activity_30d += 1
        for ttp in item.get('ttp_ids', []):
            tid = str(ttp).upper()
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
    for item in sorted(timeline_items, key=lambda entry: _parse_iso_for_sort(str(entry.get('occurred_at') or ''))):
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


def _question_priority_score(thread: dict[str, object]) -> int:
    text = str(thread.get('question_text') or '').lower()
    updates = thread.get('updates', [])
    update_count = len(updates) if isinstance(updates, list) else 0
    score = 1 + min(update_count, 4)
    high_tokens = (
        'exfiltrat',
        'impact',
        'ransom',
        'critical',
        'c2',
        'command-and-control',
        'lateral',
        'domain admin',
        'data theft',
    )
    medium_tokens = ('execution', 'persistence', 'phish', 'initial access', 'credential', 'vpn', 'exploit')
    if any(token in text for token in high_tokens):
        score += 3
    elif any(token in text for token in medium_tokens):
        score += 2
    else:
        score += 1
    return score


def _question_category_hints(question_text: str) -> set[str]:
    lowered = question_text.lower()
    hints: set[str] = set()
    if any(token in lowered for token in ('phish', 'email', 'exploit', 'vpn', 'edge', 'initial access')):
        hints.add('initial_access')
    if any(token in lowered for token in ('powershell', 'wmi', 'execution', 'command line')):
        hints.add('execution')
    if any(token in lowered for token in ('scheduled task', 'startup', 'persistence')):
        hints.add('persistence')
    if any(token in lowered for token in ('lateral', 'rdp', 'smb')):
        hints.add('lateral_movement')
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon', 'command-and-control')):
        hints.add('command_and_control')
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection')):
        hints.add('exfiltration')
    if any(token in lowered for token in ('encrypt', 'ransom', 'impact', 'disrupt')):
        hints.add('impact')
    return hints


def _actor_signal_categories(timeline_items: list[dict[str, object]]) -> set[str]:
    categories: set[str] = set()
    for item in timeline_items:
        category = str(item.get('category') or '').strip()
        if category:
            categories.add(category)
    return categories


def _question_actor_relevance(question_text: str, actor_categories: set[str], signal_text: str) -> int:
    hints = _question_category_hints(question_text)
    if not hints:
        return 1
    overlap = len(hints.intersection(actor_categories))
    if overlap >= 2:
        return 4
    if overlap == 1:
        return 3
    lowered = question_text.lower()
    if any(token in signal_text for token in re.findall(r'[a-z0-9]{4,}', lowered)):
        return 2
    return 0


def _fallback_priority_questions(actor_name: str, actor_categories: set[str]) -> list[dict[str, str]]:
    catalog: list[dict[str, str]] = []
    if 'initial_access' in actor_categories:
        catalog.append(
            {
                'question_text': 'Which exposed internet-facing systems need emergency hardening in the next 24 hours?',
                'priority': 'High',
                'know_focus': f'{actor_name} activity frequently begins through exposed edge assets and weak external auth.',
                'hunt_focus': 'Hunt exploit attempts on edge assets and unusual VPN authentication patterns.',
                'decision_to_inform': 'Decide which external assets get immediate patching, MFA enforcement, or temporary exposure reduction.',
                'where_to_check': 'Firewall/VPN, EDR',
                'time_horizon': 'Next 24 hours',
                'confidence': 'Medium',
                'disconfirming_signal': 'No suspicious edge exploitation or anomalous external auth across critical assets.',
            }
        )
    if 'impact' in actor_categories or 'exfiltration' in actor_categories:
        catalog.append(
            {
                'question_text': 'Which critical systems show signs of ransomware staging or high-risk data theft right now?',
                'priority': 'High',
                'know_focus': f'{actor_name} reporting includes high-impact disruption and/or data theft patterns.',
                'hunt_focus': 'Hunt mass file changes, backup tampering, suspicious archiving, and large outbound transfers.',
                'decision_to_inform': 'Decide whether to trigger incident response containment for specific systems or business units.',
                'where_to_check': 'EDR, Windows Event Logs, DNS/Proxy',
                'time_horizon': 'Current shift',
                'confidence': 'Medium',
                'disconfirming_signal': 'No backup tampering, suspicious archiving, or abnormal outbound transfer patterns.',
            }
        )
    if 'command_and_control' in actor_categories or 'lateral_movement' in actor_categories:
        catalog.append(
            {
                'question_text': 'Which hosts are likely pivot points that should be segmented or isolated first?',
                'priority': 'Medium',
                'know_focus': 'Recent signals suggest internal movement or remote control activity.',
                'hunt_focus': 'Hunt beacon-like traffic and unusual remote-service authentication between hosts.',
                'decision_to_inform': 'Decide which host pairs or segments need immediate containment and credential hygiene actions.',
                'where_to_check': 'DNS/Proxy, Windows Event Logs',
                'time_horizon': 'Next 72 hours',
                'confidence': 'Low',
                'disconfirming_signal': 'No sustained beaconing patterns or abnormal internal remote-service authentication.',
            }
        )
    if not catalog:
        catalog.append(
            {
                'question_text': 'What evidence would justify escalating from monitoring to active incident response?',
                'priority': 'Medium',
                'know_focus': f'{actor_name} reporting is limited, so escalation thresholds must rely on concrete local evidence.',
                'hunt_focus': 'Hunt for corroborating endpoint and network alerts tied to actor-reported techniques.',
                'decision_to_inform': 'Decide escalation threshold for incident declaration and responder activation.',
                'where_to_check': 'EDR, Windows Event Logs, DNS/Proxy',
                'time_horizon': 'This week',
                'confidence': 'Low',
                'disconfirming_signal': 'No corroborating endpoint/network evidence linked to reported tradecraft.',
            }
        )
    return catalog[:3]


def _priority_know_focus(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('phish', 'email')):
        return 'This actor may be using phishing/email delivery right now.'
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit')):
        return 'This actor may be exploiting internet-facing systems for entry.'
    if any(token in lowered for token in ('powershell', 'wmi', 'scheduled task', 'execution')):
        return 'This actor may be executing payloads on endpoints.'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon')):
        return 'This actor may be using C2/beacon traffic for control.'
    if any(token in lowered for token in ('hash', 'file', 'process', 'command line')):
        return 'This actor may leave endpoint file/process artifacts.'
    return 'Recent reporting suggests potentially active actor behavior.'


def _priority_hunt_focus(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('phish', 'email')):
        return 'Hunt suspicious sender domains, attachments, and repeated campaign subjects.'
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit')):
        return 'Hunt exploit hits on edge assets and unusual VPN authentication patterns.'
    if any(token in lowered for token in ('powershell', 'wmi', 'scheduled task', 'execution')):
        return 'Hunt unusual PowerShell/WMI commands and new scheduled tasks.'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon')):
        return 'Hunt periodic beacon traffic, rare domains, and odd outbound destinations.'
    if any(token in lowered for token in ('hash', 'file', 'process', 'command line')):
        return 'Hunt suspicious hashes, binaries, and parent-child process chains.'
    return 'Hunt corroborating signs across endpoint and network telemetry.'


def _priority_decision_to_inform(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('phish', 'email')):
        return 'Decide whether to escalate email containment controls and user-targeted takedown actions.'
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit', 'initial access')):
        return 'Decide which exposed systems require emergency hardening, patching, or temporary access restrictions.'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot')):
        return 'Decide which internal hosts or segments should be isolated to stop spread.'
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection')):
        return 'Decide whether data loss response and legal/privacy escalation should start now.'
    if any(token in lowered for token in ('encrypt', 'ransom', 'impact', 'disrupt')):
        return 'Decide whether to execute disruptive-impact containment and business continuity playbooks.'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon', 'command-and-control')):
        return 'Decide whether to block outbound destinations and initiate host-level containment.'
    return 'Decide whether monitoring remains sufficient or incident response escalation is required.'


def _priority_time_horizon(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('impact', 'ransom', 'exfiltrat', 'data theft')):
        return 'Current shift'
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit', 'initial access')):
        return 'Next 24 hours'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot', 'beacon', 'c2')):
        return 'Next 72 hours'
    return 'This week'


def _priority_disconfirming_signal(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('phish', 'email')):
        return 'No malicious sender/attachment telemetry and no campaign clustering across targeted users.'
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit', 'initial access')):
        return 'No exploit-like edge telemetry and no unusual external authentication patterns.'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot')):
        return 'No abnormal east-west remote-service authentication or privilege propagation.'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon', 'command-and-control')):
        return 'No repeatable beacon cadence, rare domain lookups, or suspicious outbound control traffic.'
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection')):
        return 'No suspicious staging/archiving behavior and no unusual outbound transfer volume.'
    if any(token in lowered for token in ('encrypt', 'ransom', 'impact', 'disrupt')):
        return 'No backup tampering, broad file-encryption behaviors, or destructive command execution.'
    return 'No corroborating endpoint and network evidence tied to the hypothesized activity.'


def _priority_confidence_label(updates_count: int, relevance: int, latest_excerpt: str) -> str:
    score = 0
    if updates_count >= 3:
        score += 2
    elif updates_count >= 1:
        score += 1
    if relevance >= 3:
        score += 2
    elif relevance == 2:
        score += 1
    if latest_excerpt:
        score += 1
    if score >= 5:
        return 'High'
    if score >= 3:
        return 'Medium'
    return 'Low'


def _priority_where_to_check(guidance_items: list[dict[str, object]], question_text: str) -> str:
    platforms: list[str] = []
    for item in guidance_items:
        value = str(item.get('platform') or '').strip()
        if value and value not in platforms:
            platforms.append(value)
    if not platforms:
        for platform in _platforms_for_question(question_text):
            if platform not in platforms:
                platforms.append(platform)
    return ', '.join(platforms[:3]) if platforms else 'Windows Event Logs'


def _priority_strongest_evidence(latest_excerpt: str, latest_source_name: str) -> str:
    if latest_excerpt:
        source = latest_source_name.strip() if latest_source_name else 'recent source reporting'
        return f'{source}: "{latest_excerpt}"'
    return 'No direct cue excerpt yet; priority based on correlated thread/question signals.'


def _priority_confidence_why(
    confidence: str,
    updates_count: int,
    relevance: int,
    latest_source_name: str,
    latest_excerpt: str,
) -> str:
    reasons: list[str] = []
    if updates_count >= 3:
        reasons.append('multiple reinforcing updates')
    elif updates_count >= 1:
        reasons.append('at least one supporting update')
    else:
        reasons.append('limited update volume')
    if relevance >= 3:
        reasons.append('strong overlap with recent actor activity categories')
    elif relevance == 2:
        reasons.append('partial overlap with recent actor activity categories')
    else:
        reasons.append('weak overlap with recent actor activity categories')
    if latest_excerpt:
        reasons.append('includes a concrete trigger cue')
    else:
        reasons.append('no concrete trigger cue captured yet')
    if latest_source_name:
        reasons.append(f'latest source: {latest_source_name}')
    return f'{confidence} confidence because ' + '; '.join(reasons) + '.'


def _priority_assumptions(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit')):
        return 'Assumes exposed edge systems and authentication telemetry are complete and current.'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot')):
        return 'Assumes internal authentication and host-to-host telemetry coverage is reliable.'
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection')):
        return 'Assumes outbound transfer visibility and data egress controls are sufficiently instrumented.'
    if any(token in lowered for token in ('ransom', 'encrypt', 'impact')):
        return 'Assumes endpoint detections capture backup tampering and disruptive command execution.'
    return 'Assumes the current telemetry set is sufficient to confirm or reject the hypothesis.'


def _priority_alternative_hypothesis(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('phish', 'email')):
        return 'Observed signals may be routine phishing noise rather than actor-specific campaign activity.'
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit')):
        return 'Observed edge anomalies may reflect benign scanning or patch-management drift, not active intrusion.'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot')):
        return 'Abnormal internal access may be administrative operations or tooling changes rather than attacker movement.'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon')):
        return 'Suspicious outbound traffic may be software updates, telemetry services, or misclassified SaaS behavior.'
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection', 'ransom', 'impact')):
        return 'Current signals may indicate operational disruption or maintenance anomalies, not adversary impact operations.'
    return 'Signals may be unrelated operational anomalies rather than evidence of this actor activity.'


def _priority_next_best_action(question_text: str, where_to_check: str) -> str:
    first_location = where_to_check.split(',')[0].strip() if where_to_check else 'Windows Event Logs'
    return f'Run a targeted 15-minute validation query in {first_location} for the latest cue and confirm signal presence.'


def _priority_action_ladder(question_text: str) -> tuple[str, str, str]:
    lowered = question_text.lower()
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'ransom', 'impact', 'encrypt')):
        return (
            'Contain impacted hosts/accounts and initiate incident response escalation.',
            'Increase monitoring scope and task a focused hunt across endpoint and network telemetry.',
            'De-escalate to monitoring and document why destructive/data-loss hypothesis was not supported.',
        )
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit', 'initial access')):
        return (
            'Apply emergency hardening/patch controls on exposed assets and enforce temporary access restrictions.',
            'Prioritize high-value exposed systems for additional telemetry review and rapid patch validation.',
            'Resume normal patch cycle while recording why active exploitation was ruled out.',
        )
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot', 'c2', 'beacon')):
        return (
            'Segment or isolate suspicious hosts and rotate credentials tied to suspicious internal movement.',
            'Pivot hunt toward authentication chains and east-west traffic to resolve ambiguity.',
            'Return isolated hosts to normal operations after documenting benign explanation.',
        )
    return (
        'Escalate monitoring to active incident workflow for the scoped systems.',
        'Collect one more corroborating signal from an independent telemetry source.',
        'Keep baseline monitoring and track for renewed indicators.',
    )


def _phase_label_for_question(question_text: str) -> str:
    hints = _question_category_hints(question_text)
    ordered = [
        ('initial_access', 'Initial Access'),
        ('execution', 'Execution'),
        ('persistence', 'Persistence'),
        ('lateral_movement', 'Lateral Movement'),
        ('command_and_control', 'Command and Control'),
        ('exfiltration', 'Exfiltration'),
        ('impact', 'Impact'),
    ]
    for key, label in ordered:
        if key in hints:
            return label
    return 'General'


def _short_decision_trigger(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit', 'initial access')):
        return 'Escalate now if active external intrusion signals are present.'
    if any(token in lowered for token in ('powershell', 'wmi', 'scheduled task', 'execution')):
        return 'Escalate now if suspicious endpoint execution is confirmed.'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot')):
        return 'Escalate now if internal host-to-host spread is confirmed.'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon', 'command-and-control')):
        return 'Escalate now if persistent command-and-control behavior is confirmed.'
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection')):
        return 'Escalate now if data staging or theft behavior is confirmed.'
    if any(token in lowered for token in ('encrypt', 'ransom', 'impact', 'disrupt')):
        return 'Escalate now if disruptive impact activity is confirmed.'
    return 'Escalate now if this activity is confirmed in current telemetry.'


def _telemetry_anchor_line(guidance_items: list[dict[str, object]], question_text: str) -> str:
    platforms: list[str] = []
    for item in guidance_items:
        platform = str(item.get('platform') or '').strip()
        if platform and platform not in platforms:
            platforms.append(platform)
    if not platforms:
        platforms = _platforms_for_question(question_text)
    return ', '.join(platforms[:2]) if platforms else 'Windows Event Logs'


def _escalation_threshold_line(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit', 'initial access')):
        return '2+ confirmed exploit or unusual access events hit critical systems in 24 hours.'
    if any(token in lowered for token in ('powershell', 'wmi', 'scheduled task', 'execution')):
        return 'Suspicious execution appears on 2+ systems or one critical system.'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot')):
        return 'Abnormal remote-service movement is seen across 2+ internal systems.'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon', 'command-and-control')):
        return 'Repeated suspicious outbound check-ins continue across 2+ intervals.'
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection')):
        return 'Unusual staging activity plus outbound transfer is observed.'
    if any(token in lowered for token in ('encrypt', 'ransom', 'impact', 'disrupt')):
        return 'Backup tampering or widespread encryption activity is detected.'
    return 'The same suspicious activity is confirmed in both endpoint and network logs.'


def _quick_check_title(question_text: str, phase_label: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit', 'initial access')):
        return 'Check for active edge intrusion signals'
    if any(token in lowered for token in ('powershell', 'wmi', 'scheduled task', 'execution')):
        return 'Check for suspicious endpoint execution'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot')):
        return 'Check for internal spread between hosts'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon', 'command-and-control')):
        return 'Check for repeated suspicious outbound traffic'
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection')):
        return 'Check for signs of data staging or theft'
    if any(token in lowered for token in ('encrypt', 'ransom', 'impact', 'disrupt')):
        return 'Check for disruptive impact behavior'
    return f'Quick check for {phase_label.lower()} activity'


def _latest_reporting_recency_label(timeline_recent_items: list[dict[str, object]]) -> str:
    parsed_dates: list[datetime] = []
    for item in timeline_recent_items:
        dt = _parse_published_datetime(str(item.get('occurred_at') or ''))
        if dt is not None:
            parsed_dates.append(dt)
    if not parsed_dates:
        return 'recency unclear'
    newest = max(parsed_dates)
    days_old = max(0, (datetime.now(timezone.utc) - newest).days)
    if days_old <= 7:
        return 'latest reporting in the last 7 days'
    if days_old <= 30:
        return 'latest reporting in the last 30 days'
    return 'latest reporting in the last 90 days'


def _build_environment_checks(
    timeline_recent_items: list[dict[str, object]],
    recent_activity_highlights: list[dict[str, object]],
    top_techniques: list[dict[str, str]],
) -> list[dict[str, str]]:
    categories = {str(item.get('category') or '').lower() for item in timeline_recent_items}
    text_blob = ' '.join(
        [
            str(item.get('title') or '')
            for item in timeline_recent_items
        ]
        + [
            str(item.get('summary') or '')
            for item in timeline_recent_items
        ]
        + [
            str(item.get('text') or '')
            for item in recent_activity_highlights
        ]
    ).lower()
    recent_ttps: set[str] = set()
    for item in timeline_recent_items:
        for ttp in item.get('ttp_ids', []):
            token = str(ttp or '').upper().strip()
            if token:
                recent_ttps.add(token)
    for item in recent_activity_highlights:
        csv_ids = str(item.get('ttp_ids') or '')
        for token in csv_ids.split(','):
            token_norm = token.strip().upper()
            if token_norm:
                recent_ttps.add(token_norm)
    known_ttps = {
        str(item.get('technique_id') or '').upper().strip()
        for item in top_techniques
        if str(item.get('technique_id') or '').strip()
    }
    source_ids = {
        str(item.get('source_id') or '').strip()
        for item in timeline_recent_items
        if str(item.get('source_id') or '').strip()
    }
    source_urls = {
        str(item.get('source_url') or '').strip()
        for item in recent_activity_highlights
        if str(item.get('source_url') or '').strip()
    }
    source_count = len(source_ids | source_urls)
    recency_label = _latest_reporting_recency_label(timeline_recent_items)

    theme_defs = [
        {
            'id': 'remote_access',
            'check': 'Unusual remote access and edge logins',
            'primary_area': 'Firewall/VPN',
            'short_cue': 'Look for unusual remote logins and edge access activity',
            'where': 'Firewall/VPN logs, identity sign-in logs, EDR',
            'look_for': 'Repeated failed VPN logins followed by success; sign-ins from new geographies or devices.',
            'why': 'Recent reporting links this actor to external-access paths before follow-on activity.',
            'keyword_tags': ['vpn', 'edge', 'remote access', 'login', 'external authentication', 'exploit'],
            'category_tags': {'initial_access', 'lateral_movement', 'command_and_control'},
            'ttp_tags': {'T1133', 'T1078', 'T1190'},
        },
        {
            'id': 'endpoint_activity',
            'check': 'Suspicious endpoint command activity',
            'primary_area': 'Endpoint',
            'short_cue': 'Look for unusual script execution and startup persistence changes',
            'where': 'EDR, Windows Event Logs, PowerShell logs',
            'look_for': 'PowerShell or command shell launched by unusual parent processes; new scheduled tasks or startup entries.',
            'why': 'Recent actor-linked behavior includes host execution and persistence techniques.',
            'keyword_tags': ['powershell', 'cmd.exe', 'wmi', 'scheduled task', 'execution', 'persistence'],
            'category_tags': {'execution', 'persistence', 'defense_evasion'},
            'ttp_tags': {'T1059', 'T1547', 'T1053'},
        },
        {
            'id': 'early_impact',
            'check': 'Early signs of data theft or disruption',
            'primary_area': 'DNS/Proxy',
            'short_cue': 'Look for early data movement and disruptive file behavior',
            'where': 'DNS/Proxy logs, EDR file activity, storage/backup audit logs',
            'look_for': 'Large outbound transfers to new domains; unusual mass file changes or rapid archive creation.',
            'why': 'Recent reporting references ransomware and data-theft style outcomes tied to this actor.',
            'keyword_tags': ['ransom', 'data theft', 'exfil', 'encrypt', 'disrupt', 'leak'],
            'category_tags': {'exfiltration', 'impact', 'command_and_control'},
            'ttp_tags': {'T1041', 'T1486', 'T1567'},
        },
    ]

    candidates: list[dict[str, object]] = []
    for theme in theme_defs:
        matched_tags: list[str] = []
        score = 0

        for cat in theme['category_tags']:
            if cat in categories:
                score += 2
                matched_tags.append(cat.replace('_', ' '))

        for keyword in theme['keyword_tags']:
            if keyword in text_blob:
                score += 1
                if keyword not in matched_tags:
                    matched_tags.append(keyword)

        ttp_hits = (recent_ttps | known_ttps).intersection(theme['ttp_tags'])
        if ttp_hits:
            score += 2
            for ttp in sorted(ttp_hits):
                if ttp not in matched_tags:
                    matched_tags.append(ttp)

        if score > 0:
            based_tags = ', '.join(matched_tags[:3]) if matched_tags else 'actor activity evidence'
            source_label = f'{source_count} sources' if source_count > 0 else 'limited source coverage'
            candidates.append(
                {
                    'score': score,
                    'primary_where': str(theme['where']).split(',')[0].strip().lower(),
                    'card': {
                        'check': str(theme['check']),
                        'primary_area': str(theme['primary_area']),
                        'short_cue': str(theme['short_cue']),
                        'where_to_look': str(theme['where']),
                        'what_to_look_for': str(theme['look_for']),
                        'why_this_matters': str(theme['why']),
                        'based_on': f'Based on: {based_tags} mentioned in {source_label} ({recency_label}).',
                    },
                }
            )

    if not candidates:
        return [
            {
                'check': 'Start with unusual remote access and logins',
                'primary_area': 'Firewall/VPN',
                'short_cue': 'Start with unusual remote access and login patterns',
                'where_to_look': 'Firewall/VPN logs, identity sign-in logs',
                'what_to_look_for': 'Repeated failed logins followed by success; sign-ins from new geographies or devices.',
                'why_this_matters': 'This gives a reliable first pass when recent actor reporting is limited or ambiguous.',
                'based_on': 'Based on: limited recent reporting.',
            }
        ]

    deduped: list[dict[str, str]] = []
    seen_primary_where: set[str] = set()
    for candidate in sorted(candidates, key=lambda item: int(item['score']), reverse=True):
        primary_where = str(candidate['primary_where'])
        if primary_where in seen_primary_where:
            continue
        seen_primary_where.add(primary_where)
        deduped.append(candidate['card'])  # type: ignore[arg-type]
        if len(deduped) >= 3:
            break

    return deduped[:3]


def _recent_change_summary(
    timeline_recent_items: list[dict[str, object]],
    recent_activity_highlights: list[dict[str, object]],
    source_items: list[dict[str, object]],
) -> dict[str, str]:
    new_reports = len({str(item.get('source_id') or '') for item in timeline_recent_items if str(item.get('source_id') or '').strip()})
    source_by_id = {str(item.get('id') or ''): item for item in source_items}
    related_source_ids = {str(item.get('source_id') or '').strip() for item in timeline_recent_items if str(item.get('source_id') or '').strip()}

    # Industry targeting synthesis.
    industry_markers: dict[str, tuple[str, ...]] = {
        'Healthcare': ('healthcare', 'hospital', 'clinic', 'medical', 'patient'),
        'Government': ('government', 'public sector', 'ministry', 'state agency', 'municipal'),
        'Financial services': ('bank', 'financial', 'credit union', 'insurance', 'fintech'),
        'Technology': ('technology', 'software', 'saas', 'cloud provider', 'it services'),
        'Manufacturing': ('manufacturing', 'industrial', 'factory', 'automotive', 'semiconductor'),
        'Energy': ('energy', 'oil', 'gas', 'utility', 'power grid'),
        'Telecom': ('telecom', 'telecommunications', 'mobile operator', 'isp', 'broadband'),
        'Education': ('education', 'university', 'school', 'college', 'academic'),
        'Retail': ('retail', 'ecommerce', 'merchant', 'point of sale', 'consumer brand'),
        'Transportation': ('transportation', 'logistics', 'shipping', 'aviation', 'rail'),
        'Defense': ('defense', 'military', 'aerospace', 'armed forces', 'national security'),
    }
    industry_scores = {name: 0 for name in industry_markers}
    for item in recent_activity_highlights:
        target = str(item.get('target_text') or '').strip().lower()
        text = str(item.get('text') or '').strip().lower()
        joined = f'{target} {text}'
        if not joined.strip():
            continue
        for industry, markers in industry_markers.items():
            if any(marker in joined for marker in markers):
                industry_scores[industry] += 1
    for source_id in related_source_ids:
        source = source_by_id.get(source_id)
        if not source:
            continue
        text = str(source.get('pasted_text') or '').lower()
        if not text:
            continue
        for industry, markers in industry_markers.items():
            if any(marker in text for marker in markers):
                industry_scores[industry] += 1

    top_industries = [name for name, score in sorted(industry_scores.items(), key=lambda x: x[1], reverse=True) if score > 0][:3]
    if top_industries:
        targets_text = ', '.join(top_industries)
    else:
        explicit_targets: list[str] = []
        for item in recent_activity_highlights:
            target = str(item.get('target_text') or '').strip()
            if target and target not in explicit_targets:
                explicit_targets.append(target)
            if len(explicit_targets) >= 3:
                break
        targets_text = ', '.join(explicit_targets) if explicit_targets else 'Not clear yet'

    # Damage synthesis from source-linked text plus recent activity summaries.
    damage_markers: dict[str, tuple[str, ...]] = {
        'data theft': ('exfil', 'data theft', 'stolen data', 'data leak', 'data breach'),
        'ransomware/extortion': ('ransom', 'extortion', 'encrypt', 'lockbit', 'leak site'),
        'service disruption': ('outage', 'disrupt', 'downtime', 'service interruption', 'unavailable'),
        'credential theft/account abuse': ('credential theft', 'password spray', 'account takeover', 'stolen credential'),
        'destructive impact': ('wiper', 'data destruction', 'sabotage', 'destructive'),
    }
    damage_scores = {name: 0 for name in damage_markers}
    summary_blob = ' '.join(str(item.get('summary') or '') for item in timeline_recent_items).lower()
    highlight_blob = ' '.join(str(item.get('text') or '') for item in recent_activity_highlights).lower()
    source_blob_parts: list[str] = []
    for source_id in related_source_ids:
        source = source_by_id.get(source_id)
        if not source:
            continue
        pasted = str(source.get('pasted_text') or '').strip()
        if pasted:
            source_blob_parts.append(pasted)
    source_blob = ' '.join(source_blob_parts).lower()
    damage_text = f'{summary_blob}\n{highlight_blob}\n{source_blob}'
    for damage_type, markers in damage_markers.items():
        damage_scores[damage_type] = sum(damage_text.count(marker) for marker in markers)
    top_damage = [name for name, score in sorted(damage_scores.items(), key=lambda x: x[1], reverse=True) if score > 0][:2]
    if len(top_damage) >= 2:
        damage = f'{top_damage[0].capitalize()} and {top_damage[1]}'
    elif len(top_damage) == 1:
        damage = top_damage[0].capitalize()
    else:
        damage = 'No clear damage outcome reported yet'

    return {
        'new_reports': str(new_reports),
        'targets': targets_text,
        'damage': damage,
    }


def _extract_target_hint(sentence: str) -> str:
    patterns = [
        r'\btarget(?:ed|ing)?\s+([A-Z][A-Za-z0-9&\-/ ]{3,80})',
        r'\bagainst\s+([A-Z][A-Za-z0-9&\-/ ]{3,80})',
        r'\bvictims?\s+include\s+([A-Z][A-Za-z0-9&\-/ ,]{3,100})',
    ]
    for pattern in patterns:
        match = re.search(pattern, sentence)
        if not match:
            continue
        target = ' '.join(match.group(1).split())
        target = re.sub(r'[.,;:]+$', '', target)
        if len(target) >= 4:
            return target[:90]
    return ''


def _sentence_mentions_actor_terms(sentence: str, actor_terms: list[str]) -> bool:
    lowered = sentence.lower()
    return any(term in lowered for term in actor_terms if term)


def _looks_like_activity_sentence(sentence: str) -> bool:
    lowered = sentence.lower()
    verbs = (
        'target', 'attack', 'exploit', 'compromise', 'phish', 'deploy',
        'ransom', 'encrypt', 'exfiltrat', 'move laterally', 'beacon',
        'used', 'leveraged', 'abused', 'campaign', 'operation',
        'activity', 'incident', 'disclosure', 'victim',
    )
    return any(token in lowered for token in verbs)


def _actor_terms(actor_name: str, mitre_group_name: str, aliases_csv: str) -> list[str]:
    raw_terms = [actor_name, mitre_group_name] + [part.strip() for part in aliases_csv.split(',') if part.strip()]
    terms: list[str] = []
    for raw in raw_terms:
        value = raw.strip().lower()
        if len(value) < 3:
            continue
        if value not in terms:
            terms.append(value)
    return terms


def _text_contains_actor_term(text: str, actor_terms: list[str]) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in actor_terms if term)


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
        netloc = urlparse(url).netloc.lower()
    except Exception:
        return False
    if not netloc:
        return False
    return any(domain in netloc for domain in ACTOR_SEARCH_DOMAINS)


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

    def _is_trusted_domain(url: str) -> bool:
        domain = _source_domain(url)
        return bool(domain and any(d in domain for d in TRUSTED_ACTIVITY_DOMAINS))

    def _actor_specific_text(text: str, terms: list[str]) -> bool:
        return bool(text and terms and _sentence_mentions_actor_terms(text, terms))

    source_by_id = {str(source['id']): source for source in sources}
    highlights: list[dict[str, str | None]] = []
    terms = [term.lower() for term in actor_terms if term]
    if not terms:
        return highlights

    for item in sorted(timeline_items, key=lambda entry: str(entry['occurred_at']), reverse=True):
        source = source_by_id.get(str(item['source_id']))
        summary = str(item.get('summary') or '')
        source_text = str(source.get('pasted_text') if source else '')
        source_url = str(source.get('url') if source else '')
        if not _looks_like_activity_sentence(summary):
            continue
        if not (_actor_specific_text(summary, terms) or _actor_specific_text(source_text, terms)):
            continue
        # Strict gating: require trusted domains unless summary is explicitly actor-tagged.
        if source_url and not _is_trusted_domain(source_url) and not _actor_specific_text(summary, terms):
            continue
        highlights.append(
            {
                'date': _format_date_or_unknown(str(item['occurred_at'])),
                'text': summary,
                'category': str(item['category']).replace('_', ' '),
                'target_text': str(item.get('target_text') or ''),
                'ttp_ids': ', '.join(str(t) for t in item.get('ttp_ids', [])),
                'source_name': str(source['source_name']) if source else None,
                'source_url': source_url if source else None,
                'evidence_title': _evidence_title_from_source(source) if source else _fallback_title_from_url(source_url),
                'evidence_source_label': _evidence_source_label_from_source(source) if source else (_source_domain(source_url) or 'Unknown source'),
                'evidence_group_domain': _canonical_group_domain(source) if source else (_source_domain(source_url) or 'unknown-source'),
                'source_published_at': str(source['published_at']) if source and source.get('published_at') else None,
            }
        )
        if len(highlights) >= 8:
            break

    if highlights:
        return highlights

    # Fallback: synthesize activity statements from actor-relevant source text.
    def _activity_synthesis_sentence(text: str, terms: list[str]) -> str | None:
        for sentence in _split_sentences(text):
            normalized = ' '.join(sentence.split())
            if len(normalized) < 35:
                continue
            if _looks_like_navigation_noise(normalized):
                continue
            if not _sentence_mentions_actor_terms(normalized, terms):
                continue
            if not _looks_like_activity_sentence(normalized):
                continue
            return normalized
        for sentence in _split_sentences(text):
            normalized = ' '.join(sentence.split())
            if len(normalized) < 35:
                continue
            if _looks_like_navigation_noise(normalized):
                continue
            if not _sentence_mentions_actor_terms(normalized, terms):
                continue
            return normalized
        return None

    for source in sorted(
        sources,
        key=lambda item: str(item.get('published_at') or item.get('retrieved_at') or ''),
        reverse=True,
    ):
        text = str(source.get('pasted_text') or '').strip()
        if not text:
            continue
        combined = f'{source.get("source_name") or ""} {source.get("url") or ""} {text}'
        if actor_terms and not _text_contains_actor_term(combined, actor_terms):
            continue
        if not _is_trusted_domain(str(source.get('url') or '')):
            continue
        synthesized = _activity_synthesis_sentence(text, actor_terms)
        if not synthesized:
            continue
        highlights.append(
            {
                'date': _format_date_or_unknown(str(source.get('published_at') or source.get('retrieved_at') or '')),
                'text': synthesized,
                'category': 'activity synthesis',
                'target_text': '',
                'ttp_ids': ', '.join(_extract_ttp_ids(synthesized)[:4]),
                'source_name': str(source['source_name']) if source else None,
                'source_url': str(source['url']) if source else None,
                'evidence_title': _evidence_title_from_source(source) if source else _fallback_title_from_url(str(source.get('url') or '')),
                'evidence_source_label': _evidence_source_label_from_source(source) if source else (_source_domain(str(source.get('url') or '')) or 'Unknown source'),
                'evidence_group_domain': _canonical_group_domain(source) if source else (_source_domain(str(source.get('url') or '')) or 'unknown-source'),
                'source_published_at': str(source['published_at']) if source and source.get('published_at') else None,
            }
        )
        if len(highlights) >= 6:
            break
    return highlights


def _extract_target_from_activity_text(text: str) -> str:
    patterns = [
        r'\bstrikes?\s+([A-Z][A-Za-z0-9&\-/ ]{3,90})',
        r'\battack(?:ed)?\s+on\s+([A-Z][A-Za-z0-9&\-/ ]{3,90})',
        r'\bagainst\s+([A-Z][A-Za-z0-9&\-/ ]{3,90})',
        r'\btarget(?:ed|ing)?\s+([A-Z][A-Za-z0-9&\-/ ]{3,90})',
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if not match:
            continue
        target = ' '.join(match.group(1).split())
        target = re.sub(r'[.,;:|]+$', '', target).strip()
        if len(target) >= 4:
            return target[:90]
    return ''


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
    lowered = sentence.lower()
    if any(token in lowered for token in ('phish', 'email', 'exploit', 'initial access', 'cve-')):
        return 'initial_access'
    if any(token in lowered for token in ('powershell', 'wmi', 'command', 'execution')):
        return 'execution'
    if any(token in lowered for token in ('scheduled task', 'startup', 'registry run key', 'persistence')):
        return 'persistence'
    if any(token in lowered for token in ('lateral movement', 'remote service', 'rdp', 'smb', 'pivot')):
        return 'lateral_movement'
    if any(token in lowered for token in ('dns', 'beacon', 'c2', 'command and control')):
        return 'command_and_control'
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection')):
        return 'exfiltration'
    if any(token in lowered for token in ('ransom', 'encrypt', 'wiper', 'impact')):
        return 'impact'
    if any(token in lowered for token in ('defense evasion', 'disable', 'tamper', 'obfuscat')):
        return 'defense_evasion'
    return None


def _extract_major_move_events(
    source_name: str,
    source_id: str,
    occurred_at: str,
    text: str,
    actor_terms: list[str],
) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for sentence in _split_sentences(text):
        if not _sentence_mentions_actor_terms(sentence, actor_terms):
            continue
        if not _looks_like_activity_sentence(sentence):
            continue
        category = _timeline_category_from_sentence(sentence)
        if category is None:
            continue
        summary = ' '.join(sentence.split())
        if len(summary) > 260:
            summary = summary[:260].rsplit(' ', 1)[0] + '...'
        target_hint = _extract_target_hint(sentence)
        ttp_ids = _extract_ttp_ids(sentence)
        title = f'{category.replace("_", " ").title()} move'
        events.append(
            {
                'id': str(uuid.uuid4()),
                'occurred_at': occurred_at,
                'category': category,
                'title': title,
                'summary': summary,
                'source_id': source_id,
                'source_name': source_name,
                'target_text': target_hint,
                'ttp_ids': ttp_ids,
            }
        )
    return events


def _guidance_for_platform(platform: str, question_text: str) -> dict[str, str | None]:
    if platform == 'M365':
        return {
            'platform': platform,
            'what_to_look_for': '\n'.join([
                '- Suspicious sender domains and lookalike addresses.',
                '- Unexpected attachment execution requests.',
                '- Repeated delivery attempts to multiple users.',
            ]),
            'where_to_look': '\n'.join([
                '- Microsoft Defender for Office alerts.',
                '- Exchange message trace and transport logs.',
                '- User-reported phishing mailbox.',
            ]),
            'query_hint': 'Filter inbound messages by sender/domain and attachment type around reported times.',
        }
    if platform == 'Email Gateway':
        return {
            'platform': platform,
            'what_to_look_for': '\n'.join([
                '- Blocked and allowed events for the same sender.',
                '- Spike in URL rewrite or detonation events.',
                '- Campaign-style subject reuse.',
            ]),
            'where_to_look': '\n'.join([
                '- Secure email gateway event history.',
                '- URL detonation sandbox verdicts.',
                '- Mail policy exception logs.',
            ]),
            'query_hint': 'Search for clustered subject lines and sender infrastructure over 24-72h windows.',
        }
    if platform == 'Firewall/VPN':
        return {
            'platform': platform,
            'what_to_look_for': '\n'.join([
                '- Exploit attempts against internet-facing services.',
                '- Unusual VPN auth behavior or impossible travel.',
                '- Repeated probes against edge administration paths.',
            ]),
            'where_to_look': '\n'.join([
                '- Firewall threat and deny logs.',
                '- VPN authentication and session logs.',
                '- WAF alerts for exploit signatures.',
            ]),
            'query_hint': 'Correlate source IPs with exploit paths and successful auth events.',
        }
    if platform == 'Windows Event Logs':
        return {
            'platform': platform,
            'what_to_look_for': '\n'.join([
                '- PowerShell script block activity and encoded commands.',
                '- WMI execution and remote process creation.',
                '- Scheduled task creation or modification anomalies.',
            ]),
            'where_to_look': '\n'.join([
                '- Security and Sysmon event logs.',
                '- PowerShell operational logs.',
                '- Task Scheduler operational logs.',
            ]),
            'query_hint': 'Pivot from parent process to command line and child process tree.',
        }
    if platform == 'DNS/Proxy':
        return {
            'platform': platform,
            'what_to_look_for': '\n'.join([
                '- Repeated beacon-like intervals to rare domains.',
                '- High-entropy or newly registered domains.',
                '- Unusual outbound protocol/domain patterns.',
            ]),
            'where_to_look': '\n'.join([
                '- DNS resolver query logs.',
                '- Secure web proxy transaction logs.',
                '- Network telemetry for egress destinations.',
            ]),
            'query_hint': 'Group by destination domain and interval regularity per host.',
        }
    return {
        'platform': 'EDR',
        'what_to_look_for': '\n'.join([
            '- Suspicious process ancestry and rare binaries.',
            '- Malicious hash sightings and unsigned executables.',
            '- Command-line patterns tied to known abuse.',
        ]),
        'where_to_look': '\n'.join([
            '- EDR detection timelines.',
            '- Endpoint process and file telemetry.',
            '- Alert triage and investigation notes.',
        ]),
        'query_hint': f'Filter endpoint telemetry using terms from the question: {question_text[:80]}',
    }


def _platforms_for_question(question_text: str) -> list[str]:
    lowered = question_text.lower()
    platforms: list[str] = []
    if any(token in lowered for token in ('phish', 'email')):
        platforms.extend(['M365', 'Email Gateway'])
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit')):
        platforms.append('Firewall/VPN')
    if any(token in lowered for token in ('powershell', 'wmi', 'scheduled task')):
        platforms.append('Windows Event Logs')
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon')):
        platforms.append('DNS/Proxy')
    if any(token in lowered for token in ('hash', 'file', 'process', 'command line')):
        platforms.append('EDR')
    if not platforms:
        platforms.append('Windows Event Logs')
    deduped: list[str] = []
    for platform in platforms:
        if platform not in deduped:
            deduped.append(platform)
    return deduped


def _strip_html(value: str) -> str:
    value = re.sub(r'<script[\s\S]*?</script>', ' ', value, flags=re.IGNORECASE)
    value = re.sub(r'<style[\s\S]*?</style>', ' ', value, flags=re.IGNORECASE)
    value = re.sub(r'<[^>]+>', ' ', value)
    value = html.unescape(value)
    value = re.sub(r'\s+', ' ', value).strip()
    return value


def _extract_meta(content: str, key_patterns: list[str]) -> str | None:
    for pattern in key_patterns:
        match = re.search(pattern, content, flags=re.IGNORECASE)
        if match:
            return html.unescape(match.group(1)).strip()
    return None


def _fallback_title_from_url(source_url: str) -> str:
    return 'Untitled article'


def _evidence_title_from_source(source: dict[str, object]) -> str:
    for key in ('title', 'headline', 'og_title', 'html_title'):
        value = str(source.get(key) or '').strip()
        if value:
            # Avoid showing raw URL/path-like strings as the visible title.
            if value.startswith(('http://', 'https://')) or (value.count('/') >= 2 and ' ' not in value):
                continue
            return value
    pasted_text = str(source.get('pasted_text') or '').strip()
    if pasted_text:
        first_sentence = _split_sentences(pasted_text)[0] if _split_sentences(pasted_text) else pasted_text
        first_sentence = ' '.join(first_sentence.split()).strip()
        if (
            first_sentence
            and not first_sentence.lower().startswith('actor-matched feed item from')
            and not first_sentence.startswith(('http://', 'https://'))
            and not (first_sentence.count('/') >= 2 and ' ' not in first_sentence)
        ):
            return first_sentence[:120]
    return _fallback_title_from_url(str(source.get('url') or ''))


def _evidence_source_label_from_source(source: dict[str, object]) -> str:
    source_url = str(source.get('url') or '').strip()
    parsed_source = urlparse(source_url)
    source_host = (parsed_source.netloc or '').lower()
    if source_host.endswith('news.google.com'):
        title_hint = _evidence_title_from_source(source)
        if ' - ' in title_hint:
            publisher_hint = title_hint.rsplit(' - ', 1)[-1].strip()
            if publisher_hint and publisher_hint.lower() not in {'google news', 'news'}:
                return publisher_hint
    for key in ('publisher', 'site_name'):
        value = str(source.get(key) or '').strip()
        if value:
            return value
    parsed = urlparse(source_url)
    hostname = (parsed.netloc or '').strip()
    if hostname:
        return hostname
    return str(source.get('source_name') or 'Unknown source').strip() or 'Unknown source'


def _canonical_group_domain(source: dict[str, object]) -> str:
    source_url = str(source.get('url') or '').strip()
    parsed = urlparse(source_url)
    host = (parsed.netloc or '').lower()
    if host.endswith('news.google.com'):
        # Google News links can contain the original article URL in query params.
        query_params = parse_qs(parsed.query)
        for key in ('url', 'u', 'q'):
            candidate = str((query_params.get(key) or [''])[0]).strip()
            if not candidate.startswith(('http://', 'https://')):
                continue
            candidate_host = (urlparse(candidate).netloc or '').lower()
            if candidate_host and not candidate_host.endswith('news.google.com'):
                return candidate_host
        source_label = _evidence_source_label_from_source(source)
        source_label_lower = source_label.lower().strip()
        if re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', source_label_lower):
            return source_label_lower
        normalized = re.sub(r'[^a-z0-9]+', '-', source_label_lower).strip('-')
        if normalized:
            return f'publisher:{normalized}'
    return host or 'unknown-source'


def _is_blocked_outbound_ip(ip_value: str) -> bool:
    try:
        ip_addr = ipaddress.ip_address(ip_value)
    except ValueError:
        return True
    return (
        ip_addr.is_private
        or ip_addr.is_loopback
        or ip_addr.is_link_local
        or ip_addr.is_multicast
        or ip_addr.is_reserved
        or ip_addr.is_unspecified
    )


def _host_matches_allowed_domains(hostname: str, allowed_domains: set[str]) -> bool:
    return any(hostname == domain or hostname.endswith(f'.{domain}') for domain in allowed_domains)


def _validate_outbound_url(source_url: str, allowed_domains: set[str] | None = None) -> str:
    normalized = source_url.strip()
    parsed = urlparse(normalized)
    if parsed.scheme.lower() not in {'http', 'https'}:
        raise HTTPException(status_code=400, detail='source_url must use http or https')
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail='source_url must not include credentials')

    hostname = (parsed.hostname or '').strip('.').lower()
    if not hostname:
        raise HTTPException(status_code=400, detail='source_url must include a valid hostname')
    if hostname == 'localhost' or hostname.endswith('.localhost'):
        raise HTTPException(status_code=400, detail='source_url points to a blocked host')

    effective_allowlist = OUTBOUND_ALLOWED_DOMAINS if allowed_domains is None else allowed_domains
    if effective_allowlist and not _host_matches_allowed_domains(hostname, effective_allowlist):
        raise HTTPException(status_code=400, detail='source_url domain is not allowed')

    try:
        addr_infos = socket.getaddrinfo(
            hostname,
            parsed.port or (443 if parsed.scheme.lower() == 'https' else 80),
            proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f'failed to resolve source_url host: {exc}') from exc

    for addr_info in addr_infos:
        resolved_ip = str(addr_info[4][0])
        if _is_blocked_outbound_ip(resolved_ip):
            raise HTTPException(status_code=400, detail='source_url resolves to a blocked IP range')

    return normalized


def _safe_http_get(
    source_url: str,
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
    allowed_domains: set[str] | None = None,
    max_redirects: int = 3,
) -> httpx.Response:
    current_url = _validate_outbound_url(source_url, allowed_domains=allowed_domains)
    for _ in range(max_redirects + 1):
        response = httpx.get(
            current_url,
            timeout=timeout,
            follow_redirects=False,
            headers=headers,
        )
        if not response.is_redirect:
            return response
        location = response.headers.get('location')
        if not location:
            return response
        next_url = urljoin(str(response.url), location)
        current_url = _validate_outbound_url(next_url, allowed_domains=allowed_domains)
    raise HTTPException(status_code=400, detail='too many redirects while fetching source_url')


def derive_source_from_url(source_url: str, fallback_source_name: str | None = None, published_hint: str | None = None) -> dict[str, str | None]:
    try:
        response = _safe_http_get(source_url, timeout=20.0)
        response.raise_for_status()
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=400, detail=f'failed to fetch source URL: {exc}') from exc

    content = response.text
    parsed = urlparse(str(response.url))
    domain = parsed.netloc or 'unknown'

    site_name = _extract_meta(
        content,
        [
            r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']+)["\']',
            r'<meta[^>]+name=["\']application-name["\'][^>]+content=["\']([^"\']+)["\']',
        ],
    )
    publisher = _extract_meta(
        content,
        [
            r'<meta[^>]+property=["\']article:publisher["\'][^>]+content=["\']([^"\']+)["\']',
            r'<meta[^>]+name=["\']publisher["\'][^>]+content=["\']([^"\']+)["\']',
        ],
    )
    source_name = site_name or fallback_source_name or domain

    og_title = _extract_meta(
        content,
        [
            r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']',
        ],
    )
    html_title = _extract_meta(
        content,
        [
            r'<title[^>]*>([^<]+)</title>',
        ],
    )
    headline = _extract_meta(
        content,
        [
            r'<meta[^>]+name=["\']headline["\'][^>]+content=["\']([^"\']+)["\']',
            r'<h1[^>]*>([^<]+)</h1>',
        ],
    )
    title = (
        _extract_meta(
            content,
            [
                r'<meta[^>]+name=["\']twitter:title["\'][^>]+content=["\']([^"\']+)["\']',
            ],
        )
        or headline
        or og_title
        or html_title
    )

    published_at = _extract_meta(
        content,
        [
            r'<meta[^>]+property=["\']article:published_time["\'][^>]+content=["\']([^"\']+)["\']',
            r'<meta[^>]+name=["\']pubdate["\'][^>]+content=["\']([^"\']+)["\']',
            r'<meta[^>]+name=["\']date["\'][^>]+content=["\']([^"\']+)["\']',
            r'<time[^>]+datetime=["\']([^"\']+)["\']',
        ],
    )
    if not published_at:
        published_at = published_hint

    paragraphs = re.findall(r'<p[^>]*>(.*?)</p>', content, flags=re.IGNORECASE | re.DOTALL)
    cleaned_paragraphs = [_strip_html(paragraph) for paragraph in paragraphs]
    cleaned_paragraphs = [paragraph for paragraph in cleaned_paragraphs if len(paragraph) > 40]

    if cleaned_paragraphs:
        pasted_text = ' '.join(cleaned_paragraphs[:10])
    else:
        pasted_text = _strip_html(content)[:5000]

    if title and title not in pasted_text:
        pasted_text = f'{title}. {pasted_text}'

    if len(pasted_text) < 80:
        raise HTTPException(status_code=400, detail='unable to derive sufficient text from source URL')

    excerpts = _extract_question_sentences(pasted_text)
    trigger_excerpt = excerpts[0] if excerpts else _first_sentences(pasted_text, count=1)

    return {
        'source_name': source_name,
        'site_name': site_name,
        'publisher': publisher,
        'title': title,
        'headline': headline,
        'og_title': og_title,
        'html_title': html_title,
        'source_url': str(response.url),
        'published_at': published_at,
        'pasted_text': pasted_text,
        'trigger_excerpt': trigger_excerpt,
    }


def _parse_feed_entries(xml_text: str) -> list[dict[str, str | None]]:
    entries: list[dict[str, str | None]] = []
    root = ET.fromstring(xml_text)

    # RSS
    for item in root.findall('.//item'):
        title = (item.findtext('title') or '').strip() or None
        link = (item.findtext('link') or '').strip() or None
        pub = (item.findtext('pubDate') or '').strip() or None
        if link:
            entries.append({'title': title, 'link': link, 'published_at': pub})

    # Atom
    namespace = {'atom': 'http://www.w3.org/2005/Atom'}
    for entry in root.findall('.//atom:entry', namespace):
        title = (entry.findtext('atom:title', default='', namespaces=namespace) or '').strip() or None
        updated = (entry.findtext('atom:updated', default='', namespaces=namespace) or '').strip() or None
        link_el = entry.find('atom:link[@rel="alternate"]', namespace) or entry.find('atom:link', namespace)
        link = link_el.get('href').strip() if link_el is not None and link_el.get('href') else None
        if link:
            entries.append({'title': title, 'link': link, 'published_at': updated})

    deduped: list[dict[str, str | None]] = []
    seen: set[str] = set()
    for entry in entries:
        link = entry.get('link')
        if link and link not in seen:
            deduped.append(entry)
            seen.add(link)
    return deduped


def _parse_published_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass
    try:
        dt = parsedate_to_datetime(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _within_lookback(published_at: str | None, lookback_days: int) -> bool:
    dt = _parse_published_datetime(published_at)
    if dt is None:
        return True
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    return dt >= cutoff


def _import_ransomware_live_actor_activity(
    connection: sqlite3.Connection,
    actor_id: str,
    actor_terms: list[str],
) -> int:
    imported = 0
    seen_groups: set[str] = set()

    for term in actor_terms:
        group = term.strip().lower().replace(' ', '')
        if len(group) < 3 or group in seen_groups:
            continue
        seen_groups.add(group)
        endpoint = f'https://api.ransomware.live/v2/groupvictims/{quote_plus(group)}'
        try:
            response = httpx.get(endpoint, timeout=20.0, follow_redirects=True)
            if response.status_code != 200:
                continue
            data = response.json()
            if not isinstance(data, list) or not data:
                continue
        except Exception:
            continue

        lines: list[str] = []
        country_counts: dict[str, int] = {}
        recent_90 = 0
        latest_attack_dt: datetime | None = None
        latest_attack_label = ''
        cutoff_90 = datetime.now(timezone.utc) - timedelta(days=90)
        for victim in data[:20]:
            if not isinstance(victim, dict):
                continue
            victim_name = str(victim.get('victim') or victim.get('name') or '').strip()
            attack_date = str(victim.get('attackdate') or victim.get('discovery_date') or '').strip()
            country = str(victim.get('country') or '').strip()
            if not victim_name:
                continue
            entry = f'{attack_date or "unknown-date"} - {victim_name}'
            if country:
                entry += f' ({country})'
                country_counts[country] = country_counts.get(country, 0) + 1
            parsed_date = _parse_published_datetime(attack_date)
            if parsed_date and parsed_date >= cutoff_90:
                recent_90 += 1
            if parsed_date and (latest_attack_dt is None or parsed_date > latest_attack_dt):
                latest_attack_dt = parsed_date
                latest_attack_label = parsed_date.date().isoformat()
            lines.append(entry)
            if len(lines) >= 15:
                break

        if not lines:
            continue

        top_countries = sorted(country_counts.items(), key=lambda item: item[1], reverse=True)[:3]
        countries_text = ', '.join([f'{country} ({count})' for country, count in top_countries]) if top_countries else 'not specified'
        examples = '; '.join(lines[:3])
        tempo_text = f'Latest listed activity: {latest_attack_label}. ' if latest_attack_label else ''
        summary = (
            f'Ransomware.live trend for {group}: {len(data)} total public victim disclosures, '
            f'{recent_90} in the last 90 days. '
            f'{tempo_text}'
            f'Most frequent victim geographies in the current sample: {countries_text}. '
            f'Recently observed targets include: {examples}.'
        )
        _upsert_source_for_actor(
            connection,
            actor_id,
            'Ransomware.live',
            endpoint,
            utc_now_iso(),
            summary,
            trigger_excerpt=f'{group} ransomware activity synthesis (tempo, geography, and target examples) from ransomware.live.',
        )
        imported += 1

    return imported


def _ollama_available() -> bool:
    base_url = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434').rstrip('/')
    try:
        response = httpx.get(f'{base_url}/api/tags', timeout=2.5)
        return response.status_code == 200
    except Exception:
        return False


def get_ollama_status() -> dict[str, str | bool]:
    base_url = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434').rstrip('/')
    model = os.environ.get('OLLAMA_MODEL', 'llama3.1:8b')
    try:
        response = httpx.get(f'{base_url}/api/tags', timeout=2.5)
        if response.status_code != 200:
            return {
                'available': False,
                'base_url': base_url,
                'model': model,
                'message': f'Ollama check failed (HTTP {response.status_code}).',
            }
        data = response.json()
        models = data.get('models', []) if isinstance(data, dict) else []
        model_names = {
            str(item.get('name'))
            for item in models
            if isinstance(item, dict) and item.get('name')
        }
        has_model = model in model_names or model.split(':')[0] in {m.split(':')[0] for m in model_names}
        if has_model:
            return {
                'available': True,
                'base_url': base_url,
                'model': model,
                'message': 'Local LLM is reachable and model is available.',
            }
        return {
            'available': True,
            'base_url': base_url,
            'model': model,
            'message': 'Ollama is reachable, but configured model was not found in tags.',
        }
    except Exception as exc:
        return {
            'available': False,
            'base_url': base_url,
            'model': model,
            'message': f'Ollama is not reachable: {exc}',
        }


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


def _ollama_generate_requirements(
    actor_name: str,
    priority_mode: str,
    org_context: str,
    evidence_rows: list[dict[str, str | None]],
) -> list[dict[str, str]]:
    if not evidence_rows or not _ollama_available():
        return []

    model = os.environ.get('OLLAMA_MODEL', 'llama3.1:8b')
    base_url = os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434').rstrip('/')
    evidence_payload = [
        {
            'source_name': row.get('source_name') or '',
            'source_url': row.get('source_url') or '',
            'source_published_at': row.get('source_published_at') or '',
            'excerpt': row.get('excerpt') or '',
        }
        for row in evidence_rows[:10]
    ]
    prompt = (
        'You generate cybersecurity intelligence requirements for analysts. '
        'Return ONLY strict JSON: {"requirements":[{'
        '"req_type":"PIR|GIR|IR","requirement_text":"...","rationale":"...",'
        '"source_url":"...","source_name":"...","source_published_at":"..."}]}. '
        'Use plain English. Keep each requirement <= 22 words. '
        f'Actor: {actor_name}. Priority mode: {priority_mode}. '
        f'Org context: {org_context or "none"}. '
        f'Evidence: {json.dumps(evidence_payload)}'
    )
    payload = {
        'model': model,
        'prompt': prompt,
        'stream': False,
        'format': 'json',
    }
    try:
        response = httpx.post(f'{base_url}/api/generate', json=payload, timeout=30.0)
        response.raise_for_status()
        content = response.json().get('response', '{}')
        parsed = json.loads(content)
        reqs = parsed.get('requirements', []) if isinstance(parsed, dict) else []
        cleaned: list[dict[str, str]] = []
        for item in reqs:
            if not isinstance(item, dict):
                continue
            req_type = str(item.get('req_type') or 'IR').upper()
            if req_type not in {'PIR', 'GIR', 'IR'}:
                req_type = 'IR'
            requirement_text = ' '.join(str(item.get('requirement_text') or '').split()).strip()
            rationale = ' '.join(str(item.get('rationale') or '').split()).strip()
            source_url = str(item.get('source_url') or '').strip()
            source_name = str(item.get('source_name') or '').strip()
            source_published_at = str(item.get('source_published_at') or '').strip()
            if not requirement_text:
                continue
            cleaned.append(
                {
                    'req_type': req_type,
                    'requirement_text': requirement_text[:220],
                    'rationale': rationale[:320],
                    'source_url': source_url,
                    'source_name': source_name,
                    'source_published_at': source_published_at,
                }
            )
            if len(cleaned) >= 8:
                break
        return cleaned
    except Exception:
        return []


def _generate_requirements_fallback(
    actor_name: str,
    priority_mode: str,
    evidence_rows: list[dict[str, str | None]],
) -> list[dict[str, str]]:
    type_hint = 'PIR' if priority_mode == 'Strategic' else ('GIR' if priority_mode == 'Operational' else 'IR')
    output: list[dict[str, str]] = []
    for row in evidence_rows[:6]:
        excerpt = str(row.get('excerpt') or '').strip()
        if not excerpt:
            continue
        question = _sanitize_question_text(_question_from_sentence(excerpt))
        if not question:
            continue
        output.append(
            {
                'req_type': type_hint,
                'requirement_text': question,
                'rationale': f'Based on recent {actor_name} reporting and observed activity.',
                'source_url': str(row.get('source_url') or ''),
                'source_name': str(row.get('source_name') or ''),
                'source_published_at': str(row.get('source_published_at') or ''),
            }
        )
    return output


def _expected_req_type(priority_mode: str) -> str:
    if priority_mode == 'Strategic':
        return 'PIR'
    if priority_mode == 'Operational':
        return 'GIR'
    return 'IR'


def _clean_requirement_text(value: str) -> str:
    text = ' '.join(value.split()).strip()
    if not text:
        return ''
    if not text.endswith('?'):
        text = text.rstrip('.!') + '?'
    return text[:220]


def _best_evidence_for_requirement(
    requirement_text: str,
    evidence_rows: list[dict[str, str | None]],
) -> dict[str, str | None] | None:
    best_row: dict[str, str | None] | None = None
    best_score = 0.0
    for row in evidence_rows:
        excerpt = str(row.get('excerpt') or '')
        score = _token_overlap(requirement_text, excerpt)
        if score > best_score:
            best_score = score
            best_row = row
    if best_row is None and evidence_rows:
        return evidence_rows[0]
    return best_row


def _kraven_style_requirement_check(
    item: dict[str, str],
    actor_name: str,
    expected_type: str,
    org_context: str,
) -> tuple[bool, int, list[str]]:
    issues: list[str] = []
    score = 0
    req_text = str(item.get('requirement_text') or '')
    rationale = str(item.get('rationale') or '')
    source_url = str(item.get('source_url') or '')
    source_name = str(item.get('source_name') or '')

    if source_url and source_name:
        score += 2
    else:
        issues.append('missing source lineage')

    words = req_text.rstrip('?').split()
    if 7 <= len(words) <= 30:
        score += 1
    else:
        issues.append('question length out of range')

    if req_text.endswith('?'):
        score += 1
    else:
        issues.append('not phrased as a question')

    if req_text.lower().startswith(('what ', 'which ', 'how ', 'where ', 'when ', 'who ')):
        score += 1
    else:
        issues.append('question not interrogative')

    actor_tokens = [tok for tok in re.findall(r'[a-z0-9]+', actor_name.lower()) if len(tok) > 2]
    if actor_tokens and any(token in req_text.lower() for token in actor_tokens):
        score += 1
    else:
        issues.append('actor reference missing')

    if rationale and any(token in rationale.lower() for token in ('decision', 'priority', 'risk', 'action', 'impact')):
        score += 1
    else:
        issues.append('weak decision linkage in rationale')

    if org_context.strip():
        ctx_tokens = [tok for tok in re.findall(r'[a-z0-9]+', org_context.lower()) if len(tok) > 3][:8]
        if ctx_tokens and any(tok in (req_text + ' ' + rationale).lower() for tok in ctx_tokens):
            score += 1

    text_lower = (req_text + ' ' + rationale).lower()
    if expected_type == 'PIR':
        if any(tok in text_lower for tok in ('intent', 'objective', 'risk', 'impact', 'campaign', 'targeting')):
            score += 2
        else:
            issues.append('PIR missing strategic framing')
    elif expected_type == 'GIR':
        if any(tok in text_lower for tok in ('trend', 'change', 'pattern', 'activity', 'capability', 'infrastructure')):
            score += 2
        else:
            issues.append('GIR missing operational framing')
    else:
        if any(tok in text_lower for tok in ('ioc', 'domain', 'ip', 'hash', 'process', 'command', 'technique', 't1')):
            score += 2
        else:
            issues.append('IR missing observable indicators')

    is_valid = score >= 7 and 'missing source lineage' not in issues
    return is_valid, score, issues


def _normalize_and_validate_requirements(
    generated: list[dict[str, str]],
    actor_name: str,
    priority_mode: str,
    org_context: str,
    evidence_rows: list[dict[str, str | None]],
) -> list[dict[str, str]]:
    expected_type = _expected_req_type(priority_mode)
    validated: list[dict[str, str]] = []
    seen_questions: set[str] = set()

    for raw in generated:
        requirement_text = _clean_requirement_text(str(raw.get('requirement_text') or ''))
        if not requirement_text:
            continue
        evidence = _best_evidence_for_requirement(requirement_text, evidence_rows) or {}
        normalized = {
            'req_type': expected_type,
            'requirement_text': requirement_text,
            'rationale': str(raw.get('rationale') or '').strip() or 'Supports analyst decision-making for this actor.',
            'source_url': str(raw.get('source_url') or evidence.get('source_url') or '').strip(),
            'source_name': str(raw.get('source_name') or evidence.get('source_name') or '').strip(),
            'source_published_at': str(raw.get('source_published_at') or evidence.get('source_published_at') or '').strip(),
        }
        key = _normalize_text(normalized['requirement_text'])
        if key in seen_questions:
            continue

        ok, score, issues = _kraven_style_requirement_check(normalized, actor_name, expected_type, org_context)
        if not ok:
            continue
        normalized['validation_score'] = str(score)
        normalized['validation_notes'] = 'passed' if not issues else '; '.join(issues)
        seen_questions.add(key)
        validated.append(normalized)
        if len(validated) >= 8:
            break

    return validated


def actor_exists(connection: sqlite3.Connection, actor_id: str) -> bool:
    row = connection.execute('SELECT id FROM actor_profiles WHERE id = ?', (actor_id,)).fetchone()
    return row is not None


def set_actor_notebook_status(actor_id: str, status: str, message: str) -> None:
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            '''
            UPDATE actor_profiles
            SET notebook_status = ?, notebook_message = ?, notebook_updated_at = ?
            WHERE id = ?
            ''',
            (status, message, utc_now_iso(), actor_id),
        )
        connection.commit()


def run_actor_generation(actor_id: str) -> None:
    try:
        imported = import_default_feeds_for_actor(actor_id)
        build_notebook(actor_id)
        set_actor_notebook_status(
            actor_id,
            'ready',
            f'Notebook ready. Imported {imported} feed source(s).',
        )
    except Exception as exc:
        set_actor_notebook_status(actor_id, 'error', f'Notebook generation failed: {exc}')


def list_actor_profiles() -> list[dict[str, object]]:
    with sqlite3.connect(DB_PATH) as connection:
        rows = connection.execute(
            '''
            SELECT
                id, display_name, scope_statement, created_at, is_tracked,
                notebook_status, notebook_message, notebook_updated_at
            FROM actor_profiles
            ORDER BY created_at DESC
            '''
        ).fetchall()
    return [
        {
            'id': row[0],
            'display_name': row[1],
            'scope_statement': row[2],
            'created_at': row[3],
            'is_tracked': bool(row[4]),
            'notebook_status': row[5],
            'notebook_message': row[6],
            'notebook_updated_at': row[7],
        }
        for row in rows
    ]


def create_actor_profile(
    display_name: str,
    scope_statement: str | None,
    is_tracked: bool = True,
) -> dict[str, str | None]:
    actor_profile = {
        'id': str(uuid.uuid4()),
        'display_name': display_name,
        'scope_statement': scope_statement,
        'created_at': utc_now_iso(),
    }
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            '''
            INSERT INTO actor_profiles (id, display_name, scope_statement, created_at, is_tracked)
            VALUES (?, ?, ?, ?, ?)
            ''',
            (
                actor_profile['id'],
                actor_profile['display_name'],
                actor_profile['scope_statement'],
                actor_profile['created_at'],
                1 if is_tracked else 0,
            ),
        )
        connection.execute(
            '''
            UPDATE actor_profiles
            SET notebook_status = ?,
                notebook_message = ?,
                notebook_updated_at = ?
            WHERE id = ?
            ''',
            (
                'running' if is_tracked else 'idle',
                'Preparing notebook generation...' if is_tracked else 'Waiting for tracking action.',
                utc_now_iso(),
                actor_profile['id'],
            ),
        )
        connection.commit()
    return actor_profile


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
    existing = connection.execute(
        'SELECT id FROM sources WHERE actor_id = ? AND url = ?',
        (actor_id, source_url),
    ).fetchone()
    if existing is not None:
        metadata_values = [title, headline, og_title, html_title, publisher, site_name]
        if any(str(value or '').strip() for value in metadata_values):
            connection.execute(
                '''
                UPDATE sources
                SET title = COALESCE(NULLIF(title, ''), ?),
                    headline = COALESCE(NULLIF(headline, ''), ?),
                    og_title = COALESCE(NULLIF(og_title, ''), ?),
                    html_title = COALESCE(NULLIF(html_title, ''), ?),
                    publisher = COALESCE(NULLIF(publisher, ''), ?),
                    site_name = COALESCE(NULLIF(site_name, ''), ?)
                WHERE id = ?
                ''',
                (
                    str(title or '').strip() or None,
                    str(headline or '').strip() or None,
                    str(og_title or '').strip() or None,
                    str(html_title or '').strip() or None,
                    str(publisher or '').strip() or None,
                    str(site_name or '').strip() or None,
                    existing[0],
                ),
            )
        return existing[0]

    final_text = pasted_text
    if trigger_excerpt and trigger_excerpt not in final_text:
        final_text = f'{trigger_excerpt}\n\n{pasted_text}'

    source_id = str(uuid.uuid4())
    connection.execute(
        '''
        INSERT INTO sources (
            id, actor_id, source_name, url, published_at, retrieved_at, pasted_text,
            title, headline, og_title, html_title, publisher, site_name
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            source_id,
            actor_id,
            source_name,
            source_url,
            published_at,
            utc_now_iso(),
            final_text,
            str(title or '').strip() or None,
            str(headline or '').strip() or None,
            str(og_title or '').strip() or None,
            str(html_title or '').strip() or None,
            str(publisher or '').strip() or None,
            str(site_name or '').strip() or None,
        ),
    )
    return source_id


def _parse_ioc_values(raw: str) -> list[str]:
    parts = re.split(r'[\n,]+', raw)
    values: list[str] = []
    for part in parts:
        candidate = part.strip()
        if not candidate:
            continue
        if candidate not in values:
            values.append(candidate)
    return values


def import_default_feeds_for_actor(actor_id: str) -> int:
    imported = 0
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')

        actor_row = connection.execute(
            'SELECT display_name FROM actor_profiles WHERE id = ?',
            (actor_id,),
        ).fetchone()
        actor_name = str(actor_row[0] if actor_row else '')
        mitre_profile = _build_actor_profile_from_mitre(actor_name)
        actor_terms = _actor_terms(
            actor_name,
            str(mitre_profile.get('group_name') or ''),
            str(mitre_profile.get('aliases_csv') or ''),
        )

        feed_list: list[tuple[str, str]] = list(DEFAULT_CTI_FEEDS)
        feed_list.extend(_actor_query_feeds(actor_terms))
        seen_links: set[str] = set()
        imported_limit = 60

        # Always attempt ransomware.live first so actor victim activity is available
        # even when other feeds are sparse or noisy.
        imported += _import_ransomware_live_actor_activity(connection, actor_id, actor_terms)

        for feed_name, feed_url in feed_list:
            try:
                feed_resp = httpx.get(feed_url, timeout=20.0, follow_redirects=True)
                feed_resp.raise_for_status()
                entries = _parse_feed_entries(feed_resp.text)
            except Exception:
                continue

            prioritized = sorted(
                entries,
                key=lambda entry: 0 if _text_contains_actor_term(
                    f'{entry.get("title") or ""} {entry.get("link") or ""}',
                    actor_terms,
                ) else 1,
            )

            for entry in prioritized[:40]:
                link = entry.get('link')
                if not link:
                    continue
                if link in seen_links:
                    continue
                if not _within_lookback(entry.get('published_at'), ACTOR_FEED_LOOKBACK_DAYS):
                    continue
                title_text = str(entry.get('title') or '')
                entry_context = f'{title_text} {link}'
                if actor_terms and not _text_contains_actor_term(entry_context, actor_terms):
                    continue
                seen_links.add(link)
                try:
                    derived = derive_source_from_url(
                        link,
                        fallback_source_name=feed_name,
                        published_hint=entry.get('published_at'),
                    )
                    combined_text = (
                        f'{entry.get("title") or ""} '
                        f'{derived.get("source_name") or ""} '
                        f'{derived.get("source_url") or ""} '
                        f'{derived.get("pasted_text") or ""}'
                    )
                    if actor_terms and not _text_contains_actor_term(combined_text, actor_terms):
                        continue
                    resolved_title = str(derived.get('title') or title_text or '').strip() or None
                    resolved_headline = str(derived.get('headline') or title_text or '').strip() or None
                    resolved_og_title = str(derived.get('og_title') or title_text or '').strip() or None
                    resolved_html_title = str(derived.get('html_title') or title_text or '').strip() or None
                    _upsert_source_for_actor(
                        connection,
                        actor_id,
                        str(derived['source_name']),
                        str(derived['source_url']),
                        str(derived['published_at']) if derived['published_at'] else None,
                        str(derived['pasted_text']),
                        str(derived['trigger_excerpt']) if derived['trigger_excerpt'] else None,
                        resolved_title,
                        resolved_headline,
                        resolved_og_title,
                        resolved_html_title,
                        str(derived.get('publisher') or '') or None,
                        str(derived.get('site_name') or '') or None,
                    )
                    imported += 1
                    if imported >= imported_limit:
                        connection.commit()
                        return imported
                except Exception:
                    if actor_terms and _text_contains_actor_term(entry_context, actor_terms):
                        try:
                            _upsert_source_for_actor(
                                connection,
                                actor_id,
                                feed_name,
                                link,
                                entry.get('published_at'),
                                title_text or f'Actor-matched feed item from {feed_name}.',
                                title_text or None,
                                title_text or None,
                                title_text or None,
                                title_text or None,
                                title_text or None,
                                None,
                                feed_name,
                            )
                            imported += 1
                            if imported >= imported_limit:
                                connection.commit()
                                return imported
                        except Exception:
                            pass
                    continue

        # Deterministic actor-focused search fallback for cases where feed parsing
        # misses obvious actor-specific reporting.
        for link in _duckduckgo_actor_search_urls(actor_terms):
            if link in seen_links:
                continue
            seen_links.add(link)
            try:
                derived = derive_source_from_url(link, fallback_source_name='Actor Search')
                combined_text = (
                    f'{derived.get("source_name") or ""} '
                    f'{derived.get("source_url") or ""} '
                    f'{derived.get("pasted_text") or ""}'
                )
                if actor_terms and not _text_contains_actor_term(combined_text, actor_terms):
                    continue
                _upsert_source_for_actor(
                    connection,
                    actor_id,
                    str(derived['source_name']),
                    str(derived['source_url']),
                    str(derived['published_at']) if derived['published_at'] else None,
                    str(derived['pasted_text']),
                    str(derived['trigger_excerpt']) if derived['trigger_excerpt'] else None,
                    str(derived.get('title') or '') or None,
                    str(derived.get('headline') or '') or None,
                    str(derived.get('og_title') or '') or None,
                    str(derived.get('html_title') or '') or None,
                    str(derived.get('publisher') or '') or None,
                    str(derived.get('site_name') or '') or None,
                )
                imported += 1
                if imported >= imported_limit:
                    connection.commit()
                    return imported
            except Exception:
                continue

        connection.commit()
    return imported


def generate_actor_requirements(actor_id: str, org_context: str, priority_mode: str) -> int:
    now = utc_now_iso()
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')

        actor_row = connection.execute(
            'SELECT display_name FROM actor_profiles WHERE id = ?',
            (actor_id,),
        ).fetchone()
        actor_name = str(actor_row[0] if actor_row else 'actor')

        evidence_rows_raw = connection.execute(
            '''
            SELECT s.source_name, s.url, s.published_at, qu.trigger_excerpt
            FROM question_updates qu
            JOIN question_threads qt ON qt.id = qu.thread_id
            JOIN sources s ON s.id = qu.source_id
            WHERE qt.actor_id = ?
            ORDER BY qu.created_at DESC
            LIMIT 16
            ''',
            (actor_id,),
        ).fetchall()
        evidence_rows: list[dict[str, str | None]] = [
            {
                'source_name': row[0],
                'source_url': row[1],
                'source_published_at': row[2],
                'excerpt': row[3],
            }
            for row in evidence_rows_raw
        ]

        if not evidence_rows:
            source_rows = connection.execute(
                '''
                SELECT source_name, url, published_at, pasted_text
                FROM sources
                WHERE actor_id = ?
                ORDER BY retrieved_at DESC
                LIMIT 12
                ''',
                (actor_id,),
            ).fetchall()
            mitre_profile = _build_actor_profile_from_mitre(actor_name)
            actor_terms = _actor_terms(
                actor_name,
                str(mitre_profile.get('group_name') or ''),
                str(mitre_profile.get('aliases_csv') or ''),
            )
            for row in source_rows:
                text = str(row[3] or '')
                for sentence in _split_sentences(text):
                    if actor_terms and not _sentence_mentions_actor_terms(sentence, actor_terms):
                        continue
                    if not _looks_like_activity_sentence(sentence):
                        continue
                    evidence_rows.append(
                        {
                            'source_name': row[0],
                            'source_url': row[1],
                            'source_published_at': row[2],
                            'excerpt': sentence,
                        }
                    )
                    if len(evidence_rows) >= 16:
                        break
                if len(evidence_rows) >= 16:
                    break

        generated = _ollama_generate_requirements(actor_name, priority_mode, org_context, evidence_rows)
        validated = _normalize_and_validate_requirements(
            generated,
            actor_name,
            priority_mode,
            org_context,
            evidence_rows,
        )
        if len(validated) < 3:
            fallback = _generate_requirements_fallback(actor_name, priority_mode, evidence_rows)
            fallback_validated = _normalize_and_validate_requirements(
                fallback,
                actor_name,
                priority_mode,
                org_context,
                evidence_rows,
            )
            for item in fallback_validated:
                key = _normalize_text(str(item.get('requirement_text') or ''))
                if any(_normalize_text(str(existing.get('requirement_text') or '')) == key for existing in validated):
                    continue
                validated.append(item)
                if len(validated) >= 8:
                    break

        connection.execute(
            '''
            INSERT INTO requirement_context (actor_id, org_context, priority_mode, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(actor_id) DO UPDATE SET
                org_context = excluded.org_context,
                priority_mode = excluded.priority_mode,
                updated_at = excluded.updated_at
            ''',
            (actor_id, org_context, priority_mode, now),
        )

        connection.execute('DELETE FROM requirement_items WHERE actor_id = ?', (actor_id,))
        inserted = 0
        for item in validated:
            connection.execute(
                '''
                INSERT INTO requirement_items (
                    id, actor_id, req_type, requirement_text, rationale_text,
                    source_name, source_url, source_published_at,
                    validation_score, validation_notes,
                    status, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    str(uuid.uuid4()),
                    actor_id,
                    str(item.get('req_type') or 'IR'),
                    str(item.get('requirement_text') or ''),
                    str(item.get('rationale') or ''),
                    str(item.get('source_name') or ''),
                    str(item.get('source_url') or ''),
                    str(item.get('source_published_at') or ''),
                    int(str(item.get('validation_score') or '0')),
                    str(item.get('validation_notes') or ''),
                    'open',
                    now,
                ),
            )
            inserted += 1
        connection.commit()
    return inserted


def build_notebook(actor_id: str) -> None:
    now = utc_now_iso()
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')

        actor_row = connection.execute(
            'SELECT display_name, scope_statement FROM actor_profiles WHERE id = ?',
            (actor_id,),
        ).fetchone()
        actor_name = actor_row[0] if actor_row else 'actor'
        actor_scope = actor_row[1] if actor_row else None
        mitre_profile = _build_actor_profile_from_mitre(actor_name)
        actor_terms = _actor_terms(
            actor_name,
            str(mitre_profile.get('group_name') or ''),
            str(mitre_profile.get('aliases_csv') or ''),
        )

        sources = connection.execute(
            '''
            SELECT id, source_name, url, published_at, retrieved_at, pasted_text
            FROM sources
            WHERE actor_id = ?
            ORDER BY retrieved_at ASC
            ''',
            (actor_id,),
        ).fetchall()

        connection.execute('DELETE FROM timeline_events WHERE actor_id = ?', (actor_id,))
        timeline_candidates: list[dict[str, object]] = []
        for source in sources:
            occurred_at = source[3] or source[4]
            text = source[5] or ''
            moves = _extract_major_move_events(source[1], source[0], occurred_at, text, actor_terms)
            if moves:
                timeline_candidates.extend(moves[:6])

        deduped_timeline: list[dict[str, object]] = []
        seen_summaries: list[str] = []
        for event in sorted(timeline_candidates, key=lambda item: str(item['occurred_at'])):
            norm = _normalize_text(str(event['summary']))
            if any(_token_overlap(norm, existing) >= 0.75 for existing in seen_summaries):
                continue
            deduped_timeline.append(event)
            seen_summaries.append(norm)

        for event in deduped_timeline:
            connection.execute(
                '''
                INSERT INTO timeline_events (
                    id, actor_id, occurred_at, category, title, summary, source_id, target_text, ttp_ids_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    str(event['id']),
                    actor_id,
                    str(event['occurred_at']),
                    str(event['category']),
                    str(event['title']),
                    str(event['summary']),
                    str(event['source_id']),
                    str(event.get('target_text') or ''),
                    json.dumps(event.get('ttp_ids') or []),
                ),
            )

        thread_rows = connection.execute(
            '''
            SELECT id, question_text, status, created_at, updated_at
            FROM question_threads
            WHERE actor_id = ?
            ORDER BY created_at ASC
            ''',
            (actor_id,),
        ).fetchall()
        thread_cache: list[dict[str, str]] = [
            {
                'id': row[0],
                'question_text': row[1],
                'status': row[2],
                'created_at': row[3],
                'updated_at': row[4],
            }
            for row in thread_rows
        ]

        source_sentence_records: list[dict[str, str]] = []
        for source in sources:
            source_id = source[0]
            text = source[5] or ''
            for sentence in _extract_question_sentences(text):
                if actor_terms and not _sentence_mentions_actor_terms(sentence, actor_terms):
                    continue
                source_sentence_records.append(
                    {
                        'source_id': source_id,
                        'sentence': sentence,
                        'question_text': _sanitize_question_text(_question_from_sentence(sentence)),
                    }
                )

        llm_candidates = _ollama_generate_questions(
            actor_name,
            actor_scope,
            [record['sentence'] for record in source_sentence_records],
        )
        for candidate in llm_candidates:
            best_sentence = None
            best_source = None
            best_score = 0.0
            for record in source_sentence_records:
                score = _token_overlap(candidate, record['sentence'])
                if score > best_score:
                    best_score = score
                    best_sentence = record['sentence']
                    best_source = record['source_id']
            if best_sentence and best_source and best_score >= 0.20:
                source_sentence_records.append(
                    {
                        'source_id': best_source,
                        'sentence': best_sentence,
                        'question_text': candidate,
                    }
                )

        for record in source_sentence_records:
            source_id = record['source_id']
            sentence = record['sentence']
            question_text = record['question_text']
            best_thread: dict[str, str] | None = None
            best_score = 0.0
            for candidate in thread_cache:
                score = _token_overlap(question_text, candidate['question_text'])
                if score > best_score:
                    best_score = score
                    best_thread = candidate

            if best_thread is not None and best_score >= 0.45:
                thread_id = best_thread['id']
                connection.execute(
                    'UPDATE question_threads SET updated_at = ? WHERE id = ?',
                    (now, thread_id),
                )
            else:
                thread_id = str(uuid.uuid4())
                connection.execute(
                    '''
                    INSERT INTO question_threads (
                        id, actor_id, question_text, status, created_at, updated_at
                    )
                    VALUES (?, ?, ?, 'open', ?, ?)
                    ''',
                    (thread_id, actor_id, question_text, now, now),
                )
                thread_cache.append(
                    {
                        'id': thread_id,
                        'question_text': question_text,
                        'status': 'open',
                        'created_at': now,
                        'updated_at': now,
                    }
                )

            existing_update = connection.execute(
                '''
                SELECT id
                FROM question_updates
                WHERE thread_id = ? AND source_id = ? AND trigger_excerpt = ?
                ''',
                (thread_id, source_id, sentence),
            ).fetchone()
            if existing_update is None:
                connection.execute(
                    '''
                    INSERT INTO question_updates (
                        id, thread_id, source_id, trigger_excerpt, update_note, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ''',
                    (str(uuid.uuid4()), thread_id, source_id, sentence, None, now),
                )

        connection.execute('DELETE FROM environment_guidance WHERE actor_id = ?', (actor_id,))
        open_threads = connection.execute(
            '''
            SELECT id, question_text
            FROM question_threads
            WHERE actor_id = ? AND status = 'open'
            ORDER BY created_at ASC
            ''',
            (actor_id,),
        ).fetchall()
        for thread in open_threads:
            thread_id = thread[0]
            question_text = thread[1]
            for platform in _platforms_for_question(question_text):
                guidance = _guidance_for_platform(platform, question_text)
                connection.execute(
                    '''
                    INSERT INTO environment_guidance (
                        id, actor_id, thread_id, platform,
                        what_to_look_for, where_to_look, query_hint, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        str(uuid.uuid4()),
                        actor_id,
                        thread_id,
                        guidance['platform'],
                        guidance['what_to_look_for'],
                        guidance['where_to_look'],
                        guidance['query_hint'],
                        now,
                    ),
                )

        connection.commit()


def _fetch_actor_notebook(actor_id: str) -> dict[str, object]:
    with sqlite3.connect(DB_PATH) as connection:
        actor_row = connection.execute(
            '''
            SELECT
                id, display_name, scope_statement, created_at, is_tracked,
                notebook_status, notebook_message, notebook_updated_at
            FROM actor_profiles
            WHERE id = ?
            ''',
            (actor_id,),
        ).fetchone()
        if actor_row is None:
            raise HTTPException(status_code=404, detail='actor not found')

        sources = connection.execute(
            '''
            SELECT
                id, source_name, url, published_at, retrieved_at, pasted_text,
                title, headline, og_title, html_title, publisher, site_name
            FROM sources
            WHERE actor_id = ?
            ORDER BY COALESCE(published_at, retrieved_at) DESC
            ''',
            (actor_id,),
        ).fetchall()

        timeline_rows = connection.execute(
            '''
            SELECT id, occurred_at, category, title, summary, source_id, target_text, ttp_ids_json
            FROM timeline_events
            WHERE actor_id = ?
            ORDER BY occurred_at ASC
            ''',
            (actor_id,),
        ).fetchall()

        thread_rows = connection.execute(
            '''
            SELECT id, question_text, status, created_at, updated_at
            FROM question_threads
            WHERE actor_id = ?
            ORDER BY updated_at DESC
            ''',
            (actor_id,),
        ).fetchall()

        updates_by_thread: dict[str, list[dict[str, object]]] = {}
        for thread_row in thread_rows:
            thread_id = thread_row[0]
            update_rows = connection.execute(
                '''
                SELECT
                    qu.id,
                    qu.trigger_excerpt,
                    qu.update_note,
                    qu.created_at,
                    s.source_name,
                    s.url,
                    s.published_at
                FROM question_updates qu
                JOIN sources s ON s.id = qu.source_id
                WHERE qu.thread_id = ?
                ORDER BY qu.created_at DESC
                ''',
                (thread_id,),
            ).fetchall()
            updates_by_thread[thread_id] = [
                {
                    'id': update_row[0],
                    'trigger_excerpt': update_row[1],
                    'update_note': update_row[2],
                    'created_at': update_row[3],
                    'source_name': update_row[4],
                    'source_url': update_row[5],
                    'source_published_at': update_row[6],
                }
                for update_row in update_rows
            ]

        guidance_rows = connection.execute(
            '''
            SELECT id, thread_id, platform, what_to_look_for, where_to_look, query_hint, created_at
            FROM environment_guidance
            WHERE actor_id = ?
            ORDER BY created_at ASC
            ''',
            (actor_id,),
        ).fetchall()
        ioc_rows = connection.execute(
            '''
            SELECT id, ioc_type, ioc_value, source_ref, created_at
            FROM ioc_items
            WHERE actor_id = ?
            ORDER BY created_at DESC
            ''',
            (actor_id,),
        ).fetchall()
        context_row = connection.execute(
            '''
            SELECT org_context, priority_mode, updated_at
            FROM requirement_context
            WHERE actor_id = ?
            ''',
            (actor_id,),
        ).fetchone()
        requirement_rows = connection.execute(
            '''
            SELECT id, req_type, requirement_text, rationale_text,
                   source_name, source_url, source_published_at,
                   validation_score, validation_notes,
                   status, created_at
            FROM requirement_items
            WHERE actor_id = ?
            ORDER BY created_at DESC
            ''',
            (actor_id,),
        ).fetchall()

        guidance_by_thread: dict[str, list[dict[str, object]]] = {}
        for row in guidance_rows:
            guidance_by_thread.setdefault(row[1], []).append(
                {
                    'id': row[0],
                    'platform': row[2],
                    'what_to_look_for': row[3],
                    'where_to_look': row[4],
                    'query_hint': row[5],
                    'created_at': row[6],
                }
            )

    actor = {
        'id': actor_row[0],
        'display_name': actor_row[1],
        'scope_statement': actor_row[2],
        'created_at': actor_row[3],
        'is_tracked': bool(actor_row[4]),
        'notebook_status': actor_row[5],
        'notebook_message': actor_row[6],
        'notebook_updated_at': actor_row[7],
    }
    timeline_items: list[dict[str, object]] = [
        {
            'id': row[0],
            'occurred_at': row[1],
            'category': row[2],
            'title': row[3],
            'summary': row[4],
            'source_id': row[5],
            'target_text': row[6],
            'ttp_ids': _safe_json_string_list(row[7]),
        }
        for row in timeline_rows
    ]
    cutoff_90 = datetime.now(timezone.utc) - timedelta(days=90)
    timeline_recent_items = [
        item
        for item in timeline_items
        if (
            (dt := _parse_published_datetime(str(item.get('occurred_at') or ''))) is not None
            and dt >= cutoff_90
        )
    ]

    thread_items: list[dict[str, object]] = []
    for row in thread_rows:
        thread_items.append(
            {
                'id': row[0],
                'question_text': row[1],
                'status': row[2],
                'created_at': row[3],
                'updated_at': row[4],
                'updates': updates_by_thread.get(row[0], []),
            }
        )

    open_thread_ids = [thread['id'] for thread in thread_items if thread['status'] == 'open']
    guidance_for_open = [
        {
            'thread_id': thread_id,
            'question_text': next(item['question_text'] for item in thread_items if item['id'] == thread_id),
            'guidance_items': guidance_by_thread.get(thread_id, []),
        }
        for thread_id in open_thread_ids
    ]
    priority_questions: list[dict[str, object]] = []
    open_threads = [thread for thread in thread_items if thread['status'] == 'open']
    actor_categories = _actor_signal_categories(timeline_recent_items)
    signal_text = ' '.join(
        [
            str(item.get('summary') or '')
            for item in timeline_recent_items
        ]
    ).lower()
    sorted_open_threads = sorted(
        open_threads,
        key=lambda thread: (
            _question_priority_score(thread),
            _parse_iso_for_sort(str(thread.get('updated_at') or '')),
        ),
        reverse=True,
    )
    for thread in sorted_open_threads:
        question_text = str(thread['question_text'])
        relevance = _question_actor_relevance(question_text, actor_categories, signal_text)
        if relevance <= 1:
            continue
        updates = thread.get('updates', [])
        latest_update = updates[0] if isinstance(updates, list) and updates else None
        score = _question_priority_score(thread) + relevance
        latest_excerpt = (
            str(latest_update.get('trigger_excerpt') or '')
            if isinstance(latest_update, dict)
            else ''
        )
        latest_excerpt = ' '.join(latest_excerpt.split())
        if len(latest_excerpt) > 180:
            latest_excerpt = latest_excerpt[:180].rsplit(' ', 1)[0] + '...'
        if score >= 8:
            priority = 'High'
        elif score >= 6:
            priority = 'Medium'
        else:
            priority = 'Low'
        guidance_items = guidance_by_thread.get(str(thread['id']), [])
        updates_count = len(updates) if isinstance(updates, list) else 0
        phase_label = _phase_label_for_question(question_text)
        priority_questions.append(
            {
                'id': thread['id'],
                'phase_label': phase_label,
                'quick_check_title': _quick_check_title(question_text, phase_label),
                'decision_trigger': _short_decision_trigger(question_text),
                'telemetry_anchor': _telemetry_anchor_line(guidance_items, question_text),
                'escalation_threshold': _escalation_threshold_line(question_text),
                'priority': priority,
                'updates_count': updates_count,
                'updated_at': thread['updated_at'],
            }
        )
        if len(priority_questions) >= 5:
            break

    if len(priority_questions) < 3:
        fallback_items = _fallback_priority_questions(str(actor['display_name']), actor_categories)
        for idx, item in enumerate(fallback_items, start=1):
            if any(
                _token_overlap(str(existing.get('decision_trigger') or ''), str(item.get('question_text') or '')) >= 0.7
                for existing in priority_questions
            ):
                continue
            fallback_question_text = str(item['question_text'])
            priority_questions.append(
                {
                    'id': f'fallback-{idx}',
                    'phase_label': _phase_label_for_question(fallback_question_text),
                    'quick_check_title': _quick_check_title(
                        fallback_question_text,
                        _phase_label_for_question(fallback_question_text),
                    ),
                    'decision_trigger': _short_decision_trigger(fallback_question_text),
                    'telemetry_anchor': f'Anchor: {str(item["where_to_check"])}.',
                    'escalation_threshold': _escalation_threshold_line(fallback_question_text),
                    'priority': str(item['priority']),
                    'updates_count': 0,
                    'updated_at': '',
                }
            )
            if len(priority_questions) >= 5:
                break

    phase_group_order: list[str] = []
    phase_groups_map: dict[str, list[dict[str, object]]] = {}
    for card in priority_questions:
        phase = str(card.get('phase_label') or 'Operational Signal')
        if phase not in phase_groups_map:
            phase_groups_map[phase] = []
            phase_group_order.append(phase)
        phase_groups_map[phase].append(card)
    priority_phase_groups = [{'phase': phase, 'cards': phase_groups_map[phase]} for phase in phase_group_order]

    source_items = [
        {
            'id': row[0],
            'source_name': row[1],
            'url': row[2],
            'published_at': row[3],
            'retrieved_at': row[4],
            'pasted_text': row[5],
            'title': row[6],
            'headline': row[7],
            'og_title': row[8],
            'html_title': row[9],
            'publisher': row[10],
            'site_name': row[11],
        }
        for row in sources
    ]
    mitre_profile = _build_actor_profile_from_mitre(str(actor['display_name']))
    actor_profile_summary = str(mitre_profile['summary'])
    top_techniques = _group_top_techniques(str(mitre_profile.get('stix_id') or ''))
    favorite_vectors = _favorite_attack_vectors(top_techniques)
    known_technique_ids = {str(item.get('technique_id') or '').upper() for item in top_techniques if item.get('technique_id')}
    emerging_technique_ids = _emerging_technique_ids_from_timeline(timeline_recent_items, known_technique_ids)
    emerging_techniques_with_dates = _first_seen_for_techniques(timeline_recent_items, emerging_technique_ids)
    timeline_graph = _build_timeline_graph(timeline_recent_items)
    timeline_compact_rows = _compact_timeline_rows(timeline_items, known_technique_ids)
    actor_terms = _actor_terms(
        str(actor['display_name']),
        str(mitre_profile.get('group_name') or ''),
        str(mitre_profile.get('aliases_csv') or ''),
    )
    recent_activity_highlights = _build_recent_activity_highlights(timeline_items, source_items, actor_terms)
    recent_activity_synthesis = _build_recent_activity_synthesis(recent_activity_highlights)
    recent_change_summary = _recent_change_summary(timeline_recent_items, recent_activity_highlights, source_items)
    environment_checks = _build_environment_checks(
        timeline_recent_items,
        recent_activity_highlights,
        top_techniques,
    )
    notebook_kpis = _build_notebook_kpis(
        timeline_items,
        known_technique_ids,
        len(open_thread_ids),
        source_items,
    )

    return {
        'actor': actor,
        'sources': source_items,
        'timeline_items': timeline_items,
        'timeline_recent_items': timeline_recent_items,
        'timeline_window_label': 'Last 90 days',
        'threads': thread_items,
        'guidance_for_open': guidance_for_open,
        'actor_profile_summary': actor_profile_summary,
        'actor_profile_source_label': str(mitre_profile['source_label']),
        'actor_profile_source_url': str(mitre_profile['source_url']),
        'actor_profile_group_name': str(mitre_profile['group_name']),
        'actor_created_date': _format_date_or_unknown(str(actor.get('created_at') or '')),
        'favorite_vectors': favorite_vectors,
        'top_techniques': top_techniques,
        'emerging_technique_ids': emerging_technique_ids,
        'emerging_techniques_with_dates': emerging_techniques_with_dates,
        'timeline_graph': timeline_graph,
        'timeline_compact_rows': timeline_compact_rows,
        'recent_activity_highlights': recent_activity_highlights,
        'recent_activity_synthesis': recent_activity_synthesis,
        'recent_change_summary': recent_change_summary,
        'environment_checks': environment_checks,
        'kpis': notebook_kpis,
        'ioc_items': [
            {
                'id': row[0],
                'ioc_type': row[1],
                'ioc_value': row[2],
                'source_ref': row[3],
                'created_at': row[4],
            }
            for row in ioc_rows
        ],
        'requirements_context': {
            'org_context': str(context_row[0]) if context_row else '',
            'priority_mode': str(context_row[1]) if context_row else 'Operational',
            'updated_at': str(context_row[2]) if context_row and context_row[2] else '',
        },
        'requirements': [
            {
                'id': row[0],
                'req_type': row[1],
                'requirement_text': row[2],
                'rationale_text': row[3],
                'source_name': row[4],
                'source_url': row[5],
                'source_published_at': row[6],
                'validation_score': row[7],
                'validation_notes': row[8],
                'status': row[9],
                'created_at': row[10],
            }
            for row in requirement_rows
        ],
        'priority_questions': priority_questions,
        'priority_phase_groups': priority_phase_groups,
        'counts': {
            'sources': len(sources),
            'timeline_events': len(timeline_rows),
            'open_questions': len(open_thread_ids),
        },
    }


def initialize_sqlite() -> None:
    global DB_PATH
    DB_PATH = _resolve_startup_db_path()
    _ensure_mitre_attack_dataset()
    global MITRE_GROUP_CACHE, MITRE_DATASET_CACHE
    MITRE_GROUP_CACHE = None
    MITRE_DATASET_CACHE = None
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
                pasted_text TEXT NOT NULL
            )
            '''
        )
        source_cols = connection.execute('PRAGMA table_info(sources)').fetchall()
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


@app.get('/health')
def health() -> dict[str, str]:
    return {'status': 'ok'}


@app.get('/', response_class=HTMLResponse)
def root(
    request: Request,
    background_tasks: BackgroundTasks,
    actor_id: str | None = None,
    notice: str | None = None,
) -> HTMLResponse:
    actors_all = list_actor_profiles()
    tracked_actors = [actor for actor in actors_all if actor['is_tracked']]

    selected_actor_id = actor_id
    all_actor_ids = {actor['id'] for actor in actors_all}
    if selected_actor_id is None:
        if tracked_actors:
            selected_actor_id = tracked_actors[0]['id']
        elif actors_all:
            selected_actor_id = actors_all[0]['id']

    if selected_actor_id is not None and selected_actor_id not in all_actor_ids:
        selected_actor_id = tracked_actors[0]['id'] if tracked_actors else (actors_all[0]['id'] if actors_all else None)

    notebook: dict[str, object] | None = None
    if selected_actor_id is not None:
        try:
            notebook = _fetch_actor_notebook(selected_actor_id)
            actor_meta = notebook.get('actor', {}) if isinstance(notebook, dict) else {}
            is_tracked = bool(actor_meta.get('is_tracked'))
            status = str(actor_meta.get('notebook_status') or '')
            needs_activity = not bool(notebook.get('recent_activity_highlights'))
            if is_tracked and needs_activity and status != 'running':
                set_actor_notebook_status(
                    selected_actor_id,
                    'running',
                    'Collecting actor-specific sources and rebuilding recent activity...',
                )
                background_tasks.add_task(run_actor_generation, selected_actor_id)
                actor_meta['notebook_status'] = 'running'
                actor_meta['notebook_message'] = 'Collecting actor-specific sources and rebuilding recent activity...'
                if not notice:
                    notice = 'Collecting actor-specific sources in the background...'
        except Exception:
            notebook = None
            if not notice:
                notice = 'Unable to load notebook for selected actor.'

    try:
        ollama_status = get_ollama_status()
    except Exception:
        ollama_status = {'available': False, 'base_url': '', 'model': ''}
    notebook_health = {'state': 'ready', 'message': 'Notebook is ready.'}
    if notebook is not None:
        actor_meta = notebook.get('actor', {}) if isinstance(notebook, dict) else {}
        status = str(actor_meta.get('notebook_status') or 'idle')
        source_count = int(notebook.get('counts', {}).get('sources', 0)) if isinstance(notebook, dict) else 0
        if status == 'running':
            notebook_health = {'state': 'running', 'message': 'Refreshing notebook...'}
        elif status == 'error':
            notebook_health = {'state': 'error', 'message': 'Refresh failed.'}
        elif source_count == 0:
            notebook_health = {'state': 'idle', 'message': 'Needs sources.'}
        elif not bool(ollama_status.get('available')):
            notebook_health = {'state': 'warning', 'message': 'LLM offline.'}
        else:
            notebook_health = {'state': 'ready', 'message': 'Notebook is ready.'}

    return templates.TemplateResponse(
        request,
        'index.html',
        {
            'actors': tracked_actors,
            'all_actors': actors_all,
            'selected_actor_id': selected_actor_id,
            'notebook': notebook,
            'notice': notice,
            'ollama_status': ollama_status,
            'notebook_health': notebook_health,
        },
    )


@app.get('/actors')
def get_actors() -> list[dict[str, str | None]]:
    actors = list_actor_profiles()
    return [
        {
            'id': str(actor['id']),
            'display_name': str(actor['display_name']),
            'scope_statement': actor['scope_statement'],
            'created_at': str(actor['created_at']),
        }
        for actor in actors
    ]


@app.post('/actors')
async def create_actor(request: Request) -> dict[str, str | None]:
    await _enforce_request_size(request, DEFAULT_BODY_LIMIT_BYTES)
    content_type = request.headers.get('content-type', '')
    if 'application/json' in content_type:
        payload = await request.json()
    else:
        form_data = await request.form()
        payload = dict(form_data)

    display_name_raw = payload.get('display_name')
    is_tracked_raw = payload.get('is_tracked')
    display_name = str(display_name_raw).strip() if display_name_raw is not None else ''
    scope_statement = None
    if is_tracked_raw is None:
        is_tracked = True
    else:
        is_tracked = str(is_tracked_raw).strip().lower() in {'1', 'true', 'on', 'yes'}

    if not display_name:
        raise HTTPException(status_code=400, detail='display_name is required')

    return create_actor_profile(display_name, scope_statement, is_tracked=is_tracked)


@app.post('/actors/new')
async def create_actor_ui(request: Request, background_tasks: BackgroundTasks) -> RedirectResponse:
    await _enforce_request_size(request, DEFAULT_BODY_LIMIT_BYTES)
    form_data = await request.form()
    display_name = str(form_data.get('display_name', '')).strip()
    scope_statement = None
    is_tracked = True
    if not display_name:
        raise HTTPException(status_code=400, detail='display_name is required')
    actor = create_actor_profile(display_name, scope_statement, is_tracked=is_tracked)
    set_actor_notebook_status(
        actor['id'],
        'running',
        'Actor added. Importing sources and generating notebook sections...',
    )
    background_tasks.add_task(run_actor_generation, actor['id'])
    return RedirectResponse(
        url=f'/?actor_id={actor["id"]}&notice=Tracking+started.+Building+notebook+in+the+background.',
        status_code=303,
    )


@app.post('/actors/{actor_id}/track')
def track_actor(actor_id: str, background_tasks: BackgroundTasks) -> RedirectResponse:
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')
        connection.execute('UPDATE actor_profiles SET is_tracked = 1 WHERE id = ?', (actor_id,))
        connection.commit()
    set_actor_notebook_status(
        actor_id,
        'running',
        'Fetching sources and generating open analytic questions and timeline entries...',
    )
    background_tasks.add_task(run_actor_generation, actor_id)
    return RedirectResponse(
        url=f'/?actor_id={actor_id}&notice=Notebook generation started',
        status_code=303,
    )


@app.post('/actors/{actor_id}/untrack')
def untrack_actor(actor_id: str) -> RedirectResponse:
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')
        connection.execute('UPDATE actor_profiles SET is_tracked = 0 WHERE id = ?', (actor_id,))
        connection.commit()
    set_actor_notebook_status(actor_id, 'idle', 'Actor untracked.')
    return RedirectResponse(url=f'/?actor_id={actor_id}', status_code=303)


@app.get('/actors/ui', response_class=HTMLResponse)
def actors_ui() -> str:
    actor_items = ''.join(
        (
            f'<li>{html.escape(str(actor["id"]), quote=True)} - '
            f'{html.escape(str(actor["display_name"]), quote=True)}</li>'
        )
        for actor in list_actor_profiles()
    )
    return (
        '<!doctype html>'
        '<html><body>'
        '<h1>Actors</h1>'
        '<form method="post" action="/actors">'
        '<label for="display_name">Display Name</label>'
        '<input id="display_name" name="display_name" required />'
        '<button type="submit">Create</button>'
        '</form>'
        '<ul>'
        f'{actor_items}'
        '</ul>'
        '</body></html>'
    )


@app.post('/actors/{actor_id}/sources')
async def add_source(actor_id: str, request: Request) -> RedirectResponse:
    await _enforce_request_size(request, SOURCE_UPLOAD_BODY_LIMIT_BYTES)
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')

    form_data = await request.form()
    source_url = str(form_data.get('source_url', '')).strip()

    # Backward-compatible fields (still accepted if provided)
    source_name = str(form_data.get('source_name', '')).strip()
    published_at = str(form_data.get('published_at', '')).strip() or None
    pasted_text = str(form_data.get('pasted_text', '')).strip()
    trigger_excerpt = str(form_data.get('trigger_excerpt', '')).strip() or None
    source_title: str | None = None
    source_headline: str | None = None
    source_og_title: str | None = None
    source_html_title: str | None = None
    source_publisher: str | None = None
    source_site_name: str | None = None

    if not source_url:
        raise HTTPException(status_code=400, detail='source_url is required')

    if not pasted_text or not source_name:
        derived = derive_source_from_url(source_url)
        source_name = str(derived['source_name'])
        source_url = str(derived['source_url'])
        published_at = str(derived['published_at']) if derived['published_at'] else published_at
        pasted_text = str(derived['pasted_text'])
        trigger_excerpt = str(derived['trigger_excerpt']) if derived['trigger_excerpt'] else trigger_excerpt
        source_title = str(derived.get('title') or '') or None
        source_headline = str(derived.get('headline') or '') or None
        source_og_title = str(derived.get('og_title') or '') or None
        source_html_title = str(derived.get('html_title') or '') or None
        source_publisher = str(derived.get('publisher') or '') or None
        source_site_name = str(derived.get('site_name') or '') or None

    with sqlite3.connect(DB_PATH) as connection:
        _upsert_source_for_actor(
            connection,
            actor_id,
            source_name,
            source_url,
            published_at,
            pasted_text,
            trigger_excerpt,
            source_title,
            source_headline,
            source_og_title,
            source_html_title,
            source_publisher,
            source_site_name,
        )
        connection.commit()

    return RedirectResponse(url=f'/?actor_id={actor_id}', status_code=303)


@app.post('/actors/{actor_id}/sources/import-feeds')
def import_feeds(actor_id: str) -> RedirectResponse:
    import_default_feeds_for_actor(actor_id)
    return RedirectResponse(url=f'/?actor_id={actor_id}', status_code=303)


@app.post('/actors/{actor_id}/iocs')
async def add_iocs(actor_id: str, request: Request) -> RedirectResponse:
    await _enforce_request_size(request, DEFAULT_BODY_LIMIT_BYTES)
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')

    form_data = await request.form()
    ioc_type = str(form_data.get('ioc_type', 'indicator')).strip() or 'indicator'
    ioc_values_raw = str(form_data.get('ioc_values', '')).strip()
    source_ref = str(form_data.get('source_ref', '')).strip() or None

    values = _parse_ioc_values(ioc_values_raw)
    if not values:
        raise HTTPException(status_code=400, detail='ioc_values is required')

    with sqlite3.connect(DB_PATH) as connection:
        for value in values:
            connection.execute(
                '''
                INSERT INTO ioc_items (id, actor_id, ioc_type, ioc_value, source_ref, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (str(uuid.uuid4()), actor_id, ioc_type, value, source_ref, utc_now_iso()),
            )
        connection.commit()

    return RedirectResponse(url=f'/?actor_id={actor_id}', status_code=303)


@app.post('/actors/{actor_id}/refresh')
def refresh_notebook(actor_id: str, background_tasks: BackgroundTasks) -> RedirectResponse:
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')
    set_actor_notebook_status(
        actor_id,
        'running',
        'Refreshing sources, questions, and timeline entries...',
    )
    background_tasks.add_task(run_actor_generation, actor_id)
    return RedirectResponse(
        url=f'/?actor_id={actor_id}&notice=Notebook refresh started',
        status_code=303,
    )


@app.post('/actors/{actor_id}/requirements/generate')
async def generate_requirements(actor_id: str, request: Request) -> RedirectResponse:
    await _enforce_request_size(request, DEFAULT_BODY_LIMIT_BYTES)
    form_data = await request.form()
    org_context = str(form_data.get('org_context', '')).strip()
    priority_mode = str(form_data.get('priority_mode', 'Operational')).strip()
    if priority_mode not in {'Strategic', 'Operational', 'Tactical'}:
        priority_mode = 'Operational'
    count = generate_actor_requirements(actor_id, org_context, priority_mode)
    return RedirectResponse(
        url=f'/?actor_id={actor_id}&notice=Generated+{count}+requirements',
        status_code=303,
    )


@app.post('/requirements/{requirement_id}/resolve')
async def resolve_requirement(requirement_id: str, request: Request) -> RedirectResponse:
    await _enforce_request_size(request, DEFAULT_BODY_LIMIT_BYTES)
    form_data = await request.form()
    actor_id = str(form_data.get('actor_id', '')).strip()
    with sqlite3.connect(DB_PATH) as connection:
        row = connection.execute(
            'SELECT actor_id FROM requirement_items WHERE id = ?',
            (requirement_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='requirement not found')
        resolved_actor_id = str(row[0])
        connection.execute(
            'UPDATE requirement_items SET status = ? WHERE id = ?',
            ('resolved', requirement_id),
        )
        connection.commit()
    return RedirectResponse(url=f'/?actor_id={actor_id or resolved_actor_id}', status_code=303)


@app.post('/questions/{thread_id}/resolve')
async def resolve_question_thread(thread_id: str, request: Request) -> RedirectResponse:
    await _enforce_request_size(request, DEFAULT_BODY_LIMIT_BYTES)
    form_data = await request.form()
    actor_id = str(form_data.get('actor_id', '')).strip()

    with sqlite3.connect(DB_PATH) as connection:
        row = connection.execute(
            'SELECT actor_id, status FROM question_threads WHERE id = ?',
            (thread_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='question thread not found')
        db_actor_id = row[0]
        if row[1] != 'resolved':
            connection.execute(
                'UPDATE question_threads SET status = ?, updated_at = ? WHERE id = ?',
                ('resolved', utc_now_iso(), thread_id),
            )
        connection.commit()

    return RedirectResponse(url=f'/?actor_id={actor_id or db_actor_id}', status_code=303)


@app.get('/actors/{actor_id}/timeline/details', response_class=HTMLResponse)
def actor_timeline_details(actor_id: str) -> HTMLResponse:
    with sqlite3.connect(DB_PATH) as connection:
        actor_row = connection.execute(
            'SELECT id, display_name FROM actor_profiles WHERE id = ?',
            (actor_id,),
        ).fetchone()
        if actor_row is None:
            raise HTTPException(status_code=404, detail='actor not found')

        rows = connection.execute(
            '''
            SELECT
                te.occurred_at, te.category, te.title, te.summary, te.target_text, te.ttp_ids_json,
                s.source_name, s.url, s.published_at
            FROM timeline_events te
            LEFT JOIN sources s ON s.id = te.source_id
            WHERE te.actor_id = ?
            ORDER BY te.occurred_at DESC
            ''',
            (actor_id,),
        ).fetchall()

    detail_rows: list[dict[str, object]] = []
    for row in rows:
        detail_rows.append(
            {
                'occurred_at': row[0],
                'category': str(row[1]).replace('_', ' '),
                'title': row[2],
                'summary': row[3],
                'target_text': row[4] or '',
                'ttp_ids': _safe_json_string_list(row[5]),
                'source_name': row[6] or '',
                'source_url': row[7] or '',
                'source_published_at': row[8] or '',
            }
        )

    content = ['<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">']
    content.append('<title>Timeline Details</title>')
    content.append(
        '<style>'
        'body{font-family:Arial,sans-serif;background:#f7f7f7;color:#111;margin:0;padding:16px;}'
        '.wrap{max-width:980px;margin:0 auto;}'
        '.top{margin-bottom:12px;}'
        '.card{background:#fff;border:1px solid #ddd;border-radius:10px;padding:10px;margin-bottom:10px;}'
        '.meta{font-size:12px;color:#334155;margin:4px 0 8px;}'
        '.badge{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #888;font-size:12px;}'
        '.muted{color:#4b5563;font-size:12px;}'
        'a{color:#2255aa;text-decoration:none;}a:hover{text-decoration:underline;}'
        '</style>'
    )
    content.append('</head><body><div class="wrap">')
    content.append(
        f'<div class="top"><a href="/?actor_id={actor_id}">← Back to dashboard</a>'
        f'<h1>Timeline Details: {html.escape(str(actor_row[1]))}</h1>'
        f'<div class="muted">Full activity evidence view for this actor.</div></div>'
    )

    if not detail_rows:
        content.append('<div class="card">No timeline entries yet.</div>')
    else:
        for item in detail_rows:
            ttp_text = ', '.join(item['ttp_ids']) if item['ttp_ids'] else ''
            source_block = ''
            if item['source_url']:
                source_name = html.escape(str(item['source_name']) or str(item['source_url']))
                source_url = html.escape(str(item['source_url']))
                source_pub = html.escape(str(item['source_published_at'] or 'unknown'))
                source_block = (
                    f'<div class="meta">Source: <a href="{source_url}" target="_blank" rel="noreferrer">{source_name}</a> '
                    f'| Published: {source_pub}</div>'
                )
            content.append('<div class="card">')
            content.append(
                f'<div><span class="badge">{html.escape(str(item["category"]))}</span> '
                f'<span class="muted">{html.escape(str(item["occurred_at"]))}</span></div>'
            )
            content.append(f'<h3>{html.escape(str(item["title"]))}</h3>')
            content.append(f'<div>{html.escape(str(item["summary"]))}</div>')
            if item['target_text']:
                content.append(f'<div class="meta"><strong>Target:</strong> {html.escape(str(item["target_text"]))}</div>')
            if ttp_text:
                content.append(f'<div class="meta"><strong>Techniques:</strong> {html.escape(ttp_text)}</div>')
            content.append(source_block)
            content.append('</div>')

    content.append('</div></body></html>')
    return HTMLResponse(''.join(content))


@app.get('/actors/{actor_id}/questions', response_class=HTMLResponse)
def actor_questions_workspace(request: Request, actor_id: str) -> HTMLResponse:
    notebook = _fetch_actor_notebook(actor_id)
    return templates.TemplateResponse(
        request,
        'questions.html',
        {
            'actor_id': actor_id,
            'notebook': notebook,
        },
    )


@app.post('/actors/{actor_id}/initialize')
def initialize_actor_state(actor_id: str) -> dict[str, str]:
    created_at = utc_now_iso()
    capability_grid_json = json.dumps(baseline_capability_grid())
    behavioral_model_json = json.dumps(baseline_behavioral_model())

    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')

        state_row = connection.execute(
            'SELECT actor_id FROM actor_state WHERE actor_id = ?',
            (actor_id,),
        ).fetchone()
        if state_row is not None:
            raise HTTPException(status_code=409, detail='actor state already initialized')

        connection.execute(
            '''
            INSERT INTO actor_state (
                actor_id, capability_grid_json, behavioral_model_json, created_at
            )
            VALUES (?, ?, ?, ?)
            ''',
            (actor_id, capability_grid_json, behavioral_model_json, created_at),
        )
        connection.commit()

    return {'actor_id': actor_id, 'status': 'initialized'}


@app.get('/actors/{actor_id}/state')
def get_actor_state(actor_id: str) -> dict[str, object]:
    with sqlite3.connect(DB_PATH) as connection:
        row = connection.execute(
            '''
            SELECT actor_id, capability_grid_json, behavioral_model_json, created_at
            FROM actor_state
            WHERE actor_id = ?
            ''',
            (actor_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail='actor state not found')
    return {
        'actor_id': row[0],
        'capability_grid': json.loads(row[1]),
        'behavioral_model': json.loads(row[2]),
        'created_at': row[3],
    }


@app.post('/actors/{actor_id}/observations')
async def create_observation(actor_id: str, request: Request) -> dict[str, object]:
    await _enforce_request_size(request, OBSERVATION_BODY_LIMIT_BYTES)
    payload = await request.json()

    source_type_raw = payload.get('source_type')
    source_type = str(source_type_raw).strip() if source_type_raw is not None else ''
    if not source_type:
        raise HTTPException(status_code=400, detail='source_type is required')

    source_ref_raw = payload.get('source_ref')
    source_date_raw = payload.get('source_date')
    source_ref = str(source_ref_raw) if source_ref_raw is not None else None
    source_date = str(source_date_raw) if source_date_raw is not None else None

    ttp_list = normalize_string_list(payload.get('ttp_list'))
    tools_list = normalize_string_list(payload.get('tools_list'))
    infra_list = normalize_string_list(payload.get('infra_list'))
    target_list = normalize_string_list(payload.get('target_list'))

    observation = {
        'id': str(uuid.uuid4()),
        'actor_id': actor_id,
        'source_type': source_type,
        'source_ref': source_ref,
        'source_date': source_date,
        'ttp_list': ttp_list,
        'tools_list': tools_list,
        'infra_list': infra_list,
        'target_list': target_list,
        'created_at': utc_now_iso(),
    }

    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')
        connection.execute(
            '''
            INSERT INTO observation_records (
                id, actor_id, source_type, source_ref, source_date,
                ttp_json, tools_json, infra_json, targets_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                observation['id'],
                observation['actor_id'],
                observation['source_type'],
                observation['source_ref'],
                observation['source_date'],
                json.dumps(observation['ttp_list']),
                json.dumps(observation['tools_list']),
                json.dumps(observation['infra_list']),
                json.dumps(observation['target_list']),
                observation['created_at'],
            ),
        )
        state_row = connection.execute(
            '''
            SELECT capability_grid_json
            FROM actor_state
            WHERE actor_id = ?
            ''',
            (actor_id,),
        ).fetchone()
        if state_row is not None:
            capability_grid = json.loads(state_row[0])
            for ttp in observation['ttp_list']:
                category = TTP_CATEGORY_MAP.get(ttp)
                if category is None:
                    continue
                category_entry = capability_grid.get(category)
                if not isinstance(category_entry, dict):
                    continue
                observed_value = category_entry.get('observed')
                evidence_refs = category_entry.get('evidence_refs')
                if observed_value != '' or evidence_refs != []:
                    continue
                existing_pending = connection.execute(
                    '''
                    SELECT id
                    FROM delta_proposals
                    WHERE actor_id = ? AND affected_category = ? AND status = 'pending'
                    ''',
                    (actor_id, category),
                ).fetchone()
                if existing_pending is not None:
                    continue
                connection.execute(
                    '''
                    INSERT INTO delta_proposals (
                        id, actor_id, observation_id, delta_type,
                        affected_category, status, created_at, validation_template_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        str(uuid.uuid4()),
                        actor_id,
                        observation['id'],
                        'expansion',
                        category,
                        'pending',
                        utc_now_iso(),
                        json.dumps(generate_validation_template('expansion', category)),
                    ),
                )
        connection.commit()

    return observation


@app.get('/actors/{actor_id}/observations')
def list_observations(actor_id: str) -> list[dict[str, object]]:
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')
        rows = connection.execute(
            '''
            SELECT
                id, actor_id, source_type, source_ref, source_date,
                ttp_json, tools_json, infra_json, targets_json, created_at
            FROM observation_records
            WHERE actor_id = ?
            ORDER BY created_at DESC
            ''',
            (actor_id,),
        ).fetchall()
    return [
        {
            'id': row[0],
            'actor_id': row[1],
            'source_type': row[2],
            'source_ref': row[3],
            'source_date': row[4],
            'ttp_list': json.loads(row[5]),
            'tools_list': json.loads(row[6]),
            'infra_list': json.loads(row[7]),
            'target_list': json.loads(row[8]),
            'created_at': row[9],
        }
        for row in rows
    ]


@app.get('/actors/{actor_id}/deltas')
def list_deltas(actor_id: str) -> list[dict[str, str]]:
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')
        rows = connection.execute(
            '''
            SELECT
                id, actor_id, observation_id, delta_type,
                affected_category, status, created_at
            FROM delta_proposals
            WHERE actor_id = ?
            ORDER BY created_at DESC
            ''',
            (actor_id,),
        ).fetchall()
    return [
        {
            'id': row[0],
            'actor_id': row[1],
            'observation_id': row[2],
            'delta_type': row[3],
            'affected_category': row[4],
            'status': row[5],
            'created_at': row[6],
        }
        for row in rows
    ]


def resolve_delta_action(actor_id: str, delta_id: str, requested_action: str) -> dict[str, str]:
    if requested_action not in ('accept', 'reject'):
        raise HTTPException(status_code=400, detail='action must be accept or reject')

    created_at = utc_now_iso()

    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')

        delta_row = connection.execute(
            '''
            SELECT id, observation_id, affected_category, status
            FROM delta_proposals
            WHERE id = ? AND actor_id = ?
            ''',
            (delta_id, actor_id),
        ).fetchone()
        if delta_row is None:
            raise HTTPException(status_code=404, detail='delta not found')
        if delta_row[3] != 'pending':
            raise HTTPException(status_code=409, detail='delta is not pending')

        state_row = connection.execute(
            '''
            SELECT capability_grid_json, behavioral_model_json
            FROM actor_state
            WHERE actor_id = ?
            ''',
            (actor_id,),
        ).fetchone()
        if state_row is None:
            raise HTTPException(status_code=404, detail='actor state not found')

        capability_grid = json.loads(state_row[0])
        behavioral_model = json.loads(state_row[1])
        previous_state = {
            'capability_grid': capability_grid,
            'behavioral_model': behavioral_model,
        }
        previous_state_json = json.dumps(previous_state)

        if requested_action == 'reject':
            connection.execute(
                '''
                UPDATE delta_proposals
                SET status = 'rejected'
                WHERE id = ? AND actor_id = ?
                ''',
                (delta_id, actor_id),
            )
            connection.execute(
                '''
                INSERT INTO state_transition_log (
                    id, actor_id, delta_id, previous_state_json,
                    new_state_json, action, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    str(uuid.uuid4()),
                    actor_id,
                    delta_id,
                    previous_state_json,
                    previous_state_json,
                    'rejected',
                    created_at,
                ),
            )
            connection.commit()
            return {'delta_id': delta_id, 'action': 'rejected'}

        affected_category = delta_row[2]
        observation_id = delta_row[1]
        category_entry = capability_grid.get(affected_category)
        if not isinstance(category_entry, dict):
            category_entry = baseline_entry()
            capability_grid[affected_category] = category_entry

        current_refs = category_entry.get('evidence_refs')
        if not isinstance(current_refs, list):
            current_refs = []
        current_refs = [str(ref) for ref in current_refs]
        current_refs.append(observation_id)
        category_entry['observed'] = f'Baseline expanded via delta {delta_id}'
        category_entry['evidence_refs'] = current_refs

        new_state = {
            'capability_grid': capability_grid,
            'behavioral_model': behavioral_model,
        }
        new_state_json = json.dumps(new_state)

        connection.execute(
            '''
            UPDATE actor_state
            SET capability_grid_json = ?, behavioral_model_json = ?
            WHERE actor_id = ?
            ''',
            (json.dumps(capability_grid), json.dumps(behavioral_model), actor_id),
        )
        connection.execute(
            '''
            UPDATE delta_proposals
            SET status = 'accepted'
            WHERE id = ? AND actor_id = ?
            ''',
            (delta_id, actor_id),
        )
        connection.execute(
            '''
            INSERT INTO state_transition_log (
                id, actor_id, delta_id, previous_state_json,
                new_state_json, action, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                str(uuid.uuid4()),
                actor_id,
                delta_id,
                previous_state_json,
                new_state_json,
                'accepted',
                created_at,
            ),
        )
        connection.commit()

    return {
        'delta_id': delta_id,
        'action': 'accepted',
        'affected_category': affected_category,
    }


@app.post('/actors/{actor_id}/deltas/{delta_id}/resolve')
async def resolve_delta(actor_id: str, delta_id: str, request: Request) -> dict[str, str]:
    await _enforce_request_size(request, DEFAULT_BODY_LIMIT_BYTES)
    payload = await request.json()
    requested_action = str(payload.get('action', ''))
    return resolve_delta_action(actor_id, delta_id, requested_action)


@app.get('/actors/{actor_id}/transitions')
def list_transitions(actor_id: str) -> list[dict[str, str]]:
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')
        rows = connection.execute(
            '''
            SELECT
                id, actor_id, delta_id, previous_state_json,
                new_state_json, action, created_at
            FROM state_transition_log
            WHERE actor_id = ?
            ORDER BY created_at ASC
            ''',
            (actor_id,),
        ).fetchall()
    return [
        {
            'id': row[0],
            'actor_id': row[1],
            'delta_id': row[2],
            'previous_state_json': row[3],
            'new_state_json': row[4],
            'action': row[5],
            'created_at': row[6],
        }
        for row in rows
    ]


@app.get('/actors/{actor_id}/deltas/ui', response_class=HTMLResponse)
def deltas_ui(actor_id: str) -> str:
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')
        rows = connection.execute(
            '''
            SELECT id, affected_category, created_at
            FROM delta_proposals
            WHERE actor_id = ? AND status = 'pending'
            ORDER BY created_at DESC
            ''',
            (actor_id,),
        ).fetchall()

    actor_path = quote(actor_id, safe='')
    actor_text = html.escape(actor_id, quote=True)
    items = ''.join(
        (
            f'<li><a href="/actors/{actor_path}/deltas/{quote(str(row[0]), safe="")}/review">'
            f'{html.escape(str(row[0]), quote=True)}</a> - '
            f'{html.escape(str(row[1]), quote=True)} - '
            f'{html.escape(str(row[2]), quote=True)}</li>'
        )
        for row in rows
    )
    return (
        '<!doctype html><html><body>'
        '<h1>Pending Deltas</h1>'
        f'<p>Actor: {actor_text}</p>'
        '<ul>'
        f'{items}'
        '</ul>'
        '</body></html>'
    )


@app.get('/actors/{actor_id}/deltas/{delta_id}')
def get_delta(actor_id: str, delta_id: str) -> dict[str, object]:
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')
        row = connection.execute(
            '''
            SELECT
                id, actor_id, observation_id, delta_type,
                affected_category, status, created_at, validation_template_json
            FROM delta_proposals
            WHERE actor_id = ? AND id = ?
            ''',
            (actor_id, delta_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail='delta not found')
    return {
        'id': row[0],
        'actor_id': row[1],
        'observation_id': row[2],
        'delta_type': row[3],
        'affected_category': row[4],
        'status': row[5],
        'created_at': row[6],
        'validation_template': json.loads(row[7]),
    }


@app.get('/actors/{actor_id}/deltas/{delta_id}/review', response_class=HTMLResponse)
def delta_review_ui(actor_id: str, delta_id: str) -> str:
    with sqlite3.connect(DB_PATH) as connection:
        if not actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')
        delta_row = connection.execute(
            '''
            SELECT
                id, actor_id, observation_id, delta_type,
                affected_category, status, created_at, validation_template_json
            FROM delta_proposals
            WHERE actor_id = ? AND id = ?
            ''',
            (actor_id, delta_id),
        ).fetchone()
        if delta_row is None:
            raise HTTPException(status_code=404, detail='delta not found')

        observation_row = connection.execute(
            '''
            SELECT source_type, source_ref, source_date, ttp_json, tools_json,
                   infra_json, targets_json, created_at
            FROM observation_records
            WHERE id = ?
            ''',
            (delta_row[2],),
        ).fetchone()
        if observation_row is None:
            raise HTTPException(status_code=404, detail='observation not found')

        state_row = connection.execute(
            '''
            SELECT capability_grid_json
            FROM actor_state
            WHERE actor_id = ?
            ''',
            (actor_id,),
        ).fetchone()
        if state_row is None:
            raise HTTPException(status_code=404, detail='actor state not found')

    capability_grid = json.loads(state_row[0])
    affected_category = delta_row[4]
    category_entry = capability_grid.get(affected_category)
    if not isinstance(category_entry, dict):
        category_entry = baseline_entry()

    validation_template = json.loads(delta_row[7])
    tier1 = validation_template.get('tier1_basic', [])
    tier2 = validation_template.get('tier2_analytic', [])
    tier3 = validation_template.get('tier3_strategic', [])

    ttp_list = json.loads(observation_row[3])
    tools_list = json.loads(observation_row[4])
    infra_list = json.loads(observation_row[5])
    target_list = json.loads(observation_row[6])

    actor_path = quote(actor_id, safe='')
    delta_path = quote(delta_id, safe='')

    def render_list(items: list[object]) -> str:
        return ''.join(f'<li>{html.escape(str(item), quote=True)}</li>' for item in items)

    return (
        '<!doctype html><html><body>'
        '<h1>Delta Review</h1>'
        f'<p>Actor id: {html.escape(actor_id, quote=True)}</p>'
        f'<p>Delta id: {html.escape(delta_id, quote=True)}</p>'
        f'<p>Status: {html.escape(str(delta_row[5]), quote=True)}</p>'
        '<h2>Proposed Change</h2>'
        f'<p>delta_type: {html.escape(str(delta_row[3]), quote=True)}</p>'
        f'<p>affected_category: {html.escape(str(affected_category), quote=True)}</p>'
        '<h2>Observation Summary</h2>'
        f'<p>source_type: {html.escape(str(observation_row[0]), quote=True)}</p>'
        f'<p>source_ref: {html.escape(str(observation_row[1]), quote=True)}</p>'
        f'<p>source_date: {html.escape(str(observation_row[2]), quote=True)}</p>'
        f'<p>created_at: {html.escape(str(observation_row[7]), quote=True)}</p>'
        '<p>ttp_list:</p><ul>'
        f'{render_list(ttp_list)}'
        '</ul>'
        '<p>tools_list:</p><ul>'
        f'{render_list(tools_list)}'
        '</ul>'
        '<p>infra_list:</p><ul>'
        f'{render_list(infra_list)}'
        '</ul>'
        '<p>target_list:</p><ul>'
        f'{render_list(target_list)}'
        '</ul>'
        '<h2>Current Baseline</h2>'
        f'<p>observed: {html.escape(str(category_entry.get("observed", "")), quote=True)}</p>'
        f'<p>assessed: {html.escape(str(category_entry.get("assessed", "")), quote=True)}</p>'
        f'<p>confidence: {html.escape(str(category_entry.get("confidence", 0.0)), quote=True)}</p>'
        f'<p>evidence_refs: {html.escape(str(category_entry.get("evidence_refs", [])), quote=True)}</p>'
        '<h2>Validation Ladder</h2>'
        '<h3>Tier 1 Basic</h3><ul>'
        f'{render_list(tier1)}'
        '</ul>'
        '<h3>Tier 2 Analytic</h3><ul>'
        f'{render_list(tier2)}'
        '</ul>'
        '<h3>Tier 3 Strategic</h3><ul>'
        f'{render_list(tier3)}'
        '</ul>'
        f'<form method="post" action="/actors/{actor_path}/deltas/{delta_path}/accept">'
        '<button type="submit">Accept</button>'
        '</form>'
        f'<form method="post" action="/actors/{actor_path}/deltas/{delta_path}/reject">'
        '<button type="submit">Reject</button>'
        '</form>'
        '</body></html>'
    )


@app.post('/actors/{actor_id}/deltas/{delta_id}/accept')
def accept_delta_ui(actor_id: str, delta_id: str) -> RedirectResponse:
    resolve_delta_action(actor_id, delta_id, 'accept')
    return RedirectResponse(url=f'/actors/{actor_id}/deltas/{delta_id}/review', status_code=303)


@app.post('/actors/{actor_id}/deltas/{delta_id}/reject')
def reject_delta_ui(actor_id: str, delta_id: str) -> RedirectResponse:
    resolve_delta_action(actor_id, delta_id, 'reject')
    return RedirectResponse(url=f'/actors/{actor_id}/deltas/{delta_id}/review', status_code=303)
