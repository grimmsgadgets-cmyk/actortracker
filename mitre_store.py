import json
import os
import re
from pathlib import Path
from typing import Callable

import httpx

DB_PATH = '/data/app.db'
ATTACK_ENTERPRISE_STIX_URL = (
    'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
)

MITRE_GROUP_CACHE: list[dict[str, object]] | None = None
MITRE_DATASET_CACHE: dict[str, object] | None = None
MITRE_TECHNIQUE_PHASE_CACHE: dict[str, list[str]] | None = None
MITRE_CAMPAIGN_LINK_CACHE: dict[str, dict[str, set[str]]] | None = None
MITRE_TECHNIQUE_INDEX_CACHE: dict[str, dict[str, str]] | None = None
MITRE_SOFTWARE_CACHE: list[dict[str, object]] | None = None


def configure(*, db_path: str | None = None, attack_url: str | None = None) -> None:
    global DB_PATH, ATTACK_ENTERPRISE_STIX_URL
    if db_path:
        DB_PATH = db_path
    if attack_url:
        ATTACK_ENTERPRISE_STIX_URL = attack_url


def clear_cache() -> None:
    global MITRE_GROUP_CACHE, MITRE_DATASET_CACHE, MITRE_TECHNIQUE_PHASE_CACHE
    global MITRE_SOFTWARE_CACHE, MITRE_CAMPAIGN_LINK_CACHE, MITRE_TECHNIQUE_INDEX_CACHE
    MITRE_GROUP_CACHE = None
    MITRE_DATASET_CACHE = None
    MITRE_TECHNIQUE_PHASE_CACHE = None
    MITRE_SOFTWARE_CACHE = None
    MITRE_CAMPAIGN_LINK_CACHE = None
    MITRE_TECHNIQUE_INDEX_CACHE = None


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
    configured = os.environ.get('MITRE_ATTACK_PATH', '').strip()
    if configured:
        return Path(configured)
    return Path(DB_PATH).resolve().parent / 'mitre_enterprise_attack.json'


def ensure_mitre_attack_dataset() -> bool:
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


def load_mitre_dataset() -> dict[str, object]:
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


def _stix_type(stix_id: str) -> str:
    if '--' not in stix_id:
        return ''
    return stix_id.split('--', 1)[0].strip().lower()


def mitre_campaign_link_index() -> dict[str, dict[str, set[str]]]:
    global MITRE_CAMPAIGN_LINK_CACHE
    if MITRE_CAMPAIGN_LINK_CACHE is not None:
        return MITRE_CAMPAIGN_LINK_CACHE

    dataset = load_mitre_dataset()
    objects = dataset.get('objects', []) if isinstance(dataset, dict) else []
    if not isinstance(objects, list):
        MITRE_CAMPAIGN_LINK_CACHE = {'groups': {}, 'software': {}}
        return MITRE_CAMPAIGN_LINK_CACHE

    campaign_keys: dict[str, set[str]] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get('type') != 'campaign':
            continue
        if bool(obj.get('revoked')) or bool(obj.get('x_mitre_deprecated')):
            continue
        campaign_id = str(obj.get('id') or '').strip()
        if not campaign_id:
            continue
        name = str(obj.get('name') or '').strip()
        aliases = _mitre_alias_values(obj)
        keys = {_normalize_actor_key(name)} if name else set()
        for alias in aliases:
            keys.add(_normalize_actor_key(alias))
        campaign_keys[campaign_id] = {key for key in keys if key}

    group_links: dict[str, set[str]] = {}
    software_links: dict[str, set[str]] = {}

    def _link_campaign(target_id: str, campaign_id: str) -> None:
        target_type = _stix_type(target_id)
        keyset = campaign_keys.get(campaign_id, set())
        if not keyset:
            return
        if target_type == 'intrusion-set':
            group_links.setdefault(target_id, set()).update(keyset)
            return
        if target_type in {'malware', 'tool'}:
            software_links.setdefault(target_id, set()).update(keyset)

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get('type') != 'relationship':
            continue
        if bool(obj.get('revoked')) or bool(obj.get('x_mitre_deprecated')):
            continue

        rel_type = str(obj.get('relationship_type') or '').strip().lower()
        source_ref = str(obj.get('source_ref') or '').strip()
        target_ref = str(obj.get('target_ref') or '').strip()
        if not source_ref or not target_ref:
            continue

        source_type = _stix_type(source_ref)
        target_type = _stix_type(target_ref)

        if rel_type == 'attributed-to':
            if source_type == 'campaign':
                _link_campaign(target_ref, source_ref)
            elif target_type == 'campaign':
                _link_campaign(source_ref, target_ref)
            continue

        if rel_type in {'uses', 'related-to'}:
            if source_type == 'campaign':
                _link_campaign(target_ref, source_ref)
            elif target_type == 'campaign':
                _link_campaign(source_ref, target_ref)

    MITRE_CAMPAIGN_LINK_CACHE = {'groups': group_links, 'software': software_links}
    return MITRE_CAMPAIGN_LINK_CACHE


def normalize_technique_id(value: str) -> str:
    return value.strip().upper()


def _normalize_tactic_name(value: str) -> str:
    return value.strip().lower().replace('-', '_').replace(' ', '_')


def mitre_technique_index() -> dict[str, dict[str, str]]:
    global MITRE_TECHNIQUE_INDEX_CACHE
    if MITRE_TECHNIQUE_INDEX_CACHE is not None:
        return MITRE_TECHNIQUE_INDEX_CACHE

    dataset = load_mitre_dataset()
    objects = dataset.get('objects', []) if isinstance(dataset, dict) else []
    if not isinstance(objects, list):
        MITRE_TECHNIQUE_INDEX_CACHE = {}
        return MITRE_TECHNIQUE_INDEX_CACHE

    index: dict[str, dict[str, str]] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get('type') != 'attack-pattern':
            continue
        if bool(obj.get('revoked')) or bool(obj.get('x_mitre_deprecated')):
            continue

        name = str(obj.get('name') or '').strip()
        refs = obj.get('external_references', [])
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            if str(ref.get('source_name') or '') != 'mitre-attack':
                continue
            technique_id = normalize_technique_id(str(ref.get('external_id') or ''))
            if not technique_id.startswith('T'):
                continue
            technique_url = str(ref.get('url') or '').strip()
            if not technique_url:
                technique_url = f'https://attack.mitre.org/techniques/{technique_id.replace(".", "/")}/'
            index[technique_id] = {
                'technique_id': technique_id,
                'name': name,
                'url': technique_url,
            }
            break

    MITRE_TECHNIQUE_INDEX_CACHE = index
    return MITRE_TECHNIQUE_INDEX_CACHE


def mitre_valid_technique_ids() -> set[str]:
    return set(mitre_technique_index().keys())


def mitre_technique_phase_index() -> dict[str, list[str]]:
    global MITRE_TECHNIQUE_PHASE_CACHE
    if MITRE_TECHNIQUE_PHASE_CACHE is not None:
        return MITRE_TECHNIQUE_PHASE_CACHE

    dataset = load_mitre_dataset()
    objects = dataset.get('objects', []) if isinstance(dataset, dict) else []
    if not isinstance(objects, list):
        MITRE_TECHNIQUE_PHASE_CACHE = {}
        return MITRE_TECHNIQUE_PHASE_CACHE

    phase_index: dict[str, list[str]] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get('type') != 'attack-pattern':
            continue
        if bool(obj.get('revoked')) or bool(obj.get('x_mitre_deprecated')):
            continue

        technique_id = ''
        refs = obj.get('external_references', [])
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                if str(ref.get('source_name') or '') != 'mitre-attack':
                    continue
                external_id = normalize_technique_id(str(ref.get('external_id') or ''))
                if external_id.startswith('T'):
                    technique_id = external_id
                    break
        if not technique_id:
            continue

        phases_raw = obj.get('kill_chain_phases', [])
        if not isinstance(phases_raw, list):
            continue
        normalized_phases: list[str] = []
        for phase_item in phases_raw:
            if not isinstance(phase_item, dict):
                continue
            phase_name = _normalize_tactic_name(str(phase_item.get('phase_name') or ''))
            if not phase_name:
                continue
            if phase_name not in normalized_phases:
                normalized_phases.append(phase_name)
        if not normalized_phases:
            continue
        phase_index[technique_id] = normalized_phases

    MITRE_TECHNIQUE_PHASE_CACHE = phase_index
    return MITRE_TECHNIQUE_PHASE_CACHE


def capability_category_from_technique_id(
    ttp_id: str,
    *,
    attack_tactic_to_capability_map: dict[str, str],
    capability_grid_keys: list[str],
) -> str | None:
    normalized_ttp = normalize_technique_id(ttp_id)
    if not normalized_ttp:
        return None

    technique_candidates = [normalized_ttp]
    if '.' in normalized_ttp:
        technique_candidates.append(normalized_ttp.split('.', 1)[0])

    phase_index = mitre_technique_phase_index()
    for technique_id in technique_candidates:
        phases = phase_index.get(technique_id, [])
        for phase in phases:
            mapped = attack_tactic_to_capability_map.get(phase)
            if mapped in capability_grid_keys:
                return mapped
    return None


def load_mitre_groups() -> list[dict[str, object]]:
    global MITRE_GROUP_CACHE
    if MITRE_GROUP_CACHE is not None:
        return MITRE_GROUP_CACHE

    dataset_path = _mitre_dataset_path()
    if not dataset_path.exists():
        MITRE_GROUP_CACHE = []
        return MITRE_GROUP_CACHE

    parsed = load_mitre_dataset()
    if not parsed:
        MITRE_GROUP_CACHE = []
        return MITRE_GROUP_CACHE

    campaign_group_keys = mitre_campaign_link_index().get('groups', {})
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
        aliases = _mitre_alias_values(obj)
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

        base_search_keys = {_normalize_actor_key(name)}
        for alias in aliases:
            base_search_keys.add(_normalize_actor_key(alias))
        if attack_id:
            base_search_keys.add(_normalize_actor_key(attack_id))

        stix_id = str(obj.get('id') or '')
        campaign_search_keys = set(campaign_group_keys.get(stix_id, set()))
        search_keys = set(base_search_keys).union(campaign_search_keys)

        groups.append(
            {
                'stix_id': stix_id,
                'name': name,
                'description': description,
                'aliases': aliases,
                'attack_id': attack_id,
                'attack_url': attack_url,
                'base_search_keys': base_search_keys,
                'campaign_search_keys': campaign_search_keys,
                'search_keys': search_keys,
            }
        )

    MITRE_GROUP_CACHE = groups
    return groups


def match_mitre_group(actor_name: str) -> dict[str, object] | None:
    actor_key = _normalize_actor_key(actor_name)
    if not actor_key:
        return None

    groups = load_mitre_groups()
    for group in groups:
        base_search_keys = group.get('base_search_keys')
        if isinstance(base_search_keys, set) and actor_key in base_search_keys:
            return group

    for group in groups:
        campaign_search_keys = group.get('campaign_search_keys')
        if isinstance(campaign_search_keys, set) and actor_key in campaign_search_keys:
            return group

    actor_tokens = set(actor_key.split())
    if not actor_tokens:
        return None

    best: dict[str, object] | None = None
    best_score = 0.0
    for group in groups:
        search_keys = group.get('search_keys')
        if not isinstance(search_keys, set):
            continue
        overlap = _candidate_overlap_score(actor_tokens, search_keys)
        if overlap > best_score:
            best_score = overlap
            best = group
    if best is not None and best_score >= 0.6:
        return best
    return None


def load_mitre_software() -> list[dict[str, object]]:
    global MITRE_SOFTWARE_CACHE
    if MITRE_SOFTWARE_CACHE is not None:
        return MITRE_SOFTWARE_CACHE

    dataset_path = _mitre_dataset_path()
    if not dataset_path.exists():
        MITRE_SOFTWARE_CACHE = []
        return MITRE_SOFTWARE_CACHE

    parsed = load_mitre_dataset()
    if not parsed or not isinstance(parsed, dict):
        MITRE_SOFTWARE_CACHE = []
        return MITRE_SOFTWARE_CACHE

    campaign_software_keys = mitre_campaign_link_index().get('software', {})
    software: list[dict[str, object]] = []
    for obj in parsed.get('objects', []):
        if not isinstance(obj, dict):
            continue

        obj_type = str(obj.get('type') or '')
        if obj_type not in {'malware', 'tool'}:
            continue
        if bool(obj.get('revoked')) or bool(obj.get('x_mitre_deprecated')):
            continue

        name = str(obj.get('name') or '').strip()
        if not name:
            continue
        description = str(obj.get('description') or '').strip()
        aliases = _mitre_alias_values(obj)

        attack_id: str | None = None
        attack_url: str | None = None
        ext_refs = obj.get('external_references', [])
        if isinstance(ext_refs, list):
            for ref in ext_refs:
                if not isinstance(ref, dict):
                    continue
                if str(ref.get('source_name') or '') != 'mitre-attack':
                    continue
                external_id = str(ref.get('external_id') or '')
                if external_id.startswith('S'):
                    attack_id = external_id
                    attack_url = str(ref.get('url') or '').strip()
                    if not attack_url:
                        attack_url = f'https://attack.mitre.org/software/{external_id}/'
                    break

        base_search_keys = {_normalize_actor_key(name)}
        for alias in aliases:
            base_search_keys.add(_normalize_actor_key(alias))
        if attack_id:
            base_search_keys.add(_normalize_actor_key(attack_id))

        stix_id = str(obj.get('id') or '')
        campaign_search_keys = set(campaign_software_keys.get(stix_id, set()))
        search_keys = set(base_search_keys).union(campaign_search_keys)
        software.append(
            {
                'stix_id': stix_id,
                'type': obj_type,
                'name': name,
                'description': description,
                'aliases': aliases,
                'attack_id': attack_id,
                'attack_url': attack_url,
                'base_search_keys': base_search_keys,
                'campaign_search_keys': campaign_search_keys,
                'search_keys': search_keys,
            }
        )

    MITRE_SOFTWARE_CACHE = software
    return MITRE_SOFTWARE_CACHE


def match_mitre_software(name: str) -> dict[str, object] | None:
    actor_key = _normalize_actor_key(name)
    if not actor_key:
        return None

    items = load_mitre_software()
    for it in items:
        base_search_keys = it.get('base_search_keys')
        if isinstance(base_search_keys, set) and actor_key in base_search_keys:
            return it

    for it in items:
        campaign_search_keys = it.get('campaign_search_keys')
        if isinstance(campaign_search_keys, set) and actor_key in campaign_search_keys:
            return it

    actor_tokens = set(actor_key.split())
    if not actor_tokens:
        return None

    best = None
    best_score = 0.0
    for it in items:
        search_keys = it.get('search_keys')
        if not isinstance(search_keys, set):
            continue
        overlap = _candidate_overlap_score(actor_tokens, search_keys)
        if overlap > best_score:
            best_score = overlap
            best = it

    if best is not None and best_score >= 0.6:
        return best
    return None


def build_actor_profile_from_mitre(
    actor_name: str,
    *,
    first_sentences: Callable[[str, int], str],
) -> dict[str, str]:
    group = match_mitre_group(actor_name)
    if group is None:
        sw = match_mitre_software(actor_name)
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
            summary = first_sentences(description, 3)
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
        summary = first_sentences(description, 3)
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


def group_top_techniques(group_stix_id: str, limit: int = 6) -> list[dict[str, str]]:
    if not group_stix_id:
        return []

    dataset = load_mitre_dataset()
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


def known_technique_ids_for_entity(entity_stix_id: str) -> set[str]:
    if not entity_stix_id:
        return set()

    dataset = load_mitre_dataset()
    objects = dataset.get('objects', []) if isinstance(dataset, dict) else []
    if not isinstance(objects, list):
        return set()

    attack_pattern_to_tid: dict[str, str] = {}
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get('type') != 'attack-pattern':
            continue
        if bool(obj.get('revoked')) or bool(obj.get('x_mitre_deprecated')):
            continue
        attack_pattern_id = str(obj.get('id') or '')
        if not attack_pattern_id:
            continue

        refs = obj.get('external_references', [])
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            if str(ref.get('source_name') or '') != 'mitre-attack':
                continue
            external_id = normalize_technique_id(str(ref.get('external_id') or ''))
            if external_id.startswith('T'):
                attack_pattern_to_tid[attack_pattern_id] = external_id
                break

    known: set[str] = set()
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        if obj.get('type') != 'relationship':
            continue
        if obj.get('relationship_type') != 'uses':
            continue
        if str(obj.get('source_ref') or '') != entity_stix_id:
            continue

        target_ref = str(obj.get('target_ref') or '')
        tid = attack_pattern_to_tid.get(target_ref)
        if tid:
            known.add(tid)
    return known


def favorite_attack_vectors(techniques: list[dict[str, str]], limit: int = 3) -> list[str]:
    phase_counts: dict[str, int] = {}
    for item in techniques:
        phase = str(item.get('phase') or '').strip().lower()
        if not phase:
            continue
        phase_counts[phase] = phase_counts.get(phase, 0) + 1
    ranked = sorted(phase_counts.items(), key=lambda entry: entry[1], reverse=True)
    return [phase.replace('_', ' ') for phase, _ in ranked[:limit]]
