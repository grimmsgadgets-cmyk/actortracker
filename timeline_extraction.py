import re
from typing import Callable


def extract_target_hint(sentence: str) -> str:
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


def sentence_mentions_actor_terms(sentence: str, actor_terms: list[str]) -> bool:
    lowered = sentence.lower()
    for term in actor_terms:
        value = term.strip().lower()
        if not value:
            continue
        escaped = re.escape(value).replace(r'\ ', r'\s+')
        pattern = rf'(?<![a-z0-9]){escaped}(?![a-z0-9])'
        if re.search(pattern, lowered):
            return True
    return False


def looks_like_activity_sentence(sentence: str) -> bool:
    lowered = sentence.lower()
    verbs = (
        'target', 'attack', 'exploit', 'compromise', 'phish', 'deploy',
        'ransom', 'encrypt', 'exfiltrat', 'move laterally', 'beacon',
        'used', 'leveraged', 'abused', 'campaign', 'operation',
        'activity', 'incident', 'disclosure', 'victim',
    )
    return any(token in lowered for token in verbs)


def extract_target_from_activity_text(text: str) -> str:
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


def timeline_category_from_sentence(sentence: str) -> str | None:
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


def extract_major_move_events(
    source_name: str,
    source_id: str,
    occurred_at: str,
    text: str,
    actor_terms: list[str],
    *,
    deps: dict[str, object],
) -> list[dict[str, object]]:
    _split_sentences = deps['split_sentences']
    _extract_ttp_ids = deps['extract_ttp_ids']
    _new_id = deps['new_id']

    events: list[dict[str, object]] = []
    for sentence in _split_sentences(text):
        if not sentence_mentions_actor_terms(sentence, actor_terms):
            continue
        if not looks_like_activity_sentence(sentence):
            continue
        category = timeline_category_from_sentence(sentence)
        if category is None:
            continue
        summary = ' '.join(sentence.split())
        if len(summary) > 260:
            summary = summary[:260].rsplit(' ', 1)[0] + '...'
        target_hint = extract_target_hint(sentence)
        ttp_ids = _extract_ttp_ids(sentence)
        title = f'{category.replace("_", " ").title()} move'
        events.append(
            {
                'id': _new_id(),
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
