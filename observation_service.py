from datetime import date
from typing import Sequence


def normalize_observation_filters_core(
    *,
    analyst: str | None,
    confidence: str | None,
    updated_from: str | None,
    updated_to: str | None,
) -> dict[str, str]:
    analyst_text = str(analyst or '').strip().lower()

    confidence_value = str(confidence or '').strip().lower()
    if confidence_value not in {'low', 'moderate', 'high'}:
        confidence_value = ''

    from_value = str(updated_from or '').strip()
    normalized_from = ''
    if from_value:
        try:
            normalized_from = date.fromisoformat(from_value).isoformat()
        except ValueError:
            normalized_from = ''

    to_value = str(updated_to or '').strip()
    normalized_to = ''
    if to_value:
        try:
            normalized_to = date.fromisoformat(to_value).isoformat()
        except ValueError:
            normalized_to = ''

    return {
        'analyst': analyst_text,
        'confidence': confidence_value,
        'updated_from': normalized_from,
        'updated_to': normalized_to,
    }


def build_observation_where_clause_core(
    actor_id: str,
    *,
    filters: dict[str, str],
) -> tuple[str, list[object]]:
    where_clauses = ['actor_id = ?']
    params: list[object] = [actor_id]

    analyst_text = str(filters.get('analyst', '')).strip().lower()
    if analyst_text:
        where_clauses.append('LOWER(updated_by) LIKE ?')
        params.append(f'%{analyst_text}%')

    confidence_value = str(filters.get('confidence', '')).strip().lower()
    if confidence_value:
        where_clauses.append('confidence = ?')
        params.append(confidence_value)

    from_value = str(filters.get('updated_from', '')).strip()
    if from_value:
        where_clauses.append('substr(updated_at, 1, 10) >= ?')
        params.append(from_value)

    to_value = str(filters.get('updated_to', '')).strip()
    if to_value:
        where_clauses.append('substr(updated_at, 1, 10) <= ?')
        params.append(to_value)

    return (' AND '.join(where_clauses), params)


def observation_source_keys_core(rows: Sequence[tuple[object, ...]]) -> list[str]:
    return sorted(
        {
            str(row[1])
            for row in rows
            if str(row[0] or '').strip().lower() == 'source' and str(row[1] or '').strip()
        }
    )


def source_lookup_chunks_core(source_keys: Sequence[str], *, chunk_size: int = 800) -> list[list[str]]:
    safe_chunk_size = max(1, int(chunk_size))
    keys = list(source_keys)
    return [keys[idx: idx + safe_chunk_size] for idx in range(0, len(keys), safe_chunk_size)]


def observation_quality_guidance_core(
    *,
    note: str,
    source_ref: str,
    confidence: str,
    source_reliability: str,
    information_credibility: str,
) -> list[str]:
    cleaned_note = ' '.join(str(note or '').split())
    lowered_note = cleaned_note.lower()
    confidence_value = str(confidence or '').strip().lower()
    source_ref_value = str(source_ref or '').strip()
    source_reliability_value = str(source_reliability or '').strip().upper()
    info_credibility_value = str(information_credibility or '').strip()

    guidance: list[str] = []
    if confidence_value == 'high' and not source_ref_value:
        guidance.append('High confidence should include a source reference (case/report/ticket id).')

    if confidence_value == 'high' and (not source_reliability_value or not info_credibility_value):
        guidance.append('High confidence should include source reliability (A-F) and information credibility (1-6).')

    words = [token for token in lowered_note.split(' ') if token]
    if not words:
        guidance.append('Add a short note describing what changed versus prior assessment.')
    elif len(words) < 6:
        guidance.append('Add one concrete detail (behavior, target, or timeframe) to reduce ambiguity.')

    vague_phrases = (
        'looks bad',
        'suspicious activity',
        'monitor this',
        'needs review',
        'check this',
        'watch this',
    )
    if lowered_note and len(words) <= 12 and any(phrase in lowered_note for phrase in vague_phrases):
        guidance.append('Replace vague wording with one evidence-backed observation from this source.')

    rationale_tokens = ('because', 'since', 'due to', 'based on', 'confirmed', 'observed', 'evidence')
    if confidence_value in {'high', 'moderate'} and lowered_note and not any(token in lowered_note for token in rationale_tokens):
        guidance.append('Add a short confidence rationale (for example: based on two corroborating reports).')

    return guidance[:3]


def map_observation_rows_core(
    rows: Sequence[tuple[object, ...]],
    *,
    source_lookup: dict[str, dict[str, str]],
) -> list[dict[str, object]]:
    return [
        {
            'item_type': row[0],
            'item_key': row[1],
            'note': row[2] or '',
            'source_ref': row[3] or '',
            'confidence': row[4] or 'moderate',
            'source_reliability': row[5] or '',
            'information_credibility': row[6] or '',
            'updated_by': row[7] or '',
            'updated_at': row[8] or '',
            'quality_guidance': observation_quality_guidance_core(
                note=str(row[2] or ''),
                source_ref=str(row[3] or ''),
                confidence=str(row[4] or 'moderate'),
                source_reliability=str(row[5] or ''),
                information_credibility=str(row[6] or ''),
            ),
            'source_name': source_lookup.get(str(row[1]), {}).get('source_name', ''),
            'source_url': source_lookup.get(str(row[1]), {}).get('source_url', ''),
            'source_title': source_lookup.get(str(row[1]), {}).get('source_title', ''),
            'source_date': source_lookup.get(str(row[1]), {}).get('source_date', ''),
        }
        for row in rows
    ]
