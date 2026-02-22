from datetime import datetime, timedelta, timezone


def build_notebook_kpis_core(
    timeline_items: list[dict[str, object]],
    known_technique_ids: set[str],
    open_questions_count: int,
    sources: list[dict[str, object]],
    *,
    deps: dict[str, object],
) -> dict[str, str]:
    _parse_published_datetime = deps['parse_published_datetime']
    _mitre_valid_technique_ids = deps['mitre_valid_technique_ids']

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


def build_timeline_graph_core(timeline_items: list[dict[str, object]], *, deps: dict[str, object]) -> list[dict[str, object]]:
    _bucket_label = deps['bucket_label']
    _timeline_category_color = deps['timeline_category_color']

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


def first_seen_for_techniques_core(
    timeline_items: list[dict[str, object]],
    technique_ids: list[str],
    *,
    deps: dict[str, object],
) -> list[dict[str, str]]:
    _parse_published_datetime = deps['parse_published_datetime']
    _short_date = deps['short_date']

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


def severity_label_core(category: str, target_text: str, novelty: bool) -> str:
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


def action_text_core(category: str) -> str:
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


def compact_timeline_rows_core(
    timeline_items: list[dict[str, object]],
    known_technique_ids: set[str],
    *,
    parse_iso_for_sort,
    short_date,
    action_text,
    severity_label,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    sorted_items = sorted(
        timeline_items,
        key=lambda entry: parse_iso_for_sort(str(entry.get('occurred_at') or '')),
        reverse=True,
    )
    for item in sorted_items[:14]:
        ttp_ids = [str(t).upper() for t in item.get('ttp_ids', [])]
        novelty = any(tech_id not in known_technique_ids for tech_id in ttp_ids) if ttp_ids else False
        category = str(item.get('category') or 'report')
        target = str(item.get('target_text') or '')
        rows.append(
            {
                'date': short_date(str(item.get('occurred_at') or '')),
                'category': category.replace('_', ' '),
                'action': action_text(category),
                'target': target,
                'techniques': ', '.join(ttp_ids),
                'severity': severity_label(category, target, novelty),
                'summary': str(item.get('summary') or ''),
            }
        )
    return rows


def emerging_techniques_from_timeline_core(
    timeline_items: list[dict[str, object]],
    known_technique_ids: set[str],
    *,
    limit: int,
    min_distinct_sources: int,
    min_event_count: int,
    deps: dict[str, object],
) -> list[dict[str, object]]:
    _mitre_technique_index = deps['mitre_technique_index']
    _parse_published_datetime = deps['parse_published_datetime']
    _normalize_technique_id = deps['normalize_technique_id']

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
