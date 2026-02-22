from datetime import datetime, timezone
from typing import Callable


def latest_reporting_recency_label(
    timeline_recent_items: list[dict[str, object]],
    *,
    parse_published_datetime: Callable[[str], datetime | None],
) -> str:
    parsed_dates: list[datetime] = []
    for item in timeline_recent_items:
        dt = parse_published_datetime(str(item.get('occurred_at') or ''))
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


def build_environment_checks(
    timeline_recent_items: list[dict[str, object]],
    recent_activity_highlights: list[dict[str, object]],
    top_techniques: list[dict[str, str]],
    *,
    recency_label: str,
) -> list[dict[str, str]]:
    categories = {str(item.get('category') or '').lower() for item in timeline_recent_items}
    text_blob = ' '.join(
        [str(item.get('title') or '') for item in timeline_recent_items]
        + [str(item.get('summary') or '') for item in timeline_recent_items]
        + [str(item.get('text') or '') for item in recent_activity_highlights]
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


def recent_change_summary(
    timeline_recent_items: list[dict[str, object]],
    recent_activity_highlights: list[dict[str, object]],
    source_items: list[dict[str, object]],
) -> dict[str, str]:
    new_reports = len({str(item.get('source_id') or '') for item in timeline_recent_items if str(item.get('source_id') or '').strip()})
    source_by_id = {str(item.get('id') or ''): item for item in source_items}
    related_source_ids = {str(item.get('source_id') or '').strip() for item in timeline_recent_items if str(item.get('source_id') or '').strip()}

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


def build_recent_activity_highlights(
    timeline_items: list[dict[str, object]],
    sources: list[dict[str, object]],
    actor_terms: list[str],
    *,
    trusted_activity_domains: set[str],
    source_domain: Callable[[str], str],
    canonical_group_domain: Callable[[dict[str, object]], str],
    looks_like_activity_sentence: Callable[[str], bool],
    sentence_mentions_actor_terms: Callable[[str, list[str]], bool],
    text_contains_actor_term: Callable[[str, list[str]], bool],
    normalize_text: Callable[[str], str],
    parse_published_datetime: Callable[[str], datetime | None],
    freshness_badge: Callable[[str | None], tuple[str, str]],
    evidence_title_from_source: Callable[[dict[str, object] | None], str],
    fallback_title_from_url: Callable[[str], str],
    evidence_source_label_from_source: Callable[[dict[str, object] | None], str],
    extract_ttp_ids: Callable[[str], list[str]],
    split_sentences: Callable[[str], list[str]],
    looks_like_navigation_noise: Callable[[str], bool],
) -> list[dict[str, str | None]]:
    def _is_trusted_domain(url: str) -> bool:
        domain = source_domain(url)
        return bool(domain and any(d in domain for d in trusted_activity_domains))

    def _actor_specific_text(text: str, terms: list[str]) -> bool:
        return bool(text and terms and sentence_mentions_actor_terms(text, terms))

    def _candidate_signal_key(
        summary: str,
        category: str,
        target_text: str,
        ttp_values: list[str],
    ) -> str:
        normalized_summary = normalize_text(summary)
        key_summary = ' '.join(normalized_summary.split()[:14])
        key_target = normalize_text(target_text)
        key_ttps = ','.join(sorted(str(value).upper() for value in ttp_values[:4]))
        return f'{normalize_text(category)}|{key_target}|{key_ttps}|{key_summary}'

    def _recency_points(value: str | None) -> int:
        dt = parse_published_datetime(str(value or ''))
        if dt is None:
            return 0
        days_old = max(0, (datetime.now(timezone.utc) - dt).days)
        if days_old <= 1:
            return 4
        if days_old <= 7:
            return 3
        if days_old <= 30:
            return 2
        return 1

    source_by_id = {str(source['id']): source for source in sources}
    highlights: list[dict[str, str | None]] = []
    terms = [term.lower() for term in actor_terms if term]
    if not terms:
        return highlights

    candidates: list[dict[str, object]] = []
    for item in timeline_items:
        source = source_by_id.get(str(item['source_id']))
        summary = str(item.get('summary') or '')
        source_text = str(source.get('pasted_text') if source else '')
        source_url = str(source.get('url') if source else '')
        if not looks_like_activity_sentence(summary):
            continue
        if not (_actor_specific_text(summary, terms) or _actor_specific_text(source_text, terms)):
            continue
        if source_url and not _is_trusted_domain(source_url) and not _actor_specific_text(summary, terms):
            continue

        ttp_list = [str(t) for t in item.get('ttp_ids', [])]
        signal_key = _candidate_signal_key(
            summary,
            str(item.get('category') or ''),
            str(item.get('target_text') or ''),
            ttp_list,
        )
        candidates.append(
            {
                'item': item,
                'source': source,
                'source_url': source_url,
                'summary': summary,
                'signal_key': signal_key,
                'date_value': str(source.get('published_at') if source else '') or str(item.get('occurred_at') or ''),
            }
        )

    signal_domains: dict[str, set[str]] = {}
    for candidate in candidates:
        signal_key = str(candidate.get('signal_key') or '')
        source_obj = candidate.get('source')
        source_domain_value = (
            canonical_group_domain(source_obj)
            if isinstance(source_obj, dict)
            else source_domain(str(candidate.get('source_url') or ''))
        )
        if not signal_key or not source_domain_value:
            continue
        signal_domains.setdefault(signal_key, set()).add(source_domain_value)

    ranked_candidates: list[dict[str, object]] = []
    for candidate in candidates:
        signal_key = str(candidate.get('signal_key') or '')
        source_url = str(candidate.get('source_url') or '')
        corroboration_sources = len(signal_domains.get(signal_key, set()))
        score = _recency_points(str(candidate.get('date_value') or ''))
        if _is_trusted_domain(source_url):
            score += 2
        if corroboration_sources >= 3:
            score += 3
        elif corroboration_sources == 2:
            score += 2
        elif corroboration_sources == 1:
            score += 1

        date_dt = parse_published_datetime(str(candidate.get('date_value') or ''))
        ranked = dict(candidate)
        ranked['score'] = score
        ranked['corroboration_sources'] = corroboration_sources
        ranked['date_dt'] = date_dt or datetime.min.replace(tzinfo=timezone.utc)
        ranked_candidates.append(ranked)

    ranked_candidates.sort(
        key=lambda entry: (
            int(entry.get('score') or 0),
            int(entry.get('corroboration_sources') or 0),
            entry.get('date_dt') or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )

    for candidate in ranked_candidates:
        item = candidate.get('item')
        source = candidate.get('source')
        if not isinstance(item, dict):
            continue
        freshness_value = str(source['published_at']) if source and source.get('published_at') else str(item.get('occurred_at') or '')
        freshness_label, freshness_class = freshness_badge(freshness_value)
        source_url = str(candidate.get('source_url') or '')
        ttp_values = [str(t) for t in item.get('ttp_ids', [])]
        highlights.append(
            {
                'date': str(item.get('occurred_at') or ''),
                'text': str(candidate.get('summary') or ''),
                'category': str(item['category']).replace('_', ' '),
                'target_text': str(item.get('target_text') or ''),
                'ttp_ids': ', '.join(ttp_values),
                'source_name': str(source['source_name']) if source else None,
                'source_url': source_url if source else None,
                'evidence_title': evidence_title_from_source(source) if source else fallback_title_from_url(source_url),
                'evidence_source_label': evidence_source_label_from_source(source) if source else (source_domain(source_url) or 'Unknown source'),
                'evidence_group_domain': canonical_group_domain(source) if source else (source_domain(source_url) or 'unknown-source'),
                'source_published_at': str(source['published_at']) if source and source.get('published_at') else None,
                'corroboration_sources': str(candidate.get('corroboration_sources') or '0'),
                'freshness_label': freshness_label,
                'freshness_class': freshness_class,
            }
        )
        if len(highlights) >= 8:
            break

    if highlights:
        return highlights

    def _activity_synthesis_sentence(text: str, terms: list[str]) -> str | None:
        for sentence in split_sentences(text):
            normalized = ' '.join(sentence.split())
            if len(normalized) < 35:
                continue
            if looks_like_navigation_noise(normalized):
                continue
            if not sentence_mentions_actor_terms(normalized, terms):
                continue
            if not looks_like_activity_sentence(normalized):
                continue
            return normalized
        for sentence in split_sentences(text):
            normalized = ' '.join(sentence.split())
            if len(normalized) < 35:
                continue
            if looks_like_navigation_noise(normalized):
                continue
            if not sentence_mentions_actor_terms(normalized, terms):
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
        if actor_terms and not text_contains_actor_term(combined, actor_terms):
            continue
        if not _is_trusted_domain(str(source.get('url') or '')):
            continue
        synthesized = _activity_synthesis_sentence(text, actor_terms)
        if not synthesized:
            continue
        freshness_label, freshness_class = freshness_badge(str(source.get('published_at') or source.get('retrieved_at') or ''))
        highlights.append(
            {
                'date': str(source.get('published_at') or source.get('retrieved_at') or ''),
                'text': synthesized,
                'category': 'activity synthesis',
                'target_text': '',
                'ttp_ids': ', '.join(extract_ttp_ids(synthesized)[:4]),
                'source_name': str(source['source_name']) if source else None,
                'source_url': str(source['url']) if source else None,
                'evidence_title': evidence_title_from_source(source) if source else fallback_title_from_url(str(source.get('url') or '')),
                'evidence_source_label': evidence_source_label_from_source(source) if source else (source_domain(str(source.get('url') or '')) or 'Unknown source'),
                'evidence_group_domain': canonical_group_domain(source) if source else (source_domain(str(source.get('url') or '')) or 'unknown-source'),
                'source_published_at': str(source['published_at']) if source and source.get('published_at') else None,
                'corroboration_sources': '1',
                'freshness_label': freshness_label,
                'freshness_class': freshness_class,
            }
        )
        if len(highlights) >= 6:
            break
    return highlights
