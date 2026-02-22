import re
from datetime import datetime, timezone
from typing import Callable


def question_priority_score(thread: dict[str, object]) -> int:
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


def question_category_hints(question_text: str) -> set[str]:
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


def actor_signal_categories(timeline_items: list[dict[str, object]]) -> set[str]:
    categories: set[str] = set()
    for item in timeline_items:
        category = str(item.get('category') or '').strip()
        if category:
            categories.add(category)
    return categories


def question_actor_relevance(question_text: str, actor_categories: set[str], signal_text: str) -> int:
    hints = question_category_hints(question_text)
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


def fallback_priority_questions(actor_name: str, actor_categories: set[str]) -> list[dict[str, str]]:
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
                'question_text': 'What changed in telemetry that increases confidence this actor is active in our environment?',
                'priority': 'Medium',
                'know_focus': f'{actor_name} reporting is limited, so confidence shifts should rely on concrete local evidence.',
                'hunt_focus': 'Hunt for corroborating endpoint and network alerts tied to actor-reported techniques.',
                'decision_to_inform': 'Decide whether confidence should move up, down, or remain unchanged based on corroborated signals.',
                'where_to_check': 'EDR, Windows Event Logs, DNS/Proxy',
                'time_horizon': 'This week',
                'confidence': 'Low',
                'disconfirming_signal': 'No corroborating endpoint/network evidence linked to reported tradecraft.',
            }
        )
    return catalog[:3]


def priority_know_focus(question_text: str) -> str:
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


def priority_hunt_focus(question_text: str) -> str:
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


def priority_decision_to_inform(question_text: str) -> str:
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


def priority_time_horizon(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('impact', 'ransom', 'exfiltrat', 'data theft')):
        return 'Current shift'
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit', 'initial access')):
        return 'Next 24 hours'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot', 'beacon', 'c2')):
        return 'Next 72 hours'
    return 'This week'


def priority_disconfirming_signal(question_text: str) -> str:
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


def priority_confidence_label(updates_count: int, relevance: int, latest_excerpt: str) -> str:
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


def priority_where_to_check(
    guidance_items: list[dict[str, object]],
    question_text: str,
    *,
    platforms_for_question: Callable[[str], list[str]],
) -> str:
    platforms: list[str] = []
    for item in guidance_items:
        value = str(item.get('platform') or '').strip()
        if value and value not in platforms:
            platforms.append(value)
    if not platforms:
        for platform in platforms_for_question(question_text):
            if platform not in platforms:
                platforms.append(platform)
    return ', '.join(platforms[:3]) if platforms else 'Windows Event Logs'


def priority_strongest_evidence(latest_excerpt: str, latest_source_name: str) -> str:
    if latest_excerpt:
        source = latest_source_name.strip() if latest_source_name else 'recent source reporting'
        return f'{source}: "{latest_excerpt}"'
    return 'No direct cue excerpt yet; priority based on correlated thread/question signals.'


def priority_confidence_why(
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


def priority_assumptions(question_text: str) -> str:
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


def priority_alternative_hypothesis(question_text: str) -> str:
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


def priority_next_best_action(question_text: str, where_to_check: str) -> str:
    _ = question_text
    first_location = where_to_check.split(',')[0].strip() if where_to_check else 'Windows Event Logs'
    return f'Run a targeted 15-minute validation query in {first_location} for the latest cue and confirm signal presence.'


def priority_action_ladder(question_text: str) -> tuple[str, str, str]:
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


def phase_label_for_question(question_text: str) -> str:
    hints = question_category_hints(question_text)
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


def short_decision_trigger(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit', 'initial access')):
        return 'What changed since last review in external intrusion signals on internet-facing systems?'
    if any(token in lowered for token in ('powershell', 'wmi', 'scheduled task', 'execution')):
        return 'What changed since last review in suspicious endpoint execution behavior?'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot')):
        return 'What changed since last review in internal host-to-host spread indicators?'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon', 'command-and-control')):
        return 'What changed since last review in command-and-control beacon or domain patterns?'
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection')):
        return 'What changed since last review in data staging or exfiltration indicators?'
    if any(token in lowered for token in ('encrypt', 'ransom', 'impact', 'disrupt')):
        return 'What changed since last review in disruptive impact activity signals?'
    return 'What changed since last review in this activity across current telemetry?'


def telemetry_anchor_line(
    guidance_items: list[dict[str, object]],
    question_text: str,
    *,
    platforms_for_question: Callable[[str], list[str]],
) -> str:
    platforms: list[str] = []
    for item in guidance_items:
        platform = str(item.get('platform') or '').strip()
        if platform and platform not in platforms:
            platforms.append(platform)
    if not platforms:
        platforms = platforms_for_question(question_text)
    return ', '.join(platforms[:2]) if platforms else 'Windows Event Logs'


def guidance_line(guidance_items: list[dict[str, object]], key: str) -> str:
    for item in guidance_items:
        value = str(item.get(key) or '').strip()
        if not value:
            continue
        first = value.splitlines()[0].strip().lstrip('-').strip()
        if first:
            return first
    return ''


def guidance_query_hint(
    guidance_items: list[dict[str, object]],
    question_text: str,
    *,
    platforms_for_question: Callable[[str], list[str]],
    guidance_for_platform: Callable[[str, str], dict[str, str | None]],
) -> str:
    for item in guidance_items:
        value = str(item.get('query_hint') or '').strip()
        if value:
            return value
    fallback = guidance_for_platform(platforms_for_question(question_text)[0], question_text)
    return str(fallback.get('query_hint') or '')


def priority_update_evidence_dt(
    update: dict[str, object],
    *,
    parse_published_datetime: Callable[[str], datetime | None],
) -> datetime | None:
    published = parse_published_datetime(str(update.get('source_published_at') or ''))
    if published is not None:
        return published
    return parse_published_datetime(str(update.get('created_at') or ''))


def priority_update_recency_label(evidence_dt: datetime | None) -> str:
    if evidence_dt is None:
        return 'Evidence recency unknown'
    days_old = max(0, (datetime.now(timezone.utc) - evidence_dt).days)
    if days_old <= 1:
        return 'Evidence age: <= 24h'
    if days_old <= 7:
        return f'Evidence age: {days_old}d'
    if days_old <= 30:
        return f'Evidence age: {days_old}d (stale)'
    return f'Evidence age: {days_old}d (very stale)'


def priority_recency_points(evidence_dt: datetime | None) -> int:
    if evidence_dt is None:
        return 0
    days_old = max(0, (datetime.now(timezone.utc) - evidence_dt).days)
    if days_old <= 1:
        return 3
    if days_old <= 7:
        return 2
    if days_old <= 30:
        return 1
    return 0


def priority_rank_score(
    thread: dict[str, object],
    relevance: int,
    evidence_dt: datetime | None,
    corroborating_sources: int,
    org_alignment: int,
) -> int:
    score = question_priority_score(thread) + max(0, relevance)
    score += priority_recency_points(evidence_dt)
    if corroborating_sources >= 3:
        score += 2
    elif corroborating_sources >= 2:
        score += 1
    score += max(0, min(org_alignment, 3))
    return score


def org_context_tokens(org_context: str) -> set[str]:
    stopwords = {
        'about', 'after', 'again', 'against', 'among', 'assets', 'because', 'before', 'being',
        'below', 'between', 'business', 'could', 'environment', 'having', 'other', 'should',
        'their', 'there', 'these', 'those', 'through', 'under', 'until', 'which', 'while',
        'within', 'without',
    }
    return {
        token
        for token in re.findall(r'[a-z0-9]{4,}', org_context.lower())
        if token not in stopwords
    }


def question_org_alignment(
    question_text: str,
    org_context: str,
    *,
    token_set: Callable[[str], set[str]],
) -> int:
    if not org_context.strip():
        return 0
    q_tokens = token_set(question_text)
    c_tokens = org_context_tokens(org_context)
    if not q_tokens or not c_tokens:
        return 0
    overlap = len(q_tokens.intersection(c_tokens))
    if overlap >= 3:
        return 3
    if overlap == 2:
        return 2
    if overlap == 1:
        return 1
    return 0


def org_alignment_label(score: int) -> str:
    if score >= 3:
        return 'High'
    if score >= 2:
        return 'Medium'
    if score >= 1:
        return 'Low'
    return 'Unknown'


def confidence_change_threshold_line(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit', 'initial access')):
        return 'Raise confidence only if 2+ confirmed exploit or unusual access events hit critical systems in 24 hours.'
    if any(token in lowered for token in ('powershell', 'wmi', 'scheduled task', 'execution')):
        return 'Raise confidence when suspicious execution appears on 2+ systems or one critical system.'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot')):
        return 'Raise confidence when abnormal remote-service movement is seen across 2+ internal systems.'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon', 'command-and-control')):
        return 'Raise confidence when repeated suspicious outbound check-ins continue across 2+ intervals.'
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection')):
        return 'Raise confidence when unusual staging activity plus outbound transfer is observed.'
    if any(token in lowered for token in ('encrypt', 'ransom', 'impact', 'disrupt')):
        return 'Raise confidence when backup tampering or widespread encryption activity is detected.'
    return 'Raise confidence when the same suspicious activity is confirmed in both endpoint and network logs.'


def expected_output_line(question_text: str) -> str:
    lowered = question_text.lower()
    if any(token in lowered for token in ('cve', 'vpn', 'edge', 'exploit', 'initial access')):
        return 'Record edge exposure delta, affected assets, and confidence shift with source links.'
    if any(token in lowered for token in ('powershell', 'wmi', 'scheduled task', 'execution')):
        return 'Record execution pattern delta, impacted hosts, and confidence shift with source links.'
    if any(token in lowered for token in ('lateral', 'rdp', 'smb', 'pivot')):
        return 'Record lateral movement delta, host relationships, and confidence shift with source links.'
    if any(token in lowered for token in ('dns', 'domain', 'c2', 'beacon', 'command-and-control')):
        return 'Record outbound beacon/domain delta, cadence, and confidence shift with source links.'
    if any(token in lowered for token in ('exfiltrat', 'stolen data', 'collection')):
        return 'Record staging or exfiltration delta, data scope, and confidence shift with source links.'
    if any(token in lowered for token in ('encrypt', 'ransom', 'impact', 'disrupt')):
        return 'Record impact behavior delta, business effect, and confidence shift with source links.'
    return 'Record the observed delta versus prior review, confidence shift, and source links.'


def escalation_threshold_line(question_text: str) -> str:
    # Backward-compatible alias for older callers while keeping non-escalation language.
    return confidence_change_threshold_line(question_text)


def quick_check_title(question_text: str, phase_label: str) -> str:
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
