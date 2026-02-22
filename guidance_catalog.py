def guidance_for_platform(platform: str, question_text: str) -> dict[str, str | None]:
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


def platforms_for_question(question_text: str) -> list[str]:
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
