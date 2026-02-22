import ipaddress
from typing import Callable
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import HTTPException


def is_blocked_outbound_ip(ip_value: str) -> bool:
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


def host_matches_allowed_domains(hostname: str, allowed_domains: set[str]) -> bool:
    return any(hostname == domain or hostname.endswith(f'.{domain}') for domain in allowed_domains)


def validate_outbound_url(
    source_url: str,
    *,
    allowed_domains: set[str] | None,
    resolve_host: Callable[..., object],
    ipproto_tcp: int,
) -> str:
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

    if allowed_domains and not host_matches_allowed_domains(hostname, allowed_domains):
        raise HTTPException(status_code=400, detail='source_url domain is not allowed')

    try:
        addr_infos = resolve_host(
            hostname,
            parsed.port or (443 if parsed.scheme.lower() == 'https' else 80),
            proto=ipproto_tcp,
        )
    except OSError as exc:
        raise HTTPException(status_code=400, detail=f'failed to resolve source_url host: {exc}') from exc

    for addr_info in addr_infos:
        resolved_ip = str(addr_info[4][0])
        if is_blocked_outbound_ip(resolved_ip):
            raise HTTPException(status_code=400, detail='source_url resolves to a blocked IP range')

    return normalized


def safe_http_get(
    source_url: str,
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
    allowed_domains: set[str] | None = None,
    max_redirects: int = 3,
    validate_url: Callable[[str, set[str] | None], str],
    http_get: Callable[..., httpx.Response],
) -> httpx.Response:
    current_url = validate_url(source_url, allowed_domains)
    for _ in range(max_redirects + 1):
        response = http_get(
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
        current_url = validate_url(next_url, allowed_domains)
    raise HTTPException(status_code=400, detail='too many redirects while fetching source_url')
