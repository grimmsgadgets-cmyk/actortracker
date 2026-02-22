import time
from collections import deque


def request_body_limit_bytes_core(
    method: str,
    path: str,
    source_upload_body_limit_bytes: int,
    observation_body_limit_bytes: int,
    default_body_limit_bytes: int,
) -> int:
    method_upper = method.upper()
    if method_upper not in {'POST', 'PUT', 'PATCH'}:
        return 0
    if path.startswith('/actors/') and path.endswith('/sources'):
        return source_upload_body_limit_bytes
    if path.startswith('/actors/') and path.endswith('/observations'):
        return observation_body_limit_bytes
    return default_body_limit_bytes


def rate_limit_bucket_core(
    method: str,
    path: str,
    rate_limit_heavy_per_minute: int,
    rate_limit_default_per_minute: int,
) -> tuple[str, int] | None:
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
        return ('write_heavy', rate_limit_heavy_per_minute)
    return ('write_default', rate_limit_default_per_minute)


def request_client_id_core(request) -> str:
    forwarded_for = request.headers.get('x-forwarded-for', '').strip()
    if forwarded_for:
        first_hop = forwarded_for.split(',', 1)[0].strip()
        if first_hop:
            return first_hop
    if request.client and request.client.host:
        return request.client.host
    return 'unknown'


def prune_rate_limit_state_core(*, now: float, rate_limit_state: dict[str, deque[float]], rate_limit_window_seconds: int) -> None:
    stale_keys: list[str] = []
    for key, timestamps in rate_limit_state.items():
        while timestamps and now - timestamps[0] >= rate_limit_window_seconds:
            timestamps.popleft()
        if not timestamps:
            stale_keys.append(key)
    for key in stale_keys:
        rate_limit_state.pop(key, None)


def check_rate_limit_core(
    request,
    *,
    rate_limit_enabled: bool,
    rate_limit_window_seconds: int,
    rate_limit_state: dict[str, deque[float]],
    rate_limit_lock,
    rate_limit_cleanup_every: int,
    rate_limit_request_counter_ref: dict[str, int],
    rate_limit_bucket,
    request_client_id,
    prune_rate_limit_state,
) -> tuple[bool, int, int]:
    bucket = rate_limit_bucket(request.method, request.url.path)
    if not rate_limit_enabled or bucket is None:
        return (False, 0, 0)
    bucket_name, limit = bucket
    client_id = request_client_id(request)
    key = f'{bucket_name}:{client_id}'
    now = time.monotonic()
    with rate_limit_lock:
        rate_limit_request_counter_ref['value'] += 1
        if rate_limit_request_counter_ref['value'] % rate_limit_cleanup_every == 0:
            prune_rate_limit_state(now)
        timestamps = rate_limit_state[key]
        while timestamps and now - timestamps[0] >= rate_limit_window_seconds:
            timestamps.popleft()
        if len(timestamps) >= limit:
            retry_after = max(1, int(rate_limit_window_seconds - (now - timestamps[0])) + 1)
            return (True, retry_after, limit)
        timestamps.append(now)
    return (False, 0, limit)
