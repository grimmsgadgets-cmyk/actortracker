import sqlite3

from actor_ingest import source_fingerprint as build_source_fingerprint
from actor_ingest import upsert_source_for_actor


def source_fingerprint_core(
    *,
    title: str | None,
    headline: str | None,
    og_title: str | None,
    html_title: str | None,
    pasted_text: str,
    deps: dict[str, object],
) -> str:
    _normalize_text = deps['normalize_text']
    _first_sentences = deps['first_sentences']

    return build_source_fingerprint(
        title,
        headline,
        og_title,
        html_title,
        pasted_text,
        normalize_text=_normalize_text,
        first_sentences=_first_sentences,
    )


def upsert_source_for_actor_core(
    *,
    connection: sqlite3.Connection,
    actor_id: str,
    source_name: str,
    source_url: str,
    published_at: str | None,
    pasted_text: str,
    trigger_excerpt: str | None,
    title: str | None,
    headline: str | None,
    og_title: str | None,
    html_title: str | None,
    publisher: str | None,
    site_name: str | None,
    deps: dict[str, object],
) -> str:
    _source_fingerprint = deps['source_fingerprint']
    _new_id = deps['new_id']
    _now_iso = deps['now_iso']

    return upsert_source_for_actor(
        connection=connection,
        actor_id=actor_id,
        source_name=source_name,
        source_url=source_url,
        published_at=published_at,
        pasted_text=pasted_text,
        trigger_excerpt=trigger_excerpt,
        title=title,
        headline=headline,
        og_title=og_title,
        html_title=html_title,
        publisher=publisher,
        site_name=site_name,
        build_fingerprint=_source_fingerprint,
        new_id=_new_id,
        now_iso=_now_iso,
    )
