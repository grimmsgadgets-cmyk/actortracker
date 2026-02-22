import hashlib
import sqlite3
from collections.abc import Callable


def source_fingerprint(
    title: str | None,
    headline: str | None,
    og_title: str | None,
    html_title: str | None,
    pasted_text: str,
    *,
    normalize_text: Callable[[str], str],
    first_sentences: Callable[[str, int], str],
) -> str:
    title_candidate = (
        str(title or '').strip()
        or str(headline or '').strip()
        or str(og_title or '').strip()
        or str(html_title or '').strip()
    )
    normalized_title = normalize_text(title_candidate)[:220]
    excerpt = first_sentences(pasted_text or '', 2)
    normalized_excerpt = normalize_text(excerpt)[:420]
    if not normalized_title and not normalized_excerpt:
        return ''
    raw = f'{normalized_title}|{normalized_excerpt}'
    return hashlib.sha1(raw.encode('utf-8')).hexdigest()


def upsert_source_for_actor(
    connection: sqlite3.Connection,
    actor_id: str,
    source_name: str,
    source_url: str,
    published_at: str | None,
    pasted_text: str,
    trigger_excerpt: str | None = None,
    title: str | None = None,
    headline: str | None = None,
    og_title: str | None = None,
    html_title: str | None = None,
    publisher: str | None = None,
    site_name: str | None = None,
    *,
    build_fingerprint: Callable[[str | None, str | None, str | None, str | None, str], str],
    new_id: Callable[[], str],
    now_iso: Callable[[], str],
) -> str:
    fingerprint = build_fingerprint(title, headline, og_title, html_title, pasted_text)
    existing = connection.execute(
        'SELECT id FROM sources WHERE actor_id = ? AND url = ?',
        (actor_id, source_url),
    ).fetchone()
    if existing is not None:
        metadata_values = [title, headline, og_title, html_title, publisher, site_name]
        if any(str(value or '').strip() for value in metadata_values):
            connection.execute(
                '''
                UPDATE sources
                SET title = COALESCE(NULLIF(title, ''), ?),
                    headline = COALESCE(NULLIF(headline, ''), ?),
                    og_title = COALESCE(NULLIF(og_title, ''), ?),
                    html_title = COALESCE(NULLIF(html_title, ''), ?),
                    publisher = COALESCE(NULLIF(publisher, ''), ?),
                    site_name = COALESCE(NULLIF(site_name, ''), ?)
                WHERE id = ?
                ''',
                (
                    str(title or '').strip() or None,
                    str(headline or '').strip() or None,
                    str(og_title or '').strip() or None,
                    str(html_title or '').strip() or None,
                    str(publisher or '').strip() or None,
                    str(site_name or '').strip() or None,
                    existing[0],
                ),
            )
        if fingerprint:
            connection.execute(
                '''
                UPDATE sources
                SET source_fingerprint = COALESCE(NULLIF(source_fingerprint, ''), ?)
                WHERE id = ?
                ''',
                (fingerprint, existing[0]),
            )
        return str(existing[0])

    if fingerprint:
        fingerprint_existing = connection.execute(
            '''
            SELECT id
            FROM sources
            WHERE actor_id = ? AND source_fingerprint = ?
            LIMIT 1
            ''',
            (actor_id, fingerprint),
        ).fetchone()
        if fingerprint_existing is not None:
            return str(fingerprint_existing[0])

    final_text = pasted_text
    if trigger_excerpt and trigger_excerpt not in final_text:
        final_text = f'{trigger_excerpt}\n\n{pasted_text}'

    source_id = new_id()
    connection.execute(
        '''
        INSERT INTO sources (
            id, actor_id, source_name, url, published_at, retrieved_at, pasted_text,
            source_fingerprint, title, headline, og_title, html_title, publisher, site_name
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            source_id,
            actor_id,
            source_name,
            source_url,
            published_at,
            now_iso(),
            final_text,
            fingerprint or None,
            str(title or '').strip() or None,
            str(headline or '').strip() or None,
            str(og_title or '').strip() or None,
            str(html_title or '').strip() or None,
            str(publisher or '').strip() or None,
            str(site_name or '').strip() or None,
        ),
    )
    return source_id
