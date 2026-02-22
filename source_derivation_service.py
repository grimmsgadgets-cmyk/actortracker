def derive_source_from_url_core(
    source_url: str,
    *,
    fallback_source_name: str | None,
    published_hint: str | None,
    deps: dict[str, object],
) -> dict[str, str | None]:
    _pipeline_derive_source_from_url_core = deps['pipeline_derive_source_from_url_core']
    _safe_http_get = deps['safe_http_get']
    _extract_question_sentences = deps['extract_question_sentences']
    _first_sentences = deps['first_sentences']

    return _pipeline_derive_source_from_url_core(
        source_url,
        fallback_source_name=fallback_source_name,
        published_hint=published_hint,
        deps={
            'safe_http_get': _safe_http_get,
            'extract_question_sentences': _extract_question_sentences,
            'first_sentences': _first_sentences,
        },
    )
