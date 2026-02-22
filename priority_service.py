from datetime import datetime


def priority_where_to_check_core(
    guidance_items: list[dict[str, object]],
    question_text: str,
    *,
    deps: dict[str, object],
) -> str:
    _priority_where_to_check = deps['priority_where_to_check']
    _platforms_for_question = deps['platforms_for_question']
    return _priority_where_to_check(
        guidance_items,
        question_text,
        platforms_for_question=lambda text: _platforms_for_question(text),
    )


def telemetry_anchor_line_core(
    guidance_items: list[dict[str, object]],
    question_text: str,
    *,
    deps: dict[str, object],
) -> str:
    _telemetry_anchor_line = deps['telemetry_anchor_line']
    _platforms_for_question = deps['platforms_for_question']
    return _telemetry_anchor_line(
        guidance_items,
        question_text,
        platforms_for_question=lambda text: _platforms_for_question(text),
    )


def guidance_query_hint_core(
    guidance_items: list[dict[str, object]],
    question_text: str,
    *,
    deps: dict[str, object],
) -> str:
    _guidance_query_hint = deps['guidance_query_hint']
    _platforms_for_question = deps['platforms_for_question']
    _guidance_for_platform = deps['guidance_for_platform']
    return _guidance_query_hint(
        guidance_items,
        question_text,
        platforms_for_question=lambda text: _platforms_for_question(text),
        guidance_for_platform=lambda platform, text: _guidance_for_platform(platform, text),
    )


def priority_update_evidence_dt_core(update: dict[str, object], *, deps: dict[str, object]) -> datetime | None:
    _priority_update_evidence_dt = deps['priority_update_evidence_dt']
    _parse_published_datetime = deps['parse_published_datetime']
    return _priority_update_evidence_dt(
        update,
        parse_published_datetime=lambda value: _parse_published_datetime(value),
    )


def question_org_alignment_core(question_text: str, org_context: str, *, deps: dict[str, object]) -> int:
    _question_org_alignment = deps['question_org_alignment']
    _token_set = deps['token_set']
    return _question_org_alignment(
        question_text,
        org_context,
        token_set=lambda text: _token_set(text),
    )
