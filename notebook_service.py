def build_notebook_wrapper_core(
    *,
    actor_id: str,
    generate_questions: bool,
    rebuild_timeline: bool,
    deps: dict[str, object],
) -> None:
    _build_notebook_core = deps['build_notebook_core']
    _db_path = deps['db_path']

    _build_notebook_core(
        actor_id,
        db_path=_db_path(),
        generate_questions=generate_questions,
        rebuild_timeline=rebuild_timeline,
        now_iso=deps['now_iso'],
        actor_exists=deps['actor_exists'],
        build_actor_profile_from_mitre=deps['build_actor_profile_from_mitre'],
        actor_terms_fn=deps['actor_terms_fn'],
        extract_major_move_events=deps['extract_major_move_events'],
        normalize_text=deps['normalize_text'],
        token_overlap=deps['token_overlap'],
        extract_question_sentences=deps['extract_question_sentences'],
        sentence_mentions_actor_terms=deps['sentence_mentions_actor_terms'],
        sanitize_question_text=deps['sanitize_question_text'],
        question_from_sentence=deps['question_from_sentence'],
        ollama_generate_questions=deps['ollama_generate_questions'],
        platforms_for_question=deps['platforms_for_question'],
        guidance_for_platform=deps['guidance_for_platform'],
    )


def fetch_actor_notebook_wrapper_core(*, actor_id: str, deps: dict[str, object]) -> dict[str, object]:
    _pipeline_fetch_actor_notebook_core = deps['pipeline_fetch_actor_notebook_core']
    _db_path = deps['db_path']

    return _pipeline_fetch_actor_notebook_core(
        actor_id,
        db_path=_db_path(),
        deps={
            'parse_published_datetime': deps['parse_published_datetime'],
            'safe_json_string_list': deps['safe_json_string_list'],
            'actor_signal_categories': deps['actor_signal_categories'],
            'question_actor_relevance': deps['question_actor_relevance'],
            'priority_update_evidence_dt': deps['priority_update_evidence_dt'],
            'question_org_alignment': deps['question_org_alignment'],
            'priority_rank_score': deps['priority_rank_score'],
            'phase_label_for_question': deps['phase_label_for_question'],
            'priority_where_to_check': deps['priority_where_to_check'],
            'priority_confidence_label': deps['priority_confidence_label'],
            'quick_check_title': deps['quick_check_title'],
            'short_decision_trigger': deps['short_decision_trigger'],
            'telemetry_anchor_line': deps['telemetry_anchor_line'],
            'priority_next_best_action': deps['priority_next_best_action'],
            'guidance_line': deps['guidance_line'],
            'guidance_query_hint': deps['guidance_query_hint'],
            'priority_disconfirming_signal': deps['priority_disconfirming_signal'],
            'confidence_change_threshold_line': deps['confidence_change_threshold_line'],
            'escalation_threshold_line': deps['escalation_threshold_line'],
            'priority_update_recency_label': deps['priority_update_recency_label'],
            'org_alignment_label': deps['org_alignment_label'],
            'fallback_priority_questions': deps['fallback_priority_questions'],
            'token_overlap': deps['token_overlap'],
            'build_actor_profile_from_mitre': deps['build_actor_profile_from_mitre'],
            'group_top_techniques': deps['group_top_techniques'],
            'favorite_attack_vectors': deps['favorite_attack_vectors'],
            'known_technique_ids_for_entity': deps['known_technique_ids_for_entity'],
            'emerging_techniques_from_timeline': deps['emerging_techniques_from_timeline'],
            'build_timeline_graph': deps['build_timeline_graph'],
            'compact_timeline_rows': deps['compact_timeline_rows'],
            'actor_terms': deps['actor_terms'],
            'build_recent_activity_highlights': deps['build_recent_activity_highlights'],
            'build_recent_activity_synthesis': deps['build_recent_activity_synthesis'],
            'recent_change_summary': deps['recent_change_summary'],
            'build_environment_checks': deps['build_environment_checks'],
            'build_notebook_kpis': deps['build_notebook_kpis'],
            'format_date_or_unknown': deps['format_date_or_unknown'],
        },
    )
