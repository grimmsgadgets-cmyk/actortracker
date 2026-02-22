import sqlite3
from datetime import datetime, timezone
from starlette.requests import Request
from fastapi import BackgroundTasks
from fastapi.testclient import TestClient

import pytest

import app as app_module


def _setup_db(tmp_path):
    app_module.DB_PATH = str(tmp_path / 'test.db')
    app_module.initialize_sqlite()


def test_build_notebook_creates_thread_and_update_with_excerpt(tmp_path):
    _setup_db(tmp_path)
    actor = app_module.create_actor_profile('APT-Test', 'Test scope')

    with sqlite3.connect(app_module.DB_PATH) as connection:
        connection.execute(
            '''
            INSERT INTO sources (
                id, actor_id, source_name, url, published_at, retrieved_at, pasted_text
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
                (
                    'src-1',
                    actor['id'],
                    'CISA',
                    'https://example.com/report',
                    '2026-02-15',
                    '2026-02-15T00:00:00+00:00',
                    'APT-Test operators should review suspicious PowerShell activity and hunt for indicators.',
                ),
            )
        connection.commit()

    app_module.build_notebook(actor['id'])

    with sqlite3.connect(app_module.DB_PATH) as connection:
        thread = connection.execute(
            'SELECT id, question_text FROM question_threads WHERE actor_id = ?',
            (actor['id'],),
        ).fetchone()
        assert thread is not None

        update = connection.execute(
            '''
            SELECT qu.trigger_excerpt, s.source_name, s.url, s.published_at
            FROM question_updates qu
            JOIN sources s ON s.id = qu.source_id
            WHERE qu.thread_id = ?
            ''',
            (thread[0],),
        ).fetchone()
        assert update is not None
        assert update[0]
        assert update[1] == 'CISA'
        assert update[2] == 'https://example.com/report'
        assert update[3] == '2026-02-15'


def test_build_notebook_wrapper_delegates_to_builder_core(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_build_core(actor_id, **kwargs):
        captured['actor_id'] = actor_id
        captured.update(kwargs)

    monkeypatch.setattr(app_module, 'build_notebook_core', _fake_build_core)

    app_module.build_notebook('actor-wrapper-test', generate_questions=False, rebuild_timeline=False)

    assert captured['actor_id'] == 'actor-wrapper-test'
    assert captured['db_path'] == app_module.DB_PATH
    assert captured['generate_questions'] is False
    assert captured['rebuild_timeline'] is False


def test_fetch_actor_notebook_wrapper_delegates_to_pipeline_core(monkeypatch):
    captured: dict[str, object] = {}

    def _fake_fetch_core(actor_id, **kwargs):
        captured['actor_id'] = actor_id
        captured.update(kwargs)
        return {'ok': True}

    monkeypatch.setattr(app_module, 'pipeline_fetch_actor_notebook_core', _fake_fetch_core)

    result = app_module._fetch_actor_notebook('actor-wrapper-test')  # noqa: SLF001

    assert result == {'ok': True}
    assert captured['actor_id'] == 'actor-wrapper-test'
    assert captured['db_path'] == app_module.DB_PATH
    deps = captured['deps']
    assert isinstance(deps, dict)
    assert 'build_recent_activity_highlights' in deps
    assert 'build_notebook_kpis' in deps
    assert 'format_date_or_unknown' in deps


def test_fetch_actor_notebook_payload_shape_regression(tmp_path):
    _setup_db(tmp_path)
    actor = app_module.create_actor_profile('APT-Payload', 'Payload shape scope')

    notebook = app_module._fetch_actor_notebook(actor['id'])  # noqa: SLF001

    required_keys = {
        'actor',
        'recent_activity_highlights',
        'priority_questions',
        'kpis',
    }
    assert required_keys.issubset(notebook.keys())
    assert isinstance(notebook['actor'], dict)
    assert isinstance(notebook['recent_activity_highlights'], list)
    assert isinstance(notebook['priority_questions'], list)
    assert isinstance(notebook['kpis'], dict)


def test_validate_outbound_url_blocks_localhost():
    with pytest.raises(app_module.HTTPException):
        app_module._validate_outbound_url('http://localhost/internal')  # noqa: SLF001


def test_validate_outbound_url_honors_allowlist(monkeypatch):
    monkeypatch.setattr(
        app_module.socket,
        'getaddrinfo',
        lambda *_args, **_kwargs: [(None, None, None, None, ('93.184.216.34', 0))],
    )
    with pytest.raises(app_module.HTTPException):
        app_module._validate_outbound_url(  # noqa: SLF001
            'https://example.org/report',
            allowed_domains={'example.com'},
        )


def test_validate_outbound_url_blocks_private_ip(monkeypatch):
    monkeypatch.setattr(
        app_module.socket,
        'getaddrinfo',
        lambda *_args, **_kwargs: [(None, None, None, None, ('127.0.0.1', 0))],
    )
    with pytest.raises(app_module.HTTPException):
        app_module._validate_outbound_url('https://example.com')  # noqa: SLF001


def test_safe_http_get_revalidates_redirect_target(monkeypatch):
    class _Response:
        def __init__(self, url: str, status_code: int, location: str | None = None):
            self.url = url
            self.status_code = status_code
            self.headers = {'location': location} if location else {}

        @property
        def is_redirect(self) -> bool:
            return self.status_code in {301, 302, 303, 307, 308}

    def _validate(url: str, allowed_domains=None):
        if 'localhost' in url:
            raise app_module.HTTPException(status_code=400, detail='blocked')
        return url

    monkeypatch.setattr(app_module, '_validate_outbound_url', _validate)
    monkeypatch.setattr(
        app_module.httpx,
        'get',
        lambda *args, **kwargs: _Response('https://safe.example/path', 302, 'http://localhost/admin'),
    )
    with pytest.raises(app_module.HTTPException):
        app_module._safe_http_get('https://safe.example/path', timeout=5.0)  # noqa: SLF001


def test_domain_allowed_for_actor_search_blocks_spoofed_hosts():
    assert app_module._domain_allowed_for_actor_search('https://www.mandiant.com/blog/post')  # noqa: SLF001
    assert app_module._domain_allowed_for_actor_search('https://sub.mandiant.com/report')  # noqa: SLF001
    assert not app_module._domain_allowed_for_actor_search('https://evilmandiant.com/report')  # noqa: SLF001
    assert not app_module._domain_allowed_for_actor_search('https://mandiant.com.evil.org/report')  # noqa: SLF001


def test_add_source_uses_manual_text_without_remote_fetch(tmp_path, monkeypatch):
    _setup_db(tmp_path)
    actor = app_module.create_actor_profile('APT-Manual', 'Manual source scope')

    def _should_not_fetch(*_args, **_kwargs):
        raise AssertionError('derive_source_from_url should not be called for manual text imports')

    monkeypatch.setattr(app_module, 'derive_source_from_url', _should_not_fetch)

    with TestClient(app_module.app) as client:
        response = client.post(
            f"/actors/{actor['id']}/sources",
            data={
                'source_url': 'https://example.com/report',
                'pasted_text': 'Manual analyst text about APT-Manual operations and observed tactics.',
                'published_at': '2026-02-10',
            },
            follow_redirects=False,
        )

    assert response.status_code == 303
    with sqlite3.connect(app_module.DB_PATH) as connection:
        row = connection.execute(
            '''
            SELECT source_name, url, pasted_text
            FROM sources
            WHERE actor_id = ?
            ''',
            (actor['id'],),
        ).fetchone()
    assert row is not None
    assert row[0] == 'example.com'
    assert row[1] == 'https://example.com/report'
    assert 'Manual analyst text' in row[2]


def test_upsert_source_skips_near_duplicate_content_by_fingerprint(tmp_path):
    _setup_db(tmp_path)
    actor = app_module.create_actor_profile('APT-Dedupe', 'Dedupe source scope')

    with sqlite3.connect(app_module.DB_PATH) as connection:
        first_id = app_module._upsert_source_for_actor(  # noqa: SLF001
            connection=connection,
            actor_id=str(actor['id']),
            source_name='CISA',
            source_url='https://example.com/advisory-a',
            published_at='2026-02-20',
            pasted_text='APT-Dedupe targeted edge devices and used phishing for access.',
            trigger_excerpt='APT-Dedupe targeted edge devices.',
            title='APT-Dedupe campaign update',
        )
        second_id = app_module._upsert_source_for_actor(  # noqa: SLF001
            connection=connection,
            actor_id=str(actor['id']),
            source_name='Mandiant',
            source_url='https://another.example.org/report-b',
            published_at='2026-02-21',
            pasted_text='APT-Dedupe targeted edge devices and used phishing for access.',
            trigger_excerpt='APT-Dedupe targeted edge devices.',
            title='APT-Dedupe campaign update',
        )
        connection.commit()
        count = connection.execute(
            'SELECT COUNT(*) FROM sources WHERE actor_id = ?',
            (actor['id'],),
        ).fetchone()[0]

    assert first_id == second_id
    assert count == 1


def test_capability_category_from_technique_id_uses_mitre_dataset(monkeypatch):
    monkeypatch.setattr(
        app_module,
        'MITRE_DATASET_CACHE',
        {
            'objects': [
                {
                    'type': 'attack-pattern',
                    'id': 'attack-pattern--1',
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'T1566'},
                    ],
                    'kill_chain_phases': [{'phase_name': 'initial-access'}],
                }
            ]
        },
    )
    monkeypatch.setattr(app_module, 'MITRE_TECHNIQUE_PHASE_CACHE', None)

    assert app_module._capability_category_from_technique_id('T1566') == 'initial_access'  # noqa: SLF001
    assert app_module._capability_category_from_technique_id('T1566.001') == 'initial_access'  # noqa: SLF001
    assert app_module._capability_category_from_technique_id('T9999') is None  # noqa: SLF001


def test_create_observation_generates_delta_from_mitre_tactic_mapping(tmp_path, monkeypatch):
    _setup_db(tmp_path)
    actor = app_module.create_actor_profile('APT-Mitre', 'MITRE-mapped observation scope')
    app_module.initialize_actor_state(actor['id'])

    with TestClient(app_module.app) as client:
        monkeypatch.setattr(
            app_module,
            'MITRE_DATASET_CACHE',
            {
                'objects': [
                    {
                        'type': 'attack-pattern',
                        'id': 'attack-pattern--2',
                        'external_references': [
                            {'source_name': 'mitre-attack', 'external_id': 'T1071'},
                        ],
                        'kill_chain_phases': [{'phase_name': 'command-and-control'}],
                    }
                ]
            },
        )
        monkeypatch.setattr(app_module, 'MITRE_TECHNIQUE_PHASE_CACHE', None)

        obs_response = client.post(
            f"/actors/{actor['id']}/observations",
            json={
                'source_type': 'report',
                'source_ref': 'unit-test',
                'ttp_list': ['t1071.001'],
                'tools_list': [],
                'infra_list': [],
                'target_list': [],
            },
        )
        assert obs_response.status_code == 200

        deltas_response = client.get(f"/actors/{actor['id']}/deltas")
        assert deltas_response.status_code == 200
        deltas = deltas_response.json()

    assert deltas
    assert deltas[0]['affected_category'] == 'command_and_control'
    assert deltas[0]['status'] == 'pending'


def test_match_mitre_group_uses_x_mitre_aliases_and_attack_id(monkeypatch):
    monkeypatch.setattr(
        app_module,
        'MITRE_DATASET_CACHE',
        {
            'objects': [
                {
                    'type': 'intrusion-set',
                    'id': 'intrusion-set--unit-1',
                    'name': 'Alpha Group',
                    'aliases': ['Alpha Legacy'],
                    'x_mitre_aliases': ['Alias One'],
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'G1234'},
                    ],
                }
            ]
        },
    )
    monkeypatch.setattr(app_module, 'MITRE_GROUP_CACHE', None)

    alias_match = app_module._match_mitre_group('Alias One')  # noqa: SLF001
    assert alias_match is not None
    assert alias_match['name'] == 'Alpha Group'

    id_match = app_module._match_mitre_group('G1234')  # noqa: SLF001
    assert id_match is not None
    assert id_match['name'] == 'Alpha Group'


def test_match_mitre_software_uses_aliases_and_attack_id(monkeypatch):
    monkeypatch.setattr(
        app_module,
        'MITRE_DATASET_CACHE',
        {
            'objects': [
                {
                    'type': 'tool',
                    'id': 'tool--unit-1',
                    'name': 'Gamma Tool',
                    'aliases': ['Gamma Legacy'],
                    'x_mitre_aliases': ['GammaX'],
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'S9001'},
                    ],
                }
            ]
        },
    )
    monkeypatch.setattr(app_module, 'MITRE_SOFTWARE_CACHE', None)

    alias_match = app_module._match_mitre_software('Gamma Legacy')  # noqa: SLF001
    assert alias_match is not None
    assert alias_match['name'] == 'Gamma Tool'

    id_match = app_module._match_mitre_software('S9001')  # noqa: SLF001
    assert id_match is not None
    assert id_match['name'] == 'Gamma Tool'


def test_match_mitre_software_fuzzy_uses_alias_tokens(monkeypatch):
    monkeypatch.setattr(
        app_module,
        'MITRE_DATASET_CACHE',
        {
            'objects': [
                {
                    'type': 'malware',
                    'id': 'malware--unit-2',
                    'name': 'Unrelated Primary',
                    'x_mitre_aliases': ['Wizard Spider'],
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'S9002'},
                    ],
                }
            ]
        },
    )
    monkeypatch.setattr(app_module, 'MITRE_SOFTWARE_CACHE', None)

    fuzzy_match = app_module._match_mitre_software('wizard spider team')  # noqa: SLF001
    assert fuzzy_match is not None
    assert fuzzy_match['name'] == 'Unrelated Primary'


def test_match_mitre_group_uses_campaign_alias_enrichment(monkeypatch):
    monkeypatch.setattr(
        app_module,
        'MITRE_DATASET_CACHE',
        {
            'objects': [
                {
                    'type': 'intrusion-set',
                    'id': 'intrusion-set--unit-2',
                    'name': 'Canonical Group',
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'G2000'},
                    ],
                },
                {
                    'type': 'campaign',
                    'id': 'campaign--unit-1',
                    'name': 'Operation Snowfall',
                    'x_mitre_aliases': ['Snowfall Cluster'],
                },
                {
                    'type': 'relationship',
                    'relationship_type': 'attributed-to',
                    'source_ref': 'campaign--unit-1',
                    'target_ref': 'intrusion-set--unit-2',
                },
            ]
        },
    )
    monkeypatch.setattr(app_module, 'MITRE_GROUP_CACHE', None)
    monkeypatch.setattr(app_module, 'MITRE_CAMPAIGN_LINK_CACHE', None)

    match = app_module._match_mitre_group('Snowfall Cluster')  # noqa: SLF001
    assert match is not None
    assert match['name'] == 'Canonical Group'


def test_match_mitre_software_uses_campaign_alias_enrichment(monkeypatch):
    monkeypatch.setattr(
        app_module,
        'MITRE_DATASET_CACHE',
        {
            'objects': [
                {
                    'type': 'tool',
                    'id': 'tool--unit-9',
                    'name': 'Canonical Tool',
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'S2000'},
                    ],
                },
                {
                    'type': 'campaign',
                    'id': 'campaign--unit-9',
                    'name': 'Project Lantern',
                    'aliases': ['Lantern Ops'],
                },
                {
                    'type': 'relationship',
                    'relationship_type': 'uses',
                    'source_ref': 'campaign--unit-9',
                    'target_ref': 'tool--unit-9',
                },
            ]
        },
    )
    monkeypatch.setattr(app_module, 'MITRE_SOFTWARE_CACHE', None)
    monkeypatch.setattr(app_module, 'MITRE_CAMPAIGN_LINK_CACHE', None)

    match = app_module._match_mitre_software('Lantern Ops')  # noqa: SLF001
    assert match is not None
    assert match['name'] == 'Canonical Tool'


def test_actors_ui_escapes_actor_display_name(tmp_path):
    _setup_db(tmp_path)
    app_module.create_actor_profile('APT-<script>alert(1)</script>', 'Test scope')

    response = app_module.actors_ui()

    assert '<script>alert(1)</script>' not in response
    assert 'APT-&lt;script&gt;alert(1)&lt;/script&gt;' in response


def test_resolve_startup_db_path_falls_back_on_permission_error(monkeypatch):
    original_db_path = app_module.DB_PATH
    app_module.DB_PATH = '/data/app.db'
    calls: list[str] = []

    def fake_prepare(path_value: str) -> str:
        calls.append(path_value)
        if path_value == '/data/app.db':
            raise PermissionError('denied')
        return path_value

    monkeypatch.setattr(app_module, '_prepare_db_path', fake_prepare)
    resolved = app_module._resolve_startup_db_path()  # noqa: SLF001
    app_module.DB_PATH = original_db_path

    assert calls[0] == '/data/app.db'
    assert resolved.endswith('/app.db')


def test_root_handles_notebook_load_failure(tmp_path, monkeypatch):
    _setup_db(tmp_path)
    actor = app_module.create_actor_profile('APT-Render', 'Render scope')
    with sqlite3.connect(app_module.DB_PATH) as connection:
        connection.execute('UPDATE actor_profiles SET is_tracked = 1 WHERE id = ?', (actor['id'],))
        connection.commit()

    monkeypatch.setattr(app_module, '_fetch_actor_notebook', lambda actor_id: (_ for _ in ()).throw(RuntimeError('boom')))
    monkeypatch.setattr(app_module, 'get_ollama_status', lambda: {'available': False, 'base_url': 'http://offline', 'model': 'none'})

    scope = {
        'type': 'http',
        'asgi': {'version': '3.0'},
        'http_version': '1.1',
        'method': 'GET',
        'scheme': 'http',
        'path': '/',
        'raw_path': b'/',
        'query_string': f'actor_id={actor["id"]}'.encode(),
        'headers': [],
        'client': ('127.0.0.1', 12345),
        'server': ('testserver', 80),
    }
    request = Request(scope)

    response = app_module.root(
        request=request,
        background_tasks=BackgroundTasks(),
        actor_id=str(actor['id']),
        notice=None,
    )

    assert response.status_code == 200


def test_root_renders_analyst_flow_headings(tmp_path, monkeypatch):
    _setup_db(tmp_path)
    actor = app_module.create_actor_profile('APT-Flow', 'Flow scope')
    monkeypatch.setattr(app_module, 'run_actor_generation', lambda actor_id: None)
    monkeypatch.setattr(
        app_module,
        'get_ollama_status',
        lambda: {'available': False, 'base_url': 'http://offline', 'model': 'none'},
    )

    with TestClient(app_module.app) as client:
        response = client.get(f'/?actor_id={actor["id"]}')

    assert response.status_code == 200
    assert '1) Who are they?' in response.text
    assert '2) What have they been up to recently?' in response.text
    assert '3) What do I do about it?' in response.text


def test_known_technique_ids_for_entity_collects_all_uses(monkeypatch):
    monkeypatch.setattr(
        app_module,
        'MITRE_DATASET_CACHE',
        {
            'objects': [
                {
                    'type': 'attack-pattern',
                    'id': 'attack-pattern--1',
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'T1001'},
                    ],
                },
                {
                    'type': 'attack-pattern',
                    'id': 'attack-pattern--2',
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'T1002'},
                    ],
                },
                {
                    'type': 'attack-pattern',
                    'id': 'attack-pattern--3',
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'T1003.001'},
                    ],
                },
                {
                    'type': 'relationship',
                    'relationship_type': 'uses',
                    'source_ref': 'intrusion-set--unit-1',
                    'target_ref': 'attack-pattern--1',
                },
                {
                    'type': 'relationship',
                    'relationship_type': 'uses',
                    'source_ref': 'intrusion-set--unit-1',
                    'target_ref': 'attack-pattern--2',
                },
                {
                    'type': 'relationship',
                    'relationship_type': 'uses',
                    'source_ref': 'intrusion-set--unit-1',
                    'target_ref': 'attack-pattern--3',
                },
            ]
        },
    )

    known = app_module._known_technique_ids_for_entity('intrusion-set--unit-1')  # noqa: SLF001

    assert known == {'T1001', 'T1002', 'T1003.001'}


def test_emerging_technique_ids_require_repeated_evidence_and_sort_by_recent():
    timeline_items = [
        {
            'occurred_at': '2026-02-05T00:00:00+00:00',
            'source_id': 'src-1',
            'ttp_ids': ['T9001'],
        },
        {
            'occurred_at': 'Tue, 04 Feb 2026 00:00:00 GMT',
            'source_id': 'src-2',
            'ttp_ids': ['T9002'],
        },
        {
            'occurred_at': '2026-02-06T00:00:00+00:00',
            'source_id': 'src-3',
            'ttp_ids': ['T9002'],
        },
        {
            'occurred_at': '2026-02-07T00:00:00+00:00',
            'source_id': 'src-4',
            'ttp_ids': ['T9003'],
        },
        {
            'occurred_at': '2026-02-08T00:00:00+00:00',
            'source_id': 'src-4',
            'ttp_ids': ['T9003'],
        },
    ]

    emerging = app_module._emerging_technique_ids_from_timeline(  # noqa: SLF001
        timeline_items,
        known_technique_ids=set(),
    )

    assert emerging == ['T9003', 'T9002']


def test_first_seen_for_techniques_handles_mixed_datetime_formats():
    timeline_items = [
        {'occurred_at': 'Tue, 04 Feb 2026 00:00:00 GMT', 'ttp_ids': ['T7001']},
        {'occurred_at': '2026-02-03T00:00:00+00:00', 'ttp_ids': ['T7001']},
    ]

    seen = app_module._first_seen_for_techniques(timeline_items, ['T7001'])  # noqa: SLF001

    assert seen == [{'technique_id': 'T7001', 'first_seen': '2026-02-03'}]


def test_extract_ttp_ids_filters_non_mitre_techniques(monkeypatch):
    monkeypatch.setattr(
        app_module,
        'MITRE_DATASET_CACHE',
        {
            'objects': [
                {
                    'type': 'attack-pattern',
                    'id': 'attack-pattern--1111',
                    'name': 'Unit Technique',
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'T1111'},
                    ],
                }
            ]
        },
    )
    monkeypatch.setattr(app_module, 'MITRE_TECHNIQUE_INDEX_CACHE', None)

    values = app_module._extract_ttp_ids('Observed T1111 and T9999 plus t1111 again.')  # noqa: SLF001

    assert values == ['T1111']


def test_emerging_techniques_include_metadata_and_drop_unknown_ids(monkeypatch):
    monkeypatch.setattr(
        app_module,
        'MITRE_DATASET_CACHE',
        {
            'objects': [
                {
                    'type': 'attack-pattern',
                    'id': 'attack-pattern--9002',
                    'name': 'Technique Nine Zero Zero Two',
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'T9002', 'url': 'https://attack.mitre.org/techniques/T9002/'},
                    ],
                },
                {
                    'type': 'attack-pattern',
                    'id': 'attack-pattern--9003',
                    'name': 'Technique Nine Zero Zero Three',
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'T9003', 'url': 'https://attack.mitre.org/techniques/T9003/'},
                    ],
                },
            ]
        },
    )
    monkeypatch.setattr(app_module, 'MITRE_TECHNIQUE_INDEX_CACHE', None)

    timeline_items = [
        {'occurred_at': '2026-02-06T00:00:00+00:00', 'source_id': 'a', 'category': 'execution', 'ttp_ids': ['T9002']},
        {'occurred_at': '2026-02-07T00:00:00+00:00', 'source_id': 'b', 'category': 'execution', 'ttp_ids': ['T9002']},
        {'occurred_at': '2026-02-08T00:00:00+00:00', 'source_id': 'z', 'category': 'impact', 'ttp_ids': ['T9003']},
        {'occurred_at': '2026-02-09T00:00:00+00:00', 'source_id': 'z', 'category': 'impact', 'ttp_ids': ['T9003', 'T9999']},
    ]

    emerging = app_module._emerging_techniques_from_timeline(timeline_items, known_technique_ids=set())  # noqa: SLF001

    assert [item['technique_id'] for item in emerging] == ['T9003', 'T9002']
    assert emerging[0]['technique_name'] == 'Technique Nine Zero Zero Three'
    assert emerging[0]['source_count'] == 1
    assert emerging[0]['event_count'] == 2
    assert emerging[0]['categories'] == ['impact']


def test_build_notebook_kpis_ignores_unknown_technique_ids(monkeypatch):
    monkeypatch.setattr(
        app_module,
        'MITRE_DATASET_CACHE',
        {
            'objects': [
                {
                    'type': 'attack-pattern',
                    'id': 'attack-pattern--1111',
                    'name': 'Known Technique',
                    'external_references': [
                        {'source_name': 'mitre-attack', 'external_id': 'T1111'},
                    ],
                }
            ]
        },
    )
    monkeypatch.setattr(app_module, 'MITRE_TECHNIQUE_INDEX_CACHE', None)

    now_iso = datetime.now(timezone.utc).isoformat()
    kpis = app_module._build_notebook_kpis(  # noqa: SLF001
        timeline_items=[{'occurred_at': now_iso, 'ttp_ids': ['T9999']}],
        known_technique_ids=set(),
        open_questions_count=0,
        sources=[],
    )

    assert kpis['new_techniques_30d'] == '0'


def test_recent_activity_highlights_prioritize_corroborated_signals():
    timeline_items = [
        {
            'occurred_at': '2026-02-20T12:00:00+00:00',
            'summary': 'APT-Flow targeted VPN edge appliances to gain initial access.',
            'category': 'initial_access',
            'target_text': 'Retail',
            'ttp_ids': ['T1566'],
            'source_id': 'src-1',
        },
        {
            'occurred_at': '2026-02-19T12:00:00+00:00',
            'summary': 'APT-Flow targeted VPN edge appliances to gain initial access.',
            'category': 'initial_access',
            'target_text': 'Retail',
            'ttp_ids': ['T1566'],
            'source_id': 'src-2',
        },
        {
            'occurred_at': '2026-02-20T13:00:00+00:00',
            'summary': 'APT-Flow used phishing lures in a broad campaign.',
            'category': 'initial_access',
            'target_text': 'Retail',
            'ttp_ids': ['T1566'],
            'source_id': 'src-3',
        },
    ]
    sources = [
        {
            'id': 'src-1',
            'source_name': 'CISA',
            'url': 'https://www.cisa.gov/advisories/aaa',
            'published_at': '2026-02-20T11:30:00+00:00',
            'pasted_text': 'APT-Flow targeted VPN edge appliances.',
            'title': 'CISA advisory',
        },
        {
            'id': 'src-2',
            'source_name': 'Mandiant',
            'url': 'https://www.mandiant.com/resources/blog/bbb',
            'published_at': '2026-02-19T11:30:00+00:00',
            'pasted_text': 'APT-Flow targeted VPN edge appliances.',
            'title': 'Mandiant blog',
        },
        {
            'id': 'src-3',
            'source_name': 'CISA',
            'url': 'https://www.cisa.gov/advisories/ccc',
            'published_at': '2026-02-20T12:30:00+00:00',
            'pasted_text': 'APT-Flow used phishing lures.',
            'title': 'CISA campaign note',
        },
    ]

    highlights = app_module._build_recent_activity_highlights(  # noqa: SLF001
        timeline_items=timeline_items,
        sources=sources,
        actor_terms=['APT-Flow'],
    )

    assert highlights
    assert 'VPN edge appliances' in str(highlights[0]['text'])
    assert highlights[0]['corroboration_sources'] == '2'


def test_run_actor_generation_returns_early_when_actor_already_running(monkeypatch):
    monkeypatch.setattr(app_module, '_mark_actor_generation_started', lambda _actor_id: False)  # noqa: SLF001

    called = {'imported': 0, 'built': 0}

    def _import_feeds(_actor_id):
        called['imported'] += 1
        return 0

    def _build_notebook(_actor_id):
        called['built'] += 1

    monkeypatch.setattr(app_module, 'import_default_feeds_for_actor', _import_feeds)
    monkeypatch.setattr(app_module, 'build_notebook', _build_notebook)

    app_module.run_actor_generation('actor-1')

    assert called['imported'] == 0
    assert called['built'] == 0


def test_text_contains_actor_term_uses_token_boundaries():
    assert app_module._text_contains_actor_term('APT-Flow targeted VPN edge', ['apt-flow'])  # noqa: SLF001
    assert not app_module._text_contains_actor_term('The apartment lease was updated.', ['apt'])  # noqa: SLF001
    assert not app_module._text_contains_actor_term('Wizardly operations observed.', ['wizard'])  # noqa: SLF001


def test_run_actor_generation_builds_timeline_then_full_notebook(monkeypatch):
    monkeypatch.setattr(app_module, '_mark_actor_generation_started', lambda _actor_id: True)  # noqa: SLF001
    monkeypatch.setattr(app_module, '_mark_actor_generation_finished', lambda _actor_id: None)  # noqa: SLF001
    monkeypatch.setattr(app_module, 'import_default_feeds_for_actor', lambda _actor_id: 3)

    status_messages: list[str] = []
    build_calls: list[tuple[bool, bool]] = []

    def _status(_actor_id, _status, message):
        status_messages.append(message)

    def _build(_actor_id, *, generate_questions=True, rebuild_timeline=True):
        build_calls.append((generate_questions, rebuild_timeline))

    monkeypatch.setattr(app_module, 'set_actor_notebook_status', _status)
    monkeypatch.setattr(app_module, 'build_notebook', _build)

    class _DummyConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, *_args, **_kwargs):
            return None

        def commit(self):
            return None

    monkeypatch.setattr(app_module.sqlite3, 'connect', lambda *_args, **_kwargs: _DummyConn())

    app_module.run_actor_generation('actor-2')

    assert build_calls == [(False, True), (True, False)]
    assert any('Sources collected (3). Building timeline preview...' in message for message in status_messages)
    assert any('Timeline ready. Generating question threads and guidance...' in message for message in status_messages)
