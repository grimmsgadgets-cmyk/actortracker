import html
import json
import sqlite3
import uuid
from urllib.parse import quote

import route_paths
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse


def create_evolution_router(*, deps: dict[str, object]) -> APIRouter:
    router = APIRouter()

    _enforce_request_size = deps['enforce_request_size']
    _observation_body_limit_bytes = deps['observation_body_limit_bytes']
    _default_body_limit_bytes = deps['default_body_limit_bytes']
    _db_path = deps['db_path']
    _actor_exists = deps['actor_exists']
    _normalize_technique_id = deps['normalize_technique_id']
    _normalize_string_list = deps['normalize_string_list']
    _utc_now_iso = deps['utc_now_iso']
    _capability_category_from_technique_id = deps['capability_category_from_technique_id']
    _generate_validation_template = deps['generate_validation_template']
    _baseline_entry = deps['baseline_entry']
    _resolve_delta_action = deps['resolve_delta_action']

    @router.get('/actors/{actor_id}/state')
    def get_actor_state(actor_id: str) -> dict[str, object]:
        with sqlite3.connect(_db_path()) as connection:
            row = connection.execute(
                '''
                SELECT actor_id, capability_grid_json, behavioral_model_json, created_at
                FROM actor_state
                WHERE actor_id = ?
                ''',
                (actor_id,),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='actor state not found')
        return {
            'actor_id': row[0],
            'capability_grid': json.loads(row[1]),
            'behavioral_model': json.loads(row[2]),
            'created_at': row[3],
        }

    @router.post(route_paths.ACTOR_STATE_OBSERVATIONS)
    async def create_observation(actor_id: str, request: Request) -> dict[str, object]:
        await _enforce_request_size(request, _observation_body_limit_bytes)
        payload = await request.json()

        source_type_raw = payload.get('source_type')
        source_type = str(source_type_raw).strip() if source_type_raw is not None else ''
        if not source_type:
            raise HTTPException(status_code=400, detail='source_type is required')

        source_ref_raw = payload.get('source_ref')
        source_date_raw = payload.get('source_date')
        source_ref = str(source_ref_raw) if source_ref_raw is not None else None
        source_date = str(source_date_raw) if source_date_raw is not None else None

        ttp_list = [_normalize_technique_id(item) for item in _normalize_string_list(payload.get('ttp_list'))]
        tools_list = _normalize_string_list(payload.get('tools_list'))
        infra_list = _normalize_string_list(payload.get('infra_list'))
        target_list = _normalize_string_list(payload.get('target_list'))

        observation = {
            'id': str(uuid.uuid4()),
            'actor_id': actor_id,
            'source_type': source_type,
            'source_ref': source_ref,
            'source_date': source_date,
            'ttp_list': ttp_list,
            'tools_list': tools_list,
            'infra_list': infra_list,
            'target_list': target_list,
            'created_at': _utc_now_iso(),
        }

        with sqlite3.connect(_db_path()) as connection:
            if not _actor_exists(connection, actor_id):
                raise HTTPException(status_code=404, detail='actor not found')
            connection.execute(
                '''
                INSERT INTO observation_records (
                    id, actor_id, source_type, source_ref, source_date,
                    ttp_json, tools_json, infra_json, targets_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    observation['id'],
                    observation['actor_id'],
                    observation['source_type'],
                    observation['source_ref'],
                    observation['source_date'],
                    json.dumps(observation['ttp_list']),
                    json.dumps(observation['tools_list']),
                    json.dumps(observation['infra_list']),
                    json.dumps(observation['target_list']),
                    observation['created_at'],
                ),
            )
            state_row = connection.execute(
                '''
                SELECT capability_grid_json
                FROM actor_state
                WHERE actor_id = ?
                ''',
                (actor_id,),
            ).fetchone()
            if state_row is not None:
                capability_grid = json.loads(state_row[0])
                for ttp in observation['ttp_list']:
                    category = _capability_category_from_technique_id(ttp)
                    if category is None:
                        continue
                    category_entry = capability_grid.get(category)
                    if not isinstance(category_entry, dict):
                        continue
                    observed_value = category_entry.get('observed')
                    evidence_refs = category_entry.get('evidence_refs')
                    if observed_value != '' or evidence_refs != []:
                        continue
                    existing_pending = connection.execute(
                        '''
                        SELECT id
                        FROM delta_proposals
                        WHERE actor_id = ? AND affected_category = ? AND status = 'pending'
                        ''',
                        (actor_id, category),
                    ).fetchone()
                    if existing_pending is not None:
                        continue
                    connection.execute(
                        '''
                        INSERT INTO delta_proposals (
                            id, actor_id, observation_id, delta_type,
                            affected_category, status, created_at, validation_template_json
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''',
                        (
                            str(uuid.uuid4()),
                            actor_id,
                            observation['id'],
                            'expansion',
                            category,
                            'pending',
                            _utc_now_iso(),
                            json.dumps(_generate_validation_template('expansion', category)),
                        ),
                    )
            connection.commit()

        return observation

    @router.get(route_paths.ACTOR_STATE_OBSERVATIONS)
    def list_observations(actor_id: str) -> list[dict[str, object]]:
        with sqlite3.connect(_db_path()) as connection:
            if not _actor_exists(connection, actor_id):
                raise HTTPException(status_code=404, detail='actor not found')
            rows = connection.execute(
                '''
                SELECT
                    id, actor_id, source_type, source_ref, source_date,
                    ttp_json, tools_json, infra_json, targets_json, created_at
                FROM observation_records
                WHERE actor_id = ?
                ORDER BY created_at DESC
                ''',
                (actor_id,),
            ).fetchall()
        return [
            {
                'id': row[0],
                'actor_id': row[1],
                'source_type': row[2],
                'source_ref': row[3],
                'source_date': row[4],
                'ttp_list': json.loads(row[5]),
                'tools_list': json.loads(row[6]),
                'infra_list': json.loads(row[7]),
                'target_list': json.loads(row[8]),
                'created_at': row[9],
            }
            for row in rows
        ]

    @router.get('/actors/{actor_id}/deltas')
    def list_deltas(actor_id: str) -> list[dict[str, str]]:
        with sqlite3.connect(_db_path()) as connection:
            if not _actor_exists(connection, actor_id):
                raise HTTPException(status_code=404, detail='actor not found')
            rows = connection.execute(
                '''
                SELECT
                    id, actor_id, observation_id, delta_type,
                    affected_category, status, created_at
                FROM delta_proposals
                WHERE actor_id = ?
                ORDER BY created_at DESC
                ''',
                (actor_id,),
            ).fetchall()
        return [
            {
                'id': row[0],
                'actor_id': row[1],
                'observation_id': row[2],
                'delta_type': row[3],
                'affected_category': row[4],
                'status': row[5],
                'created_at': row[6],
            }
            for row in rows
        ]

    @router.post('/actors/{actor_id}/deltas/{delta_id}/resolve')
    async def resolve_delta(actor_id: str, delta_id: str, request: Request) -> dict[str, str]:
        await _enforce_request_size(request, _default_body_limit_bytes)
        payload = await request.json()
        requested_action = str(payload.get('action', ''))
        return _resolve_delta_action(actor_id, delta_id, requested_action)

    @router.get('/actors/{actor_id}/transitions')
    def list_transitions(actor_id: str) -> list[dict[str, str]]:
        with sqlite3.connect(_db_path()) as connection:
            if not _actor_exists(connection, actor_id):
                raise HTTPException(status_code=404, detail='actor not found')
            rows = connection.execute(
                '''
                SELECT
                    id, actor_id, delta_id, previous_state_json,
                    new_state_json, action, created_at
                FROM state_transition_log
                WHERE actor_id = ?
                ORDER BY created_at ASC
                ''',
                (actor_id,),
            ).fetchall()
        return [
            {
                'id': row[0],
                'actor_id': row[1],
                'delta_id': row[2],
                'previous_state_json': row[3],
                'new_state_json': row[4],
                'action': row[5],
                'created_at': row[6],
            }
            for row in rows
        ]

    @router.get('/actors/{actor_id}/deltas/ui', response_class=HTMLResponse)
    def deltas_ui(actor_id: str) -> str:
        with sqlite3.connect(_db_path()) as connection:
            if not _actor_exists(connection, actor_id):
                raise HTTPException(status_code=404, detail='actor not found')
            rows = connection.execute(
                '''
                SELECT id, affected_category, created_at
                FROM delta_proposals
                WHERE actor_id = ? AND status = 'pending'
                ORDER BY created_at DESC
                ''',
                (actor_id,),
            ).fetchall()

        actor_path = quote(actor_id, safe='')
        actor_text = html.escape(actor_id, quote=True)
        items = ''.join(
            (
                f'<li><a href="/actors/{actor_path}/deltas/{quote(str(row[0]), safe="")}/review">'
                f'{html.escape(str(row[0]), quote=True)}</a> - '
                f'{html.escape(str(row[1]), quote=True)} - '
                f'{html.escape(str(row[2]), quote=True)}</li>'
            )
            for row in rows
        )
        return (
            '<!doctype html><html><body>'
            '<h1>Pending Deltas</h1>'
            f'<p>Actor: {actor_text}</p>'
            '<ul>'
            f'{items}'
            '</ul>'
            '</body></html>'
        )

    @router.get('/actors/{actor_id}/deltas/{delta_id}')
    def get_delta(actor_id: str, delta_id: str) -> dict[str, object]:
        with sqlite3.connect(_db_path()) as connection:
            if not _actor_exists(connection, actor_id):
                raise HTTPException(status_code=404, detail='actor not found')
            row = connection.execute(
                '''
                SELECT
                    id, actor_id, observation_id, delta_type,
                    affected_category, status, created_at, validation_template_json
                FROM delta_proposals
                WHERE actor_id = ? AND id = ?
                ''',
                (actor_id, delta_id),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail='delta not found')
        return {
            'id': row[0],
            'actor_id': row[1],
            'observation_id': row[2],
            'delta_type': row[3],
            'affected_category': row[4],
            'status': row[5],
            'created_at': row[6],
            'validation_template': json.loads(row[7]),
        }

    @router.get('/actors/{actor_id}/deltas/{delta_id}/review', response_class=HTMLResponse)
    def delta_review_ui(actor_id: str, delta_id: str) -> str:
        with sqlite3.connect(_db_path()) as connection:
            if not _actor_exists(connection, actor_id):
                raise HTTPException(status_code=404, detail='actor not found')
            delta_row = connection.execute(
                '''
                SELECT
                    id, actor_id, observation_id, delta_type,
                    affected_category, status, created_at, validation_template_json
                FROM delta_proposals
                WHERE actor_id = ? AND id = ?
                ''',
                (actor_id, delta_id),
            ).fetchone()
            if delta_row is None:
                raise HTTPException(status_code=404, detail='delta not found')

            observation_row = connection.execute(
                '''
                SELECT source_type, source_ref, source_date, ttp_json, tools_json,
                       infra_json, targets_json, created_at
                FROM observation_records
                WHERE id = ?
                ''',
                (delta_row[2],),
            ).fetchone()
            if observation_row is None:
                raise HTTPException(status_code=404, detail='observation not found')

            state_row = connection.execute(
                '''
                SELECT capability_grid_json
                FROM actor_state
                WHERE actor_id = ?
                ''',
                (actor_id,),
            ).fetchone()
            if state_row is None:
                raise HTTPException(status_code=404, detail='actor state not found')

        capability_grid = json.loads(state_row[0])
        affected_category = delta_row[4]
        category_entry = capability_grid.get(affected_category)
        if not isinstance(category_entry, dict):
            category_entry = _baseline_entry()

        validation_template = json.loads(delta_row[7])
        tier1 = validation_template.get('tier1_basic', [])
        tier2 = validation_template.get('tier2_analytic', [])
        tier3 = validation_template.get('tier3_strategic', [])

        ttp_list = json.loads(observation_row[3])
        tools_list = json.loads(observation_row[4])
        infra_list = json.loads(observation_row[5])
        target_list = json.loads(observation_row[6])

        actor_path = quote(actor_id, safe='')
        delta_path = quote(delta_id, safe='')

        def render_list(items: list[object]) -> str:
            return ''.join(f'<li>{html.escape(str(item), quote=True)}</li>' for item in items)

        return (
            '<!doctype html><html><body>'
            '<h1>Delta Review</h1>'
            f'<p>Actor id: {html.escape(actor_id, quote=True)}</p>'
            f'<p>Delta id: {html.escape(delta_id, quote=True)}</p>'
            f'<p>Status: {html.escape(str(delta_row[5]), quote=True)}</p>'
            '<h2>Proposed Change</h2>'
            f'<p>delta_type: {html.escape(str(delta_row[3]), quote=True)}</p>'
            f'<p>affected_category: {html.escape(str(affected_category), quote=True)}</p>'
            '<h2>Observation Summary</h2>'
            f'<p>source_type: {html.escape(str(observation_row[0]), quote=True)}</p>'
            f'<p>source_ref: {html.escape(str(observation_row[1]), quote=True)}</p>'
            f'<p>source_date: {html.escape(str(observation_row[2]), quote=True)}</p>'
            f'<p>created_at: {html.escape(str(observation_row[7]), quote=True)}</p>'
            '<p>ttp_list:</p><ul>'
            f'{render_list(ttp_list)}'
            '</ul>'
            '<p>tools_list:</p><ul>'
            f'{render_list(tools_list)}'
            '</ul>'
            '<p>infra_list:</p><ul>'
            f'{render_list(infra_list)}'
            '</ul>'
            '<p>target_list:</p><ul>'
            f'{render_list(target_list)}'
            '</ul>'
            '<h2>Current Baseline</h2>'
            f'<p>observed: {html.escape(str(category_entry.get("observed", "")), quote=True)}</p>'
            f'<p>assessed: {html.escape(str(category_entry.get("assessed", "")), quote=True)}</p>'
            f'<p>confidence: {html.escape(str(category_entry.get("confidence", 0.0)), quote=True)}</p>'
            f'<p>evidence_refs: {html.escape(str(category_entry.get("evidence_refs", [])), quote=True)}</p>'
            '<h2>Validation Ladder</h2>'
            '<h3>Tier 1 Basic</h3><ul>'
            f'{render_list(tier1)}'
            '</ul>'
            '<h3>Tier 2 Analytic</h3><ul>'
            f'{render_list(tier2)}'
            '</ul>'
            '<h3>Tier 3 Strategic</h3><ul>'
            f'{render_list(tier3)}'
            '</ul>'
            f'<form method="post" action="/actors/{actor_path}/deltas/{delta_path}/accept">'
            '<button type="submit">Accept</button>'
            '</form>'
            f'<form method="post" action="/actors/{actor_path}/deltas/{delta_path}/reject">'
            '<button type="submit">Reject</button>'
            '</form>'
            '</body></html>'
        )

    @router.post('/actors/{actor_id}/deltas/{delta_id}/accept')
    def accept_delta_ui(actor_id: str, delta_id: str) -> RedirectResponse:
        _resolve_delta_action(actor_id, delta_id, 'accept')
        return RedirectResponse(url=f'/actors/{actor_id}/deltas/{delta_id}/review', status_code=303)

    @router.post('/actors/{actor_id}/deltas/{delta_id}/reject')
    def reject_delta_ui(actor_id: str, delta_id: str) -> RedirectResponse:
        _resolve_delta_action(actor_id, delta_id, 'reject')
        return RedirectResponse(url=f'/actors/{actor_id}/deltas/{delta_id}/review', status_code=303)

    return router
