import json
import sqlite3
import uuid

from fastapi import HTTPException


def initialize_actor_state_core(*, actor_id: str, deps: dict[str, object]) -> dict[str, str]:
    _utc_now_iso = deps['utc_now_iso']
    _baseline_capability_grid = deps['baseline_capability_grid']
    _baseline_behavioral_model = deps['baseline_behavioral_model']
    _db_path = deps['db_path']
    _actor_exists = deps['actor_exists']

    created_at = _utc_now_iso()
    capability_grid_json = json.dumps(_baseline_capability_grid())
    behavioral_model_json = json.dumps(_baseline_behavioral_model())

    with sqlite3.connect(_db_path()) as connection:
        if not _actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')

        state_row = connection.execute(
            'SELECT actor_id FROM actor_state WHERE actor_id = ?',
            (actor_id,),
        ).fetchone()
        if state_row is not None:
            raise HTTPException(status_code=409, detail='actor state already initialized')

        connection.execute(
            '''
            INSERT INTO actor_state (
                actor_id, capability_grid_json, behavioral_model_json, created_at
            )
            VALUES (?, ?, ?, ?)
            ''',
            (actor_id, capability_grid_json, behavioral_model_json, created_at),
        )
        connection.commit()

    return {'actor_id': actor_id, 'status': 'initialized'}


def resolve_delta_action_core(
    *,
    actor_id: str,
    delta_id: str,
    requested_action: str,
    deps: dict[str, object],
) -> dict[str, str]:
    _utc_now_iso = deps['utc_now_iso']
    _db_path = deps['db_path']
    _actor_exists = deps['actor_exists']
    _baseline_entry = deps['baseline_entry']

    if requested_action not in ('accept', 'reject'):
        raise HTTPException(status_code=400, detail='action must be accept or reject')

    created_at = _utc_now_iso()

    with sqlite3.connect(_db_path()) as connection:
        if not _actor_exists(connection, actor_id):
            raise HTTPException(status_code=404, detail='actor not found')

        delta_row = connection.execute(
            '''
            SELECT id, observation_id, affected_category, status
            FROM delta_proposals
            WHERE id = ? AND actor_id = ?
            ''',
            (delta_id, actor_id),
        ).fetchone()
        if delta_row is None:
            raise HTTPException(status_code=404, detail='delta not found')
        if delta_row[3] != 'pending':
            raise HTTPException(status_code=409, detail='delta is not pending')

        state_row = connection.execute(
            '''
            SELECT capability_grid_json, behavioral_model_json
            FROM actor_state
            WHERE actor_id = ?
            ''',
            (actor_id,),
        ).fetchone()
        if state_row is None:
            raise HTTPException(status_code=404, detail='actor state not found')

        capability_grid = json.loads(state_row[0])
        behavioral_model = json.loads(state_row[1])
        previous_state = {
            'capability_grid': capability_grid,
            'behavioral_model': behavioral_model,
        }
        previous_state_json = json.dumps(previous_state)

        if requested_action == 'reject':
            connection.execute(
                '''
                UPDATE delta_proposals
                SET status = 'rejected'
                WHERE id = ? AND actor_id = ?
                ''',
                (delta_id, actor_id),
            )
            connection.execute(
                '''
                INSERT INTO state_transition_log (
                    id, actor_id, delta_id, previous_state_json,
                    new_state_json, action, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    str(uuid.uuid4()),
                    actor_id,
                    delta_id,
                    previous_state_json,
                    previous_state_json,
                    'rejected',
                    created_at,
                ),
            )
            connection.commit()
            return {'delta_id': delta_id, 'action': 'rejected'}

        affected_category = delta_row[2]
        observation_id = delta_row[1]
        category_entry = capability_grid.get(affected_category)
        if not isinstance(category_entry, dict):
            category_entry = _baseline_entry()
            capability_grid[affected_category] = category_entry

        current_refs = category_entry.get('evidence_refs')
        if not isinstance(current_refs, list):
            current_refs = []
        current_refs = [str(ref) for ref in current_refs]
        current_refs.append(observation_id)
        category_entry['observed'] = f'Baseline expanded via delta {delta_id}'
        category_entry['evidence_refs'] = current_refs

        new_state = {
            'capability_grid': capability_grid,
            'behavioral_model': behavioral_model,
        }
        new_state_json = json.dumps(new_state)

        connection.execute(
            '''
            UPDATE actor_state
            SET capability_grid_json = ?, behavioral_model_json = ?
            WHERE actor_id = ?
            ''',
            (json.dumps(capability_grid), json.dumps(behavioral_model), actor_id),
        )
        connection.execute(
            '''
            UPDATE delta_proposals
            SET status = 'accepted'
            WHERE id = ? AND actor_id = ?
            ''',
            (delta_id, actor_id),
        )
        connection.execute(
            '''
            INSERT INTO state_transition_log (
                id, actor_id, delta_id, previous_state_json,
                new_state_json, action, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                str(uuid.uuid4()),
                actor_id,
                delta_id,
                previous_state_json,
                new_state_json,
                'accepted',
                created_at,
            ),
        )
        connection.commit()

    return {
        'delta_id': delta_id,
        'action': 'accepted',
        'affected_category': affected_category,
    }
