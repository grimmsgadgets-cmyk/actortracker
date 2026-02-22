import sqlite3

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import RedirectResponse


def create_api_router(*, deps: dict[str, object]) -> APIRouter:
    router = APIRouter()

    _list_actor_profiles = deps['list_actor_profiles']
    _enforce_request_size = deps['enforce_request_size']
    _default_body_limit_bytes = deps['default_body_limit_bytes']
    _create_actor_profile = deps['create_actor_profile']
    _db_path = deps['db_path']
    _actor_exists = deps['actor_exists']
    _set_actor_notebook_status = deps['set_actor_notebook_status']
    _run_actor_generation = deps['run_actor_generation']

    @router.get('/health')
    def health() -> dict[str, str]:
        return {'status': 'ok'}

    @router.get('/actors')
    def get_actors() -> list[dict[str, str | None]]:
        actors = _list_actor_profiles()
        return [
            {
                'id': str(actor['id']),
                'display_name': str(actor['display_name']),
                'scope_statement': actor['scope_statement'],
                'created_at': str(actor['created_at']),
            }
            for actor in actors
        ]

    @router.post('/actors')
    async def create_actor(request: Request) -> dict[str, str | None]:
        await _enforce_request_size(request, _default_body_limit_bytes)
        content_type = request.headers.get('content-type', '')
        if 'application/json' in content_type:
            payload = await request.json()
        else:
            form_data = await request.form()
            payload = dict(form_data)

        display_name_raw = payload.get('display_name')
        is_tracked_raw = payload.get('is_tracked')
        display_name = str(display_name_raw).strip() if display_name_raw is not None else ''
        scope_statement = None
        if is_tracked_raw is None:
            is_tracked = True
        else:
            is_tracked = str(is_tracked_raw).strip().lower() in {'1', 'true', 'on', 'yes'}

        if not display_name:
            raise HTTPException(status_code=400, detail='display_name is required')

        return _create_actor_profile(display_name, scope_statement, is_tracked=is_tracked)

    @router.post('/actors/{actor_id}/track')
    def track_actor(actor_id: str, background_tasks: BackgroundTasks) -> RedirectResponse:
        with sqlite3.connect(_db_path()) as connection:
            if not _actor_exists(connection, actor_id):
                raise HTTPException(status_code=404, detail='actor not found')
            connection.execute('UPDATE actor_profiles SET is_tracked = 1 WHERE id = ?', (actor_id,))
            connection.commit()
        _set_actor_notebook_status(
            actor_id,
            'running',
            'Fetching sources and generating open analytic questions and timeline entries...',
        )
        background_tasks.add_task(_run_actor_generation, actor_id)
        return RedirectResponse(
            url=f'/?actor_id={actor_id}&notice=Notebook generation started',
            status_code=303,
        )

    @router.post('/actors/{actor_id}/untrack')
    def untrack_actor(actor_id: str) -> RedirectResponse:
        with sqlite3.connect(_db_path()) as connection:
            if not _actor_exists(connection, actor_id):
                raise HTTPException(status_code=404, detail='actor not found')
            connection.execute('UPDATE actor_profiles SET is_tracked = 0 WHERE id = ?', (actor_id,))
            connection.commit()
        _set_actor_notebook_status(actor_id, 'idle', 'Actor untracked.')
        return RedirectResponse(url=f'/?actor_id={actor_id}', status_code=303)

    return router
