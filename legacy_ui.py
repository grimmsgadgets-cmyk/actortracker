import html


def render_actors_ui(*, actors: list[dict[str, object]]) -> str:
    actor_items = ''.join(
        (
            f'<li>{html.escape(str(actor["id"]), quote=True)} - '
            f'{html.escape(str(actor["display_name"]), quote=True)}</li>'
        )
        for actor in actors
    )
    return (
        '<!doctype html>'
        '<html><body>'
        '<h1>Actors</h1>'
        '<form method="post" action="/actors">'
        '<label for="display_name">Display Name</label>'
        '<input id="display_name" name="display_name" required />'
        '<button type="submit">Create</button>'
        '</form>'
        '<ul>'
        f'{actor_items}'
        '</ul>'
        '</body></html>'
    )
