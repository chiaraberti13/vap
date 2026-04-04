from fastapi.testclient import TestClient

import app


def test_csp_disallows_inline_scripts_by_default():
    with TestClient(app.app) as client:
        response = client.get("/")

    assert response.status_code == 200
    csp = response.headers.get("Content-Security-Policy", "")
    assert "script-src" in csp
    directives = {}
    for chunk in csp.split(";"):
        directive = chunk.strip()
        if not directive:
            continue
        key, _, value = directive.partition(" ")
        directives[key] = value

    script_src = directives.get("script-src", "")
    style_src = directives.get("style-src", "")
    object_src = directives.get("object-src", "")
    base_uri = directives.get("base-uri", "")
    form_action = directives.get("form-action", "")
    assert "'unsafe-inline'" not in script_src
    assert "'unsafe-inline'" not in style_src
    assert script_src == "'self' https://cdn.tailwindcss.com"
    assert style_src == "'self' https://cdn.tailwindcss.com"
    assert object_src == "'none'"
    assert base_uri == "'self'"
    assert form_action == "'self'"
