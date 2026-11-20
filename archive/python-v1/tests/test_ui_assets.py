from test_core import setup


def test_ui_and_offline_docs_are_public_without_credentials(setup):
    client, _, _, _ = setup
    client.headers.pop("Authorization")
    for path in ("/", "/docs", "/static/app.js", "/static/app.css"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert "a" * 32 not in response.text
    assert client.get("/v1/me").status_code == 401
    assert client.get("/data/demo-access.json").status_code == 404
    assert client.get("/static/demo-access.json").status_code == 404
    assert client.get("/openapi.json").status_code == 200


def test_ui_assets_do_not_use_html_injection_or_browser_storage(setup):
    client, _, _, _ = setup
    script = client.get("/static/app.js").text
    for unsafe in ("innerHTML", "outerHTML", "localStorage", "sessionStorage", "eval("):
        assert unsafe not in script
