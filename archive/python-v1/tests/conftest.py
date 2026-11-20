import pytest


@pytest.fixture(autouse=True)
def isolated_runtime_settings(monkeypatch):
    monkeypatch.delenv("ASTRAGUARD_MODEL_DIGEST", raising=False)
    monkeypatch.delenv("ASTRAGUARD_AUDIT_RETENTION_DAYS", raising=False)
