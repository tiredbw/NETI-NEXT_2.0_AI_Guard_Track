import json
from pathlib import Path
import stat
import subprocess
import sys


def test_launcher_prepares_private_stable_credentials(tmp_path):
    directory = tmp_path / "demo"
    command = [sys.executable, str(Path("scripts/run_demo.py").resolve()), "--prepare-only", "--state-dir", str(directory)]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    path = directory / "demo-access.json"
    access = json.loads(path.read_text())
    assert len(access["identities"]) == 5
    assert len(access["hmac_key"]) == 64
    for token in access["identities"]:
        assert len(token) >= 32 and token not in result.stdout
    assert access["hmac_key"] not in result.stdout
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    before = path.read_bytes()
    subprocess.run(command, check=True, capture_output=True)
    assert path.read_bytes() == before


def test_launcher_adds_admin_without_rotating_existing_secrets(tmp_path):
    directory = tmp_path / "demo"
    directory.mkdir(mode=0o700)
    existing = {"identities": {"old-token-" * 4: {"subject_id": "alice", "tenant_id": "A", "role": "viewer"}}, "hmac_key": "h" * 64}
    path = directory / "demo-access.json"
    path.write_text(json.dumps(existing))
    result = subprocess.run([sys.executable, str(Path("scripts/run_demo.py").resolve()), "--prepare-only",
                             "--state-dir", str(directory)], check=True, capture_output=True, text=True)
    migrated = json.loads(path.read_text())
    assert migrated["hmac_key"] == existing["hmac_key"]
    assert migrated["identities"]["old-token-" * 4] == existing["identities"]["old-token-" * 4]
    admin = [p for p in migrated["identities"].values() if p["role"] == "policy_admin"]
    assert admin == [{"subject_id": "policy-admin", "tenant_id": "control", "role": "policy_admin"}]
    assert "old-token" not in result.stdout
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
