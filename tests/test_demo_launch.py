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
    assert len(access["identities"]) == 4
    assert len(access["hmac_key"]) == 64
    for token in access["identities"]:
        assert len(token) >= 32 and token not in result.stdout
    assert access["hmac_key"] not in result.stdout
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    before = path.read_bytes()
    subprocess.run(command, check=True, capture_output=True)
    assert path.read_bytes() == before
