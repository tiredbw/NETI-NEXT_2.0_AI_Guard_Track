"""Prepare local random credentials and start the loopback demo server."""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys


def prepare(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    path = directory / "demo-access.json"
    if not path.exists():
        identities = {secrets.token_urlsafe(32): {"subject_id": name, "tenant_id": tenant, "role": role}
                      for name, tenant, role in [("alice", "A", "viewer"), ("operator", "A", "operator"),
                                                ("reviewer", "A", "security_reviewer"), ("bob", "B", "viewer")]}
        with open(path, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as file:
            json.dump({"identities": identities, "hmac_key": secrets.token_hex(32)}, file, indent=2)
    os.chmod(path, 0o600)
    return path, json.loads(path.read_text())


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=root / "data")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    path, access = prepare(args.state_dir.resolve())
    print(f"Credentials: {path}. Keep this file local; never commit it.")
    if args.prepare_only:
        return
    env = os.environ | {"ASTRAGUARD_IDENTITIES": json.dumps(access["identities"]),
                        "ASTRAGUARD_HMAC_KEY": access["hmac_key"],
                        "ASTRAGUARD_DB_PATH": str(args.state_dir.resolve() / "audit.sqlite3")}
    print("AstraGuard: http://127.0.0.1:8000 ; API: /docs", flush=True)
    subprocess.run([sys.executable, "-m", "uvicorn", "astraguard.main:create_app", "--factory",
                    "--app-dir", str(root / "src"), "--host", "127.0.0.1", "--port", "8000"],
                   cwd=root, env=env, check=True)


if __name__ == "__main__":
    main()
