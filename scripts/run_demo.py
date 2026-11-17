"""Prepare local random credentials and start the loopback demo server."""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile


def prepare(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.stat().st_mode & 0o077:
        raise ValueError("State directory must be private (0700)")
    path = directory / "demo-access.json"
    if path.is_symlink():
        raise ValueError("Credentials file must not be a symlink")
    if not path.exists():
        identities = {secrets.token_urlsafe(32): {"subject_id": name, "tenant_id": tenant, "role": role}
                      for name, tenant, role in [("alice", "A", "viewer"), ("operator", "A", "operator"),
                                                ("reviewer", "A", "security_reviewer"), ("bob", "B", "viewer")]}
        with open(path, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as file:
            json.dump({"identities": identities, "hmac_key": secrets.token_hex(32)}, file, indent=2)
    os.chmod(path, 0o600)
    access = json.loads(path.read_text())
    if not any(identity["role"] == "policy_admin" for identity in access["identities"].values()):
        access["identities"][secrets.token_urlsafe(32)] = {
            "subject_id": "policy-admin", "tenant_id": "control", "role": "policy_admin"}
        fd, temporary = tempfile.mkstemp(dir=directory, prefix=".access-")
        try:
            with os.fdopen(fd, "w") as file:
                json.dump(access, file, indent=2)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return path, access


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=root / "data")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be 1..65535")
    path, access = prepare(args.state_dir.resolve())
    print(f"Credentials: {path}. Keep this file local; never commit it.")
    if args.prepare_only:
        return
    env = os.environ | {"ASTRAGUARD_IDENTITIES": json.dumps(access["identities"]),
                        "ASTRAGUARD_HMAC_KEY": access["hmac_key"],
                        "ASTRAGUARD_DB_PATH": str(args.state_dir.resolve() / "audit.sqlite3")}
    print(f"AstraGuard: http://127.0.0.1:{args.port} ; API: /docs", flush=True)
    subprocess.run([sys.executable, "-m", "uvicorn", "astraguard.main:create_app", "--factory",
                    "--app-dir", str(root / "src"), "--host", "127.0.0.1", "--port", str(args.port), "--workers", "1"],
                   cwd=root, env=env, check=True)


if __name__ == "__main__":
    main()
