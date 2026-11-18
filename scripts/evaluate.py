"""Opt-in evaluation against real local Ollama, isolated from the demo's data."""

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import httpx
from fastapi.testclient import TestClient

from astraguard.demo import ToolIntent
from astraguard.evaluation import EvalCase, summarize
from astraguard.main import create_app
from astraguard.schemas import Principal


def source_hash():
    digest = hashlib.sha256()
    for path in sorted([*ROOT.glob("src/**/*.py"), *ROOT.glob("policies/*.yaml")]):
        digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def model_metadata():
    with httpx.Client(trust_env=False, timeout=5) as client:
        version = client.get("http://127.0.0.1:11434/api/version")
        version.raise_for_status()
        tags = client.get("http://127.0.0.1:11434/api/tags")
        tags.raise_for_status()
    model = next(m for m in tags.json()["models"] if m["name"] == "qwen3.5:4b")
    return {"server_version": version.json()["version"], "model": model["name"],
            "digest": model["digest"], "details": model.get("details", {})}


def post(client, path, body, durations):
    started = time.perf_counter()
    response = client.post(path, json=body)
    durations.append((time.perf_counter() - started) * 1000)
    if response.status_code not in (200, 201):
        raise RuntimeError(f"HTTP_{response.status_code}:{response.json().get('error', {}).get('code', 'unknown')}")
    return response.json()


def run_case(client, app, case, principal, token, repeat):
    started = time.perf_counter()
    record = {"id": case.id, "repeat": repeat, "category": case.category, "split": case.split,
              "mode": case.mode, "label": case.label, "critical": case.critical,
              "expected_decision": case.expected_decision, "decision": None, "reason_codes": [],
              "request_ms": [], "detector_failed": False, "technical_error": None, "stop_turn": None}
    observed = []
    client.headers["Authorization"] = "Bearer " + token
    try:
        session = client.post("/v1/sessions")
        if session.status_code != 201:
            raise RuntimeError("SESSION_SETUP_FAILED")
        base = {"session_id": session.json()["session_id"], "policy_id": "strict-demo-v1"}
        if case.mode == "tool_boundary":
            intent = ToolIntent(**case.tool_intent.model_dump())
            gate = app.state.agent.preflight(principal, intent)
            if gate[0] != "BLOCK" or case.id == "Q05-03":
                parent = post(client, "/v1/checks", base | {"text": case.text}, record["request_ms"])
                observed.append(parent)
                if parent["decision"] != "ALLOW":
                    if gate[0] == "BLOCK":
                        raise RuntimeError("FIXTURE_REQUIRES_ALLOWED_PARENT")
                    final = parent
                elif gate[0] == "ALLOW":
                    execution = app.state.agent.invoke(principal, intent, parent)
                    final = execution["tool_check"]
                else:
                    final = {"decision": gate[0], "reason_codes": [gate[1]]}
                if gate[0] == "BLOCK":
                    final = {"decision": gate[0], "reason_codes": [gate[1]]}
            else:
                final = {"decision": gate[0], "reason_codes": [gate[1]]}
        else:
            for index, text in enumerate(case.session_turns or [case.text]):
                response = post(client, "/v1/agent/turns", base | {"text": text}, record["request_ms"])
                final = response["check"]
                observed.append(final)
                record["stop_turn"] = index
                if final["decision"] != "ALLOW":
                    break
        record["decision"] = final["decision"]
        record["reason_codes"] = final.get("reason_codes", [])
        record["expected_reasons_present"] = set(case.expected_reason_codes) <= set(record["reason_codes"])
    except Exception as error:
        # Persist only error types/codes; never echo request bodies or credentials.
        record["technical_error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
    record["detector_failed"] = any(any(code.startswith("DETECTOR_") for code in c.get("reason_codes", [])) for c in observed)
    record["detector_statuses"] = [c.get("detector", {}).get("status") for c in observed]
    record["detector_digests"] = [c.get("detector", {}).get("digest") for c in observed]
    record["elapsed_ms"] = (time.perf_counter() - started) * 1000
    return record


def group_reports(rows):
    return {"mixed": summarize(rows),
            "by_split": {split: summarize([r for r in rows if r["split"] == split]) for split in ("dev", "holdout")},
            "by_mode": {mode: summarize([r for r in rows if r["mode"] == mode]) for mode in ("gateway", "tool_boundary")},
            "by_category": {category: summarize([r for r in rows if r["category"] == category]) for category in sorted({r["category"] for r in rows})}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "eval/cases.v1.jsonl")
    parser.add_argument("--split", choices=["dev", "holdout", "all"], default="dev")
    parser.add_argument("--repeat", type=int, choices=[1, 2, 3], default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.chdir(ROOT)
    cases = [EvalCase.model_validate_json(line) for line in args.dataset.read_text().splitlines() if line]
    if len({c.id for c in cases}) != len(cases):
        raise ValueError("Duplicate case IDs")
    cases = [c for c in cases if args.split == "all" or c.split == args.split]
    if args.limit is not None:
        if args.limit < 1:
            parser.error("limit must be positive")
        cases = cases[:args.limit]
    if not cases:
        parser.error("empty selection")
    output = args.output or ROOT / "data/eval" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    metadata = {"started_at": started, "code_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                "git_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], text=True).strip()),
                "source_hash": source_hash(), "dataset_sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
                "python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
                "model": model_metadata(), "selected_cases": len(cases), "split": args.split, "repeats": args.repeat,
                "measurement": "sequential in-process TestClient API + real local Ollama; tool_boundary separate",
                "limitations": ["Synthetic, pre-exposed labels; holdout name does not prove independent validation.",
                                "Mixed aggregate includes tool ACL fixtures; see gateway-only metrics.",
                                "No paid API, no fake detector, no response repair or automatic retry."]}
    (output / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2))
    identities, principals, tokens = {}, {}, {}
    for case in cases:
        token = secrets.token_urlsafe(32)
        principal = Principal(subject_id="eval-" + case.id, tenant_id="A", role=case.principal_fixture)
        tokens[case.id], principals[case.id], identities[token] = token, principal, principal
    warm_token = secrets.token_urlsafe(32)
    identities[warm_token] = Principal(subject_id="eval-warm", tenant_id="A", role="viewer")
    app = create_app(credentials=identities, db_path=output / "audit.sqlite3", hmac_key=secrets.token_bytes(32))
    rows = []
    with TestClient(app) as client, (output / "cases.jsonl").open("w") as stream:
        metadata["startup_model"] = app.state.detector.health() if hasattr(app.state.detector, "health") else None
        metadata["startup_detector"] = metadata["startup_model"]["status"] if metadata["startup_model"] else app.state.detector_status
        client.headers["Authorization"] = "Bearer " + warm_token
        session = client.post("/v1/sessions").json()["session_id"]
        warm_durations = []
        warm = post(client, "/v1/checks", {"session_id": session, "policy_id": "strict-demo-v1", "text": "Добрый день"}, warm_durations)
        metadata["warmup"] = {"decision": warm["decision"], "elapsed_ms": warm_durations[0], "excluded_from_quality": True}
        for repeat in range(args.repeat):
            for index, case in enumerate(cases):
                row = run_case(client, app, case, principals[case.id], tokens[case.id], repeat)
                rows.append(row)
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
                stream.flush()
                print(f"{repeat + 1}:{index + 1}/{len(cases)} {case.id} {row['decision'] or 'ERROR'} expected={case.expected_decision}", flush=True)
    metadata["finished_at"] = datetime.now(timezone.utc).isoformat()
    metadata["source_unchanged"] = metadata["source_hash"] == source_hash()
    metadata["model_unchanged"] = metadata["model"] == model_metadata()
    (output / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2))
    primary = [r for r in rows if r["repeat"] == 0]
    by_id = defaultdict(list)
    for row in rows:
        by_id[row["id"]].append(row["decision"])
    report = {"metadata": metadata, "primary_first_pass": group_reports(primary),
              "per_pass": {str(i): group_reports([r for r in rows if r["repeat"] == i]) for i in range(args.repeat)},
              "decision_instability_ids": [key for key, values in by_id.items() if len(set(values)) > 1] if args.repeat > 1 else None}
    (output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"REPORT {output / 'report.json'}", flush=True)


if __name__ == "__main__":
    main()
