import importlib.util
from pathlib import Path

from astraguard.evaluation import EvalCase, percentiles, summarize


def row(case_id, label, expected, decision, critical=False):
    return {"id": case_id, "label": label, "critical": critical, "expected_decision": expected,
            "decision": decision, "elapsed_ms": 10, "request_ms": [8], "detector_failed": False}


def test_frozen_corpus_counts_and_fixtures():
    cases = [EvalCase.model_validate_json(line) for line in Path("eval/cases.v1.jsonl").read_text().splitlines()]
    assert len(cases) == len({c.id for c in cases}) == 100
    assert sum(c.label == "A" for c in cases) == 45
    assert sum(c.critical for c in cases) == 36
    assert sum(c.split == "dev" for c in cases) == 60
    assert sum(c.mode == "tool_boundary" for c in cases) == 9
    mapping = {c.id: c for c in cases}
    assert mapping["Q05-03"].tool_intent.resource_id == "B1"
    assert len(mapping["Q08-10"].session_turns) == 5
    assert "\u200b" in mapping["Q09-03"].text


def test_metrics_known_confusion():
    rows = [row("tp", "A", "BLOCK", "BLOCK", True), row("fn", "A", "BLOCK", "ALLOW", True),
            row("fp", "B", "ALLOW", "REVIEW"), row("tn", "B", "ALLOW", "ALLOW")]
    report = summarize(rows)
    metrics = report["containment"]
    assert [metrics[k] for k in ("tp", "fp", "fn", "tn")] == [1, 1, 1, 1]
    assert metrics["precision"] == metrics["recall"] == metrics["f1"] == .5
    assert metrics["fpr"] == metrics["fnr"] == .5
    assert report["strict_block"]["fp"] == 0
    assert report["critical"]["containment_recall"] == .5
    assert report["critical"]["allowed_ids"] == ["fn"]


def test_all_review_is_not_good_classifier():
    report = summarize([row("attack", "A", "BLOCK", "REVIEW", True), row("benign", "B", "ALLOW", "REVIEW")])
    assert report["containment"]["recall"] == 1
    assert report["containment"]["precision"] == .5
    assert report["benign_review_rate"] == 1
    assert report["strict_block"]["recall"] == 0
    assert report["exact_decision_accuracy"] == 0


def test_technical_errors_are_not_dropped():
    report = summarize([row("attack", "A", "BLOCK", None, True), row("benign", "B", "ALLOW", None)])
    assert report["n"] == 2
    assert report["containment"]["fn"] == 1
    assert report["containment"]["fp"] == 1
    assert report["critical"]["unresolved_ids"] == ["attack"]
    assert report["confusion_matrix"]["BLOCK"]["ERROR"] == 1


def test_empty_and_nearest_rank():
    assert summarize([])["containment"]["precision"] is None
    assert summarize([])["critical"]["containment_recall"] is None
    assert percentiles(list(range(1, 101))) == {"n": 100, "p50": 50, "p95": 95}


def load_runner():
    spec = importlib.util.spec_from_file_location("eval_runner", "scripts/evaluate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


from test_core import setup
from astraguard.schemas import Principal


def test_runner_uses_actual_gateway_decision_not_expected_label(setup):
    client, app, _, _ = setup
    case = EvalCase.model_validate_json(Path("eval/cases.v1.jsonl").read_text().splitlines()[0])
    case.expected_decision = "ALLOW"
    result = load_runner().run_case(client, app, case, Principal(subject_id="alice", tenant_id="A", role="viewer"), "a" * 32, 0)
    assert result["decision"] == "BLOCK"
    assert result["technical_error"] is None
    assert result["decision"] != result["expected_decision"]


def test_runner_typed_policy_and_read_paths(setup):
    client, app, detector, _ = setup
    runner = load_runner()
    cases = {c.id: c for c in [EvalCase.model_validate_json(line) for line in Path("eval/cases.v1.jsonl").read_text().splitlines()]}
    principal = Principal(subject_id="alice", tenant_id="A", role="viewer")
    denied = runner.run_case(client, app, cases["Q05-01"], principal, "a" * 32, 0)
    assert denied["decision"] == "BLOCK" and detector.calls == 0
    own_read = runner.run_case(client, app, cases["Q05-06"], principal, "a" * 32, 0)
    assert own_read["decision"] == "ALLOW" and app.state.agent.invocations == 1


def test_runner_keeps_setup_errors(setup):
    client, app, _, _ = setup
    case = EvalCase.model_validate_json(Path("eval/cases.v1.jsonl").read_text().splitlines()[0])
    result = load_runner().run_case(client, app, case, Principal(subject_id="alice", tenant_id="A", role="viewer"), "wrong-credential", 0)
    assert result["decision"] is None
    assert result["technical_error"] == "SESSION_SETUP_FAILED"


def test_evaluator_can_access_startup_detector_state(setup):
    _, app, detector, _ = setup
    assert app.state.detector is detector
    startup = app.state.detector.health() if hasattr(app.state.detector, "health") else None
    assert startup is None


def test_runner_counts_late_content_block_instead_of_initial_allow(setup):
    client, app, _, _ = setup
    case = EvalCase.model_validate_json(Path("eval/cases.v1.jsonl").read_text().splitlines()[0])
    case = case.model_copy(update={"text": "/read A3", "session_turns": [], "mode": "gateway", "tool_intent": None})
    result = load_runner().run_case(client, app, case,
        Principal(subject_id="alice", tenant_id="A", role="viewer"), "a" * 32, 0)
    assert result["technical_error"] is None
    assert result["decision"] == "BLOCK"
    assert result["reason_codes"] == ["ACTIVE_OVERRIDE"]
    assert app.state.agent.invocations == 1
