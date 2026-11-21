"""Бенчмарк порядка слоёв: Qwen без TF-IDF, подсказка TF-IDF в промпте, быстрый фильтр TF-IDF до Qwen, страховка после.

Честность: TF-IDF для бенчмарка обучается только на 80% групп dev, а проверка идёт на оставшихся 20% групп
(примеры, которых классификатор не видел, и без их перефразировок). Иначе фильтр и подсказка выглядели бы
лучше, чем будут на скрытом тесте.

Для каждой конфигурации скрипт запускает собранный сервис с нужными переменными окружения, ждёт /health,
прогоняет отложенные примеры через официальные call_endpoint и score из evaluate.py и печатает таблицу.

Запуск (из каталога backend, после cargo build --release, Ollama запущена):
  python train/bench_tfidf.py <evaluate.py> <dev.jsonl>
Результаты: bench/<конфигурация>.report.json и .pred.jsonl, итог в bench/summary.md.
"""
import importlib.util, json, os, subprocess, sys, time, urllib.request
from pathlib import Path

import numpy as np
from sklearn.model_selection import GroupShuffleSplit  # Разбиение по группам.

sys.path.insert(0, str(Path(__file__).parent))
from tfidf import features_text, fit, export_model  # Те же признаки и экспорт, что у основной модели.

PORT = 8011  # Отдельный порт, чтобы не мешать запущенному демо.
CONFIGS = [  # Имя -> переменные окружения сервиса.
    ("qwen", {}),
    ("qwen+hint", {"TFIDF_HINT": "1"}),
    ("prefilter0.9", {"TFIDF_PREFILTER": "0.9"}),
    ("prefilter0.9+hint", {"TFIDF_PREFILTER": "0.9", "TFIDF_HINT": "1"}),
    ("qwen+backstop", {"TFIDF_BACKSTOP": "1"}),
]


def load_evaluate(path):
    spec = importlib.util.spec_from_file_location("evaluate", path)  # Официальный оценщик организаторов.
    ev = importlib.util.module_from_spec(spec); spec.loader.exec_module(ev)
    return ev


def split_model(rows, groups, out_model):
    """TF-IDF на 80% групп; возвращает отложенные 20% примеров."""
    g = np.array([groups[r["id"]] for r in rows])
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=0).split(rows, groups=g))  # Фиксированное разбиение.
    train = [rows[i] for i in tr]
    vec, attack, category = fit([features_text(r) for r in train], np.array([r["expected_decision"] == "block" for r in train]), np.array([r["risk_category"] for r in train]))
    export_model(vec, attack, category, 0.747, train, out_model, f"dev, 80% групп ({len(train)} примеров), для бенчмарка")
    return [rows[i] for i in te]


def wait_ready(timeout=180):
    """Ждёт /health: первый запуск прогревает модель."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=2) as r:
                if r.status == 200: return True
        except Exception:
            time.sleep(1)
    return False


def main(evaluate_path, dev_path):
    ev = load_evaluate(evaluate_path)
    root = Path(__file__).resolve().parents[1]  # Каталог backend.
    rows = ev.load_jsonl(dev_path)
    groups = json.load(open(root.parent / "eval" / "dev_groups.json", encoding="utf-8"))["groups"]
    out = root / "bench"; out.mkdir(exist_ok=True)
    model = out / "tfidf.bench.json"
    held = split_model(rows, groups, model)
    print(f"Отложено {len(held)} примеров из {len(rows)} (TF-IDF их не видел)")
    exe = root / "target" / "release" / ("astraguard.exe" if os.name == "nt" else "astraguard")
    if not exe.exists(): sys.exit("Сначала: cargo build --release")
    lines = ["| Конфигурация | Score | Блокировка high/critical | Ложные блокировки трудных легитимных | p95, мс | Вызовов Qwen пропущено |", "|---|---|---|---|---|---|"]
    for name, extra in CONFIGS:
        env = dict(os.environ, BIND=f"127.0.0.1:{PORT}", TFIDF_MODEL=str(model), JOURNAL_PATH="", **extra)
        proc = subprocess.Popen([str(exe)], cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # Сервис с этой конфигурацией.
        try:
            if not wait_ready(): print(f"{name}: сервис не поднялся"); continue
            preds = [ev.call_endpoint(f"http://127.0.0.1:{PORT}/v1/check", r) for r in held]  # Последовательно, как у организаторов.
        finally:
            proc.terminate(); proc.wait(timeout=10)
        rep = ev.score(held, preds)
        skipped = sum(1 for p in preds if any(s.get("label") == "skipped" for s in p.get("signals", [])))
        hc = rep["strict_block_recall_high_critical"]  # Порог приза 0,85.
        (out / f"{name}.report.json").write_text(json.dumps(rep, ensure_ascii=False, indent=2), encoding="utf-8")
        (out / f"{name}.pred.jsonl").write_text("".join(json.dumps(p, ensure_ascii=False) + "\n" for p in preds), encoding="utf-8")
        line = f"| {name} | {rep['score']:.4f} | {hc:.3f} | {rep['hard_negative_block_rate']:.3f} | {rep['latency_p95_ms']:.0f} | {skipped}/{len(held)} |"
        print(line); lines.append(line)
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Итог:", out / "summary.md")


if __name__ == "__main__":
    main(*sys.argv[1:])
