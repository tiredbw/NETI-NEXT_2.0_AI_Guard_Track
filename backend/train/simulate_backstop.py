"""Честная оценка TF-IDF-страховки на прогоне Qwen без повторного прогона.

Берёт предсказания сервиса на dev (evaluate.py --save-predictions, страховка выключена)
и оценки классификатора вне обучения (tfidf.oof_dev.json: каждый пример оценён моделью,
которая его не видела, с разбиением по группам). Для каждого порога меняет allow на block там,
где классификатор уверен, и считает балл официальной функцией score из evaluate.py.

Запуск:
  python backend/train/simulate_backstop.py <evaluate.py> <dev.jsonl> <predictions.jsonl> eval/tfidf_oof_dev.json
"""
import copy, importlib.util, json, sys

BLOCKABLE = {"prompt_injection", "jailbreak", "indirect_injection", "system_prompt_extraction", "system_prompt_override",
             "privilege_escalation", "data_exfiltration", "harmful_content", "fraud_social_engineering", "abuse",
             "unauthorized_data_access", "tool_abuse"}  # always_block + context_dependent исходной политики.


def main(evaluate_path, dev_path, pred_path, oof_path):
    spec = importlib.util.spec_from_file_location("evaluate", evaluate_path)  # Официальный оценщик.
    ev = importlib.util.module_from_spec(spec); spec.loader.exec_module(ev)
    rows = ev.load_jsonl(dev_path); preds = ev.load_jsonl(pred_path)
    oof = json.load(open(oof_path, encoding="utf-8"))
    base = ev.score(rows, preds)
    print(f"без страховки: score {base['score']:.4f}")
    truth = {r["id"]: r for r in rows}
    for t in (0.70, 0.75, 0.80, 0.85, 0.90):
        changed = copy.deepcopy(preds); fixed = broke = 0
        for p in changed:
            o = oof.get(p["id"])
            if o and p.get("decision") == "allow" and o["p_attack"] >= t and o["category"] in BLOCKABLE:
                p["decision"] = "block"; p["risk_category"] = o["category"]; p["risk_level"] = "high"
                if truth[p["id"]]["expected_decision"] == "block": fixed += 1
                else: broke += 1
        s = ev.score(rows, changed)
        print(f"порог {t:.2f}: score {s['score']:.4f} ({s['score'] - base['score']:+.4f}), исправлено пропусков {fixed}, новых ложных блокировок {broke}")


if __name__ == "__main__":
    main(*sys.argv[1:])
