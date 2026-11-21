"""Доля открытого текста (поле plain), которую normalize.rs показал модели. Без Qwen, за секунды.
Запуск: cargo run --release --example decode_scan -- eval/own_fresh.v3.probe.jsonl > /tmp/d.jsonl
        python eval/decode_coverage.py eval/own_fresh.v3.probe.jsonl /tmp/d.jsonl
"""
import json, re, sys, collections  # Стандартная библиотека.
rows = {json.loads(l)["id"]: json.loads(l) for l in open(sys.argv[1], encoding="utf-8")}  # Набор.
seen = {json.loads(l)["id"]: json.loads(l)["text"] for l in open(sys.argv[2], encoding="utf-8")}  # Что увидела модель.
words = lambda s: set(w for w in re.findall(r"\w+", s.lower()) if len(w) >= 4)  # Значимые слова.
stat = collections.defaultdict(list)  # Покрытие по семействам.
for i, r in rows.items():
    if "plain" not in r: continue  # Только обфусцированные.
    p = words(r["plain"]); s = words(seen[i])  # Слова открытого текста и увиденного.
    cov = len(p & s) / max(1, len(p))  # Доля найденных слов.
    stat[r["tags"][-1]].append(cov)
    if cov < 0.8 and len(sys.argv) > 3: print(f"{cov:.2f} {i} {r['tags'][-1]} | {seen[i][:120]!r}")
ok = sum(c >= 0.8 for v in stat.values() for c in v); n = sum(len(v) for v in stat.values())  # Итог.
for k, v in sorted(stat.items(), key=lambda kv: sum(kv[1]) / len(kv[1])): print(f"{k:30s} {sum(v)/len(v):.2f} ({len(v)})")
print(f"раскодировано (≥80% слов): {ok}/{n}")
