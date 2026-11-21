"""Внешний набор (parquet, csv или jsonl) -> JSONL {text, label} для TFIDF_EXTRA.

Примеры (скачать файл на странице датасета HuggingFace, вкладка Files):
  python train/external.py prompt-injections.parquet text label ext_deepset.jsonl
  python train/external.py jailbreak.csv prompt type ext_jackhhao.jsonl --attack jailbreak
  python train/external.py gandalf.parquet text - ext_gandalf.jsonl --all-attack
Без --attack метка читается как число: 1 — атака, 0 — нет. С --attack X атакой считается значение X.
Для parquet нужен pandas и pyarrow: python -m pip install pandas pyarrow
"""
import argparse, json
from pathlib import Path


def rows(path):
    p = Path(path)
    if p.suffix == ".jsonl": return [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
    import pandas as pd  # Только для parquet и csv.
    df = pd.read_parquet(p) if p.suffix == ".parquet" else pd.read_csv(p)
    return df.to_dict("records")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src"); ap.add_argument("text_col"); ap.add_argument("label_col"); ap.add_argument("out")
    ap.add_argument("--attack", help="значение метки, означающее атаку"); ap.add_argument("--all-attack", action="store_true")
    a = ap.parse_args()
    n = pos = 0
    with open(a.out, "w", encoding="utf-8") as f:
        for r in rows(a.src):
            text = str(r.get(a.text_col) or "").strip()
            if not text: continue
            if a.all_attack: label = 1
            elif a.attack is not None: label = int(str(r[a.label_col]) == a.attack)
            else: label = int(float(r[a.label_col]) > 0)
            f.write(json.dumps({"text": text[:4000], "label": label}, ensure_ascii=False) + "\n")
            n += 1; pos += label
    print(f"{a.out}: {n} примеров, атак {pos}")


if __name__ == "__main__":
    main()
