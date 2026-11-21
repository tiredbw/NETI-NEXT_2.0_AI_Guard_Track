"""TF-IDF-страховка для Qwen: символьные n-граммы + логистическая регрессия по категориям.

Делает три вещи:
1. Кросс-валидация по группам похожих примеров (groups.py): оценки вне обучения для каждого примера dev.
2. Подбор порога страховки: при каком p(атака) можно блокировать, если Qwen сказал allow,
   почти без ложных блокировок легитимных запросов вне обучения.
3. Обучение на всём dev и экспорт в JSON для Rust (backend/models/tfidf.json).

Признаки строятся только из входа API: роль, запрос, вложения, история (как features_text в Rust).
Запуск: python backend/train/tfidf.py <dev.jsonl> <groups.json> <out.json> [validation.jsonl]
"""
import json, sys
from pathlib import Path
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer  # Символьные n-граммы.
from sklearn.linear_model import LogisticRegression  # Линейный классификатор.
from sklearn.model_selection import GroupKFold  # Разбиение с учётом групп.


VEC = dict(analyzer="char_wb", ngram_range=(1, 4), lowercase=True, sublinear_tf=True, min_df=2, max_features=40000)  # Настройки векторизации; повторены в Rust.
C_ATTACK = 4.0  # Регуляризация бинарной модели «атака или нет» (подобрано по кросс-валидации по группам).
C_CATEGORY = 8.0  # Регуляризация модели категорий атак.


def features_text(row):
    """Роль, запрос, вложения и последние реплики пользователя. Та же склейка в backend/src/tfidf.rs."""
    ctx = row.get("context", {})
    parts = ["role " + str(ctx.get("user_role", "")), row["user_prompt"]]  # Роль и запрос.
    parts += [a.get("content", "") for a in ctx.get("attachments", [])[:4]]  # До четырёх вложений.
    parts += [t.get("content", "") for t in ctx.get("history", [])[-4:] if t.get("role") == "user"]  # Последние реплики пользователя.
    return "\n".join(parts)


def fit(texts, is_attack, labels):
    """Один словарь, две модели: вероятность атаки и категория среди атак."""
    vec = TfidfVectorizer(**VEC)
    X = vec.fit_transform(texts)
    attack = LogisticRegression(C=C_ATTACK, max_iter=3000, class_weight="balanced").fit(X, is_attack)
    idx = np.where(is_attack)[0]
    category = LogisticRegression(C=C_CATEGORY, max_iter=3000).fit(X[idx], labels[idx])
    return vec, attack, category


def export_model(vec, attack, category, threshold, rows, out_path, trained_on):
    """Пишет модель в JSON для Rust; контрольные примеры Rust сверяет при загрузке."""
    export = {
        "format": "astraguard-tfidf-1",
        "analyzer": VEC["analyzer"], "ngram_range": list(VEC["ngram_range"]), "lowercase": True, "sublinear_tf": True,
        "threshold": round(threshold, 4),
        "vocabulary": {term: int(i) for term, i in vec.vocabulary_.items()}, "idf": [round(float(x), 6) for x in vec.idf_],
        "attack_coef": [round(float(x), 6) for x in attack.coef_[0]], "attack_intercept": round(float(attack.intercept_[0]), 6),
        "categories": list(category.classes_),
        "category_coef": [[round(float(x), 6) for x in row] for row in category.coef_], "category_intercept": [round(float(x), 6) for x in category.intercept_],
        "trained_on": trained_on, "cv": "GroupKFold(5) по группам groups.py, порог: не больше 1 ложной блокировки вне обучения",
    }
    controls = []
    for r in rows[:5]:
        X = vec.transform([features_text(r)])
        controls.append({"text": features_text(r), "p_attack": round(float(attack.predict_proba(X)[0, 1]), 6), "category": str(category.predict(X)[0])})
    export["controls"] = controls
    json.dump(export, open(out_path, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    return controls


def main(dev_path, groups_path, out_path, val_path=None):
    rows = [json.loads(l) for l in open(dev_path, encoding="utf-8")]
    groups = json.load(open(groups_path, encoding="utf-8"))["groups"]
    texts = [features_text(r) for r in rows]
    labels = np.array([r["risk_category"] for r in rows])
    is_attack = np.array([r["expected_decision"] == "block" for r in rows])  # Атака: ожидается block.
    g = np.array([groups[r["id"]] for r in rows])

    oof = np.zeros(len(rows)); oof_cat = np.empty(len(rows), dtype=object)
    for tr, te in GroupKFold(n_splits=5).split(texts, labels, g):  # Похожие примеры не делятся между частями.
        vec, attack, category = fit([texts[i] for i in tr], is_attack[tr], labels[tr])
        X = vec.transform([texts[i] for i in te])
        oof[te] = attack.predict_proba(X)[:, 1]
        oof_cat[te] = category.predict(X)

    neg = np.sort(oof[~is_attack])
    print("Порог | атак поймано вне обучения | ложных блокировок легитимных (из %d)" % (~is_attack).sum())
    for t in (0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9):
        print(f"{t:.2f} | {(oof[is_attack] >= t).sum()}/{is_attack.sum()} | {(oof[~is_attack] >= t).sum()}")
    threshold = float(neg[-2] + 1e-3)  # Не больше одной ложной блокировки вне обучения на dev.
    caught = is_attack & (oof >= threshold)
    cat_ok = (oof_cat[is_attack] == labels[is_attack]).mean()
    print(f"Выбран порог {threshold:.3f}: ловит {caught.sum()}/{is_attack.sum()} атак, ложных {(oof[~is_attack] >= threshold).sum()}; категория атаки верна в {cat_ok:.2f} случаев")
    print("По категориям:", {c: f"{(oof[is_attack & (labels == c)] >= threshold).sum()}/{(is_attack & (labels == c)).sum()}" for c in sorted(set(labels[is_attack]))})
    for r, p in zip(rows, oof):  # Ближайшие к порогу легитимные: что может сломать страховка.
        if not r["expected_decision"] == "block" and p >= threshold - 0.05:
            print(f"  легитимный p={p:.2f} {r['context']['user_role']}: {r['user_prompt'][:100]!r}")

    vec, attack, category = fit(texts, is_attack, labels)  # Финальная модель на всём dev.
    if val_path:  # Свой набор: не участвовал ни в обучении, ни в выборе порога.
        val = [json.loads(l) for l in open(val_path, encoding="utf-8")]
        pv = attack.predict_proba(vec.transform([features_text(r) for r in val]))[:, 1]
        va = np.array([r["expected_decision"] == "block" for r in val])
        print(f"Свой набор ({len(val)}): атак поймано {(pv[va] >= threshold).sum()}/{va.sum()}, ложных {(pv[~va] >= threshold).sum()}/{(~va).sum()}")

    controls = export_model(vec, attack, category, threshold, rows, out_path, "public dev.jsonl (500 примеров)")
    oof_path = str(Path(out_path).resolve().parents[2] / "eval" / "tfidf_oof_dev.json")  # Оценки вне обучения для честной симуляции страховки на прогонах Qwen.
    json.dump({r["id"]: {"p_attack": round(float(p), 6), "category": str(c)} for r, p, c in zip(rows, oof, oof_cat)}, open(oof_path, "w", encoding="utf-8"), ensure_ascii=False)
    print("контроль:", [(c["p_attack"], c["category"]) for c in controls], "; оценки вне обучения:", oof_path)


if __name__ == "__main__":
    main(*sys.argv[1:])
