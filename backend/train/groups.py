"""Разбиение dev на группы похожих примеров (TRAINING.md, п. 2).

Близкие перефразировки и дубликаты попадают в одну группу, чтобы при кросс-валидации
они не оказались одновременно в обучении и в проверке. Группы строятся по сходству
нормализованного текста: косинус TF-IDF по словам >= порога, затем связные компоненты.
Метки, id, tags, difficulty и lang в сходство не входят.

Запуск: python backend/train/groups.py <dev.jsonl> <out.json>
"""
import json, re, sys
from sklearn.feature_extraction.text import TfidfVectorizer  # Векторизация слов.
from sklearn.metrics.pairwise import cosine_similarity  # Попарное сходство.

THRESHOLD = 0.55  # Порог сходства: выше — считаем перефразировкой одного шаблона.
FILLER = re.compile(r"\b(пожалуйста|please|срочно|быстро|плиз|спасибо|thanks)\b")  # Вежливые хвосты генератора.


def features_text(row):
    """Текст, по которому ищем похожие: запрос, вложения и история, как видит детектор."""
    ctx = row.get("context", {})  # Контекст запроса.
    parts = [row["user_prompt"]]  # Текущий запрос.
    parts += [a.get("content", "") for a in ctx.get("attachments", [])]  # Вложения.
    parts += [t.get("content", "") for t in ctx.get("history", [])]  # История.
    return "\n".join(parts)


def canon(text):
    """Нормализация для сходства: регистр, числа, имена ресурсов и вежливые слова не важны."""
    t = text.lower()  # Регистр.
    t = FILLER.sub(" ", t)  # Вежливые слова.
    t = re.sub(r"\d+", "0", t)  # Числа и IP одинаковы.
    t = re.sub(r"[a-z0-9]+(-[a-z0-9]+)+", "res", t)  # Имена сервисов вида billing-api-prod.
    return re.sub(r"\s+", " ", t).strip()  # Пробелы.


def build_groups(rows):
    """Возвращает id -> номер группы."""
    texts = [canon(features_text(r)) for r in rows]  # Нормализованные тексты.
    sim = cosine_similarity(TfidfVectorizer(analyzer="word", token_pattern=r"(?u)\b\w+\b").fit_transform(texts))  # Сходство всех пар.
    parent = list(range(len(rows)))  # Система непересекающихся множеств.

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]  # Сжатие пути.
            i = parent[i]
        return i

    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            if sim[i, j] >= THRESHOLD:
                parent[find(i)] = find(j)  # Объединяем похожие.
    roots = {}  # Корень -> номер группы.
    return {r["id"]: roots.setdefault(find(i), len(roots)) for i, r in enumerate(rows)}


if __name__ == "__main__":
    rows = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8")]  # dev.jsonl.
    groups = build_groups(rows)  # Группы.
    sizes = {}
    for g in groups.values():
        sizes[g] = sizes.get(g, 0) + 1
    json.dump({"threshold": THRESHOLD, "groups": groups}, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=0)
    big = sorted(sizes.values(), reverse=True)[:10]  # Крупнейшие группы.
    print(f"примеров {len(rows)}, групп {len(sizes)}, одиночек {sum(1 for s in sizes.values() if s == 1)}, крупнейшие {big}")
