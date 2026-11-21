"""Размножение обучающих примеров вариациями, которые не меняют разметку.

Только для обучения TF-IDF. Вариации делаются внутри обучающей части разбиения, поэтому
перефразировки одного примера не попадают в проверку (группы groups.py сохраняются).

Что меняем:
- имена сервисов: на другие того же типа окружения (prod -> prod, nonprod -> nonprod, без окружения -> без окружения),
  потому что права и разметка зависят от окружения;
- вежливые приставки и хвосты («Привет!», «Срочно:», «пожалуйста», «ASAP»), регистр первой буквы;
- у атак дополнительно обфускацию: leetspeak, разрядку, латинские двойники кириллицы и наоборот.
  Легитимные запросы не обфусцируем, чтобы классификатор не решил, что «странный текст = атака».
"""
import random, re

PROD = ["payments-prod-02", "auth-svc-prod", "prod-db-01", "k8s-prod-master", "billing-api-prod", "orders-prod-01", "prod-cache-03", "crm-prod-db"]  # Маски prod-*, *-prod, *-prod-*.
NONPROD = ["dev-k8s-node1", "dev-db-02", "test-runner-05", "stage-api-03", "dev-api-07", "stage-db-01", "test-queue-02"]  # dev-*, stage-*, test-*.
PLAIN = ["search-indexer", "crm-backend", "report-generator", "auth-service", "notification-worker", "payments-api", "billing-worker", "user-profile"]  # Без окружения в имени.
PREFIX = ["", "", "Здравствуйте. ", "Слушай, ", "Срочно: ", "Добрый день! ", "Hey, ", "Вопрос: ", "Привет! ", "Urgent: ", "Hello, ", "Hi! ", "Quick question: "]  # Как в dev.
SUFFIX = ["", "", " пожалуйста", " Спасибо.", " Очень нужно.", " Заранее спасибо!", " Thanks.", " ASAP.", " Please.", " thx"]  # Как в dev.
LEET = {"а": "@", "е": "3", "о": "0", "a": "4", "e": "3", "o": "0", "i": "1", "s": "5", "t": "7"}  # Замены leetspeak.
HOMO = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х"}  # Двойники.
NAME = re.compile(r"\b[a-z0-9]+(?:-[a-z0-9]+)+\b")  # Имена ресурсов вида billing-api-prod.


def kind(name):
    """Тип окружения имени ресурса."""
    if name.startswith("prod-") or name.endswith("-prod") or "-prod-" in name: return PROD
    if name.startswith(("dev-", "stage-", "test-")): return NONPROD
    return PLAIN if name in PLAIN or name.count("-") == 1 else None  # Остальные (флаги, номера задач) не трогаем.


def swap_names(text, rnd):
    def repl(m):
        pool = kind(m.group(0))
        return rnd.choice(pool) if pool else m.group(0)  # Имя того же типа окружения.
    return NAME.sub(repl, text)


def obfuscate(text, rnd):
    """Одна из обфускаций, которые встречаются в атаках dev."""
    how = rnd.choice(["leet", "space", "homo"])
    if how == "leet": return "".join(LEET.get(ch, ch) if rnd.random() < 0.6 else ch for ch in text)
    if how == "space": return " ".join(text) if len(text) < 200 else text
    return "".join(HOMO.get(ch, ch) if rnd.random() < 0.3 else ch for ch in text)


def variants(row, n, seed=0):
    """n вариантов примера с той же разметкой; поля вне user_prompt не меняются."""
    rnd = random.Random(f"{row['id']}:{seed}")  # Детерминированно для воспроизводимости.
    attack = row["expected_decision"] == "block"
    out = []
    for k in range(n):
        p = swap_names(row["user_prompt"], rnd)
        p = p[0].lower() + p[1:] if p and rnd.random() < 0.2 else p  # Регистр первой буквы.
        p = rnd.choice(PREFIX) + p + rnd.choice(SUFFIX)
        if attack and rnd.random() < 0.3: p = obfuscate(p, rnd)  # Обфускация только у атак.
        out.append(dict(row, id=f"{row['id']}~{k}", user_prompt=p))
    return out


def augment(rows, n):
    """Исходные примеры плюс по n вариантов каждого."""
    return [x for r in rows for x in [r] + (variants(r, n) if n > 0 else [])]
