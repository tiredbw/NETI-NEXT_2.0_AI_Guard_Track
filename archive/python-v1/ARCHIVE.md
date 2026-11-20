# Архив: первая версия на Python (FastAPI)

Здесь лежит первая версия AstraGuard: FastAPI, SQLite, свой контракт `/v1/checks` с tenant и Bearer-токенами,
собственный корпус из 100 сценариев. Она **не используется** в решении для кейса «ИИ-сторож» v2.0
и не запускается из корня репозитория.

Действующее решение: сервис на Rust в [`backend/`](../../backend/README.md) и интерфейс в [`frontend/`](../../frontend/README.md).

Что отсюда переиспользовано:
- корпуса `cases.v1` и `cases.bypass.v1` превращены в свой набор проверки `eval/own_validation.v1.jsonl`,
  `cases.holdout.v2` — в отложенный `eval/own_holdout.v2.jsonl` (см. `backend/train/own_validation.py`);
- идеи нормализации и правил перенесены в `backend/src/normalize.rs` и `backend/src/rules.rs`.

Пути внутри архивных документов указывают на старое расположение (`src/`, `scripts/`, `tests/` в корне).
