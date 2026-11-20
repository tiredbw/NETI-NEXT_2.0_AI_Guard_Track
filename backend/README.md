# AstraGuard (Rust/Axum)

Сторож для `it_ops_agent`: `POST /v1/check` по контракту кейса «ИИ-сторож» v2.0.
Формат ответа совпадает с `CheckResult` из `docs/FRONTEND_PROMPT.md`. Каждый запрос проходит через Qwen (Ollama) и детерминированную YAML-политику.

## Запуск

```bash
ollama pull qwen3.5:4b
cd backend
cargo run --release
```

Переменные окружения:

| Переменная | По умолчанию | Что делает |
|---|---|---|
| `BIND` | `0.0.0.0:8000` | Адрес сервера |
| `POLICY_PATH` | `../policies/security_policy.yaml` | Файл политики |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Адрес Ollama |
| `OLLAMA_MODEL` | `qwen3.5:4b` | Модель |
| `DETECTOR_TIMEOUT_MS` | `8000` | Таймаут модели; при превышении `block` |
| `GUARD_MODE` | `gpu` | Режим в `/health` |
| `ADMIN_TOKEN` | не задан | Токен для `PUT /v1/policy` и `/v1/policy/reload` |
| `FRONTEND_DIR` | `../frontend` | Каталог интерфейса; сервис раздаёт его на `/`. Нет `index.html` — только API |
| `JOURNAL_PATH` | `../data/journal.jsonl` | Журнал проверок в JSONL (только маскированный текст); пусто — только память |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Origin отдельного dev-сервера фронта; для демо с того же адреса не нужен |

После запуска интерфейс открывается на [http://127.0.0.1:8000](http://127.0.0.1:8000): фронт и API на одном origin.

## Маршруты

Контракт описан в [docs/FRONTEND_PROMPT.md](../docs/FRONTEND_PROMPT.md). Ошибки: `{"error": "<code>", "detail": "<текст>"}`.

| Маршрут | Что делает |
|---|---|
| `POST /v1/check` | Только оценка: решение, риск, категория, объяснение. Пишется в журнал |
| `POST /v1/demo/submit` | Проверка и путь до заглушки агента: allow → квитанция, block → не передано, confirm → ожидание подтверждения (10 мин) |
| `POST /v1/demo/confirm` | Одноразовое подтверждение автором неизменного запроса (`request_hash`): 403 чужой, 409 изменён/использован, 410 истёк |
| `GET /v1/agent/inbox` | Что реально получила заглушка агента |
| `GET /v1/journal` | Журнал: `since`, `until`, `decision`, `category`, `role`, `limit`, `offset` |
| `GET /v1/policy`, `GET /v1/policy/history` | Действующая политика с версией, автором и временем; история версий |
| `POST /v1/policy/validate` | Проверка YAML без применения |
| `PUT /v1/policy` | Применение с `X-Admin-Token`: 401 без токена, 403 неверный, 422 ошибки валидации |
| `POST /v1/sessions`, `GET /v1/sessions?user_id=` | Создать сессию; список только своих |
| `GET` / `DELETE /v1/sessions/{id}?user_id=` | Сессия с историей; удаление |
| `POST /v1/sessions/{id}/messages` | Реплика: история сессии уходит в `context.history`, ответ с `history_effect` |
| `GET /health` | Готовность, модель, версия политики |

Сессии: до 20 реплик пользователя и 60 минут хранения; пользователь видит только свои. Журнал, входящие агента, подтверждения и сессии хранятся в памяти процесса (журнал дополнительно в JSONL) и сбрасываются при перезапуске.

## Перезагрузка политики

- Отредактируйте `policies/security_policy.yaml` в корне репозитория: сервис перечитывает файл раз в секунду. Невалидный файл не применяется, работает прежняя версия.
- Или `curl -X POST -H "X-Admin-Token: $ADMIN_TOKEN" localhost:8000/v1/policy/reload`.
- Версия (`version` из YAML + `#` + 8 символов sha256) возвращается в каждом ответе `/v1/check` в поле `policy_version`.

## Как принимается решение

1. Окружение по маскам из YAML и словам prod/dev/stage/test; нет признаков → считаем prod и пишем это в объяснении.
2. Qwen (`think: false`, JSON-схема, `keep_alive: -1`) возвращает категорию, риск, инструмент, запрещённое действие и работу с секретами.
3. Порядок: сбой модели → block; `forbidden_actions` → block; `always_block` → block; значения секретов → block; затем права роль → инструмент → окружение (deny/confirm/allow).

## Проверка

```bash
cargo test
python3 scripts/fake_ollama.py &        # заглушка Ollama, только для проверки HTTP-контракта
python3 evaluate.py --data dev.jsonl --endpoint http://127.0.0.1:8000/v1/check --report report.json
```
