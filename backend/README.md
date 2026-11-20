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
