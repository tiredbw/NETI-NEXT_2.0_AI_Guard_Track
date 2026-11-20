# Этап 1: advisory API

Реализован первый функциональный этап, не весь P0. Runtime: Python 3.12; `uv.lock` фиксирует зависимости.

Этот документ описывает состояние первого этапа. Последующие дополнения и актуальные ограничения — в [STAGE_02.md](STAGE_02.md).

## Запуск

Из корня репозитория:

```bash
uv sync --python 3.12 --frozen
export ASTRAGUARD_HMAC_KEY="$(.venv/bin/python -c 'import secrets; print(secrets.token_hex(32))')"
export ASTRAGUARD_IDENTITIES="$(.venv/bin/python -c 'import secrets,json; print(json.dumps({secrets.token_urlsafe(32): {"subject_id":"alice","tenant_id":"A","role":"viewer"}}))')"
.venv/bin/uvicorn astraguard.main:create_app --factory --app-dir src --host 127.0.0.1 --port 8000
```

Переменные экспортируются в текущем shell; секретов по умолчанию нет. При повторном запуске с новым ключом HMAC корреляция старых событий не сохраняется. Для постоянной конфигурации хранить значения локально вне Git. `.env.example` автоматически не загружается.

Swagger UI: http://127.0.0.1:8000/docs. В этом этапе bearer header задаётся вручную в HTTP-клиенте; полноценный демонстрационный UI запланирован отдельно.

Доступные маршруты: GET `/health/live`, `/health/ready`, `/v1/me`, `/v1/policies`, POST `/v1/sessions`, POST `/v1/checks`, GET `/v1/checks`, `/v1/checks/{id}`.

Создать сессию с Authorization Bearer credential, затем отправить `/v1/checks` с `text`, `session_id`, `policy_id: strict-demo-v1`. Чужие session/check недоступны. Пустой текст запрещён; >6000 символов и body >64 КиБ →413. Сбой обязательного аудита →503. Ни один маршрут пока не исполняет инструментов и не вызывает целевого агента.

## Проверки

```bash
.venv/bin/python -m pytest -q
```

Offline tests используют fake detector и mock HTTP transport только в тестах. Проверяется маршрутизация решений, а не точность Qwen. Есть предупреждение Starlette о deprecated httpx TestClient backend; текущие тесты исполняются, переход на другой backend не включён в этот этап.

Compatibility smoke Ollama выполняется отдельно. Первая попытка получила invalid_output; runner выдал literal `\\n` вместо валидного JSON. Включены проверенное `think:false` и требование компактного JSON. Ответ не «ремонтируется»: невалидный результат всегда REVIEW. Реальные метрики корпуса ещё не измерены.

После изменения на реальном локальном Ollama один запрос «Объясни, что такое prompt injection и как от него защищаться» вернул валидный DetectorResult: benign, categories=[], severity=none. Это успешный compatibility smoke, не оценка качества корпуса.

## Оставшиеся этапы

- Полный policy lifecycle, глубина/duplicate keys YAML, audit retention и полная схема метаданных/версий из API.md.
- Tool registry/executor, enforce tenant boundary непосредственно перед действием, agent forwarding, approvals/idempotency.
- Серверная многоходовая история; сейчас advisory check рассматривает только текущий текст, без накопления turns.
- Policy admin API, filters/cursor history, статистика; текущая история ограничена последними 100 событиями и owner scope.
- Startup model warm-up/digest; сейчас readiness degraded до первой успешной проверки detector, digest явно null.
- Полный end-to-end timing (текущее total до записи audit), учёт queue, доказательство отмены backend inference при timeout.
- Веб-интерфейс и корпус quality evaluation по TEST_PLAN.md.

Политика проверяет назначение профиля и роли на API; функция авторизации tool intent покрыта unit tests, но runtime endpoint инструментов ещё отсутствует. Поэтому этот этап нельзя представлять как готовую защиту инструментов или завершение CLAUDE_TASK_01.
