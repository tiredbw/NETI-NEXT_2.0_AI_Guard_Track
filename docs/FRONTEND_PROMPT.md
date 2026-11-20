# Промпт для фронтенда «ИИ-сторож»

Этот документ — задание фронтенд-разработчику (человеку или Claude Code) и одновременно контракт API между фронтом и бэком. Бэкенд реализует маршруты из раздела «Контракт», фронт до их готовности работает на встроенном моке.

---

## Промпт

Ты делаешь демонстрационный и административный интерфейс для «ИИ-сторожа» — защитного шлюза между пользователем и DevOps-агентом `it_ops_agent` (кейс «Группа Астра», НЭТИ-НЕКСТ 2.0). Сторож проверяет запрос вместе с контекстом (роль, история, вложения), применяет YAML-политику `security_policy.yaml` и возвращает `allow`, `confirm` или `block` с уровнем риска, категорией и объяснением.

Интерфейс оценивают эксперты на защите. Он должен наглядно показать:

1. запрос, роль, историю и вложения, решение, риск, категорию и объяснение;
2. что `allow` передаётся агенту, `block` не передаётся, а `confirm` передаётся только после отдельного подтверждения;
3. журнал проверок со временем, решением, категорией, задержкой и версией политики, с маскированием секретов;
4. что правка YAML-политики меняет решение без правки кода и переобучения;
5. бонусы: журнал с фильтрами, просмотр и редактирование политики с автором/временем и ограничением доступа, изолированные сессии с историей и многошаговой атакой.

### Ограничения

- Чистые HTML, CSS и JavaScript (ES modules), без сборки и без CDN: сервис должен работать без интернета.
- Код в `frontend/`. Бэкенд раздаёт эту папку статикой с того же origin, что и API. Для отдельного запуска: `python3 -m http.server 5173 -d frontend`.
- Режим мока включается явно: `?mock=1`. Без него фронт ходит в реальный API. Если API недоступен, интерфейс показывает ошибку и ничего не передаёт агенту (fail-closed), а не переключается на мок молча.
- Адрес API по умолчанию — тот же origin; переопределяется `?api=http://host:8000`.
- Никаких секретов в localStorage. Админ-токен хранится только в памяти вкладки.
- Пользовательский текст выводится только через `textContent`, никакого `innerHTML` с данными.
- Работает на ширине телефона, поддерживает тёмную тему.

### Задачи

**P0**
- [ ] Каркас: шапка с режимом (API или мок), здоровьем сервиса и версией политики; вкладки «Проверка», «Агент», «Журнал», «Политика», «Сессии».
- [ ] Мок всего контракта: политика читается из YAML (тот же формат, что `security_policy.yaml`), детектор на правилах, журнал, входящие агента, сессии.
- [ ] Экран проверки. Ввод: пользователь и роль, запрос, история (реплики user/assistant), вложения (имя и текст). Вывод: решение, риск, категория, объяснение, инструмент, окружение, правило политики, сигналы, задержка, версия политики.
- [ ] Демо-сценарии на кнопках: легитимный вопрос, учебный вопрос про атаку, jailbreak, инъекция во вложении, извлечение системного промпта, один запрос под разными ролями, prod и dev.
- [ ] «Сравнить по ролям»: один запрос проверяется для developer, sre и admin, результаты рядом.
- [ ] allow → «Передано агенту», квитанция. block → «Не передано». confirm → отдельная кнопка «Подтвердить»; до неё агент ничего не получает.
- [ ] Подтверждение привязано к пользователю и хешу запроса: если запрос или контекст изменены после проверки, кнопка недоступна и нужна повторная проверка.
- [ ] Вкладка «Агент»: что реально получила заглушка агента. Заблокированных запросов там нет.

**P1**
- [ ] Журнал: фильтры по времени, решению, категории, роли; задержка и версия политики; текст замаскирован.
- [ ] Политика: текущий YAML, версия, автор и время изменения, история версий.
- [ ] Редактор политики: проверка, применение только с админ-токеном, список ошибок валидации.
- [ ] Сценарий для жюри: проверить запрос, изменить правило, проверить снова и показать «было → стало».

**P2**
- [ ] Сессии: создание, список своих сессий, история диалога, очистка; пользователь видит только свои сессии.
- [ ] Многошаговая атака и легитимное продолжение; объяснение, как история повлияла на решение.
- [ ] Лимиты сессии: число реплик и срок хранения.

### Готово, когда

- Все сценарии проходят в мок-режиме и с реальным API без правки кода фронта.
- В консоли браузера нет ошибок; интерфейс работает на ширине 375 px и в тёмной теме.
- `node --test frontend/tests` проходит.

---

## Контракт API

Все тела — JSON, `Content-Type: application/json; charset=utf-8`. Ошибки: HTTP 4xx/5xx и тело `{"error": "<code>", "detail": "<текст>"}`.

### Общие типы

```jsonc
// Context — ровно как в кейсе
{
  "target_agent": "it_ops_agent",
  "user_role": "developer | sre | admin",
  "user_id": "u-1001",
  "user_name": "Иван Петров",
  "system_prompt": "…",
  "history": [{"role": "user | assistant", "content": "…"}],
  "attachments": [{"type": "document", "name": "README.md", "content": "…"}]
}

// CheckResult — ответ /v1/check; первые пять полей требует evaluator
{
  "decision": "allow | confirm | block",
  "risk_level": "none | low | medium | high | critical",
  "risk_category": "none | sensitive_action | prompt_injection | …",
  "explanation": "Роль developer не допускает restart_service в prod.",
  "latency_ms": 412.3,
  "check_id": "chk_…",
  "request_hash": "sha256 от канонического JSON {user_prompt, context}",
  "policy_version": "1#3f9a2c1b",
  "tool": "restart_service | read_logs | run_shell | delete_resource | secrets | null",
  "env": "prod | nonprod | unknown | null",
  "policy_rule": "agents.it_ops_agent.roles.developer.tools.restart_service = nonprod",
  "signals": [{"source": "rules | model | policy | history | attachment", "label": "…", "detail": "…"}]
}
```

`request_hash` — SHA-256 (hex) строки `JSON.stringify` от `{user_prompt, context}` с ключами, отсортированными по алфавиту на всех уровнях, без пробелов. Фронт считает тот же хеш, чтобы понять, изменён ли запрос после проверки.

### Маршруты

| Маршрут | Тело / параметры | Ответ |
|---|---|---|
| `GET /health` | — | `{status: "ok", mode: "gpu", model: "qwen3.5:4b", policy_version}` |
| `POST /v1/check` | `{user_prompt, context}` | `CheckResult`. Только оценка, ничего не передаёт. |
| `POST /v1/demo/submit` | `{user_prompt, context}` | `{check: CheckResult, status: "forwarded" \| "blocked" \| "pending_confirmation", receipt: Receipt \| null, confirmation: {check_id, request_hash, user_id, expires_at} \| null}` |
| `POST /v1/demo/confirm` | `{check_id, request_hash, user_id}` | `{status: "forwarded", receipt: Receipt}`. Ошибки: 403 `wrong_user`, 404 `not_found`, 409 `request_changed` или `already_used`, 410 `expired`. |
| `GET /v1/agent/inbox?limit=50` | — | `{items: [Receipt]}`, новые сверху |
| `GET /v1/journal` | `since`, `until` (ISO 8601), `decision`, `category`, `role`, `limit`, `offset` | `{items: [JournalEntry], total}` |
| `GET /v1/policy` | — | `{version, updated_at, updated_by, comment, yaml}` |
| `GET /v1/policy/history` | — | `{items: [{version, updated_at, updated_by, comment}]}` |
| `POST /v1/policy/validate` | `{yaml}` | `{valid: bool, errors: [string]}` |
| `PUT /v1/policy` | `{yaml, comment}` + заголовок `X-Admin-Token` | `{version, updated_at, updated_by}`. 401 без токена, 403 неверный токен, 422 `{error: "invalid_policy", errors: [...]}` |
| `POST /v1/sessions` | `{user_id, user_name, user_role}` | `Session` |
| `GET /v1/sessions?user_id=` | — | `{items: [Session без turns]}` — только сессии этого пользователя |
| `GET /v1/sessions/{id}?user_id=` | — | `Session`; 403 `wrong_user`, 404, 410 `expired` |
| `DELETE /v1/sessions/{id}?user_id=` | — | `{deleted: true}` |
| `POST /v1/sessions/{id}/messages` | `{user_id, user_prompt, attachments}` | ответ как у `/v1/demo/submit` плюс `history_effect: {turns_considered, flagged: [{turn, reason}], note}` и `session: Session` |

```jsonc
// Receipt — запись заглушки агента
{"receipt_id": "rcp_…", "check_id": "chk_…", "received_at": "ISO", "user_id": "u-1001",
 "user_role": "sre", "decision": "allow | confirm", "confirmed": false, "prompt_masked": "…"}

// JournalEntry
{"check_id": "chk_…", "ts": "ISO", "user_id": "u-1001", "user_role": "sre",
 "decision": "block", "risk_level": "high", "risk_category": "tool_abuse",
 "latency_ms": 12.5, "policy_version": "1#3f9a2c1b", "prompt_masked": "…", "explanation": "…",
 "source": "check | demo | session"}

// Session
{"session_id": "ses_…", "user_id": "u-1001", "user_role": "sre", "created_at": "ISO", "expires_at": "ISO",
 "limits": {"max_turns": 20, "ttl_minutes": 60},
 "turns": [{"index": 0, "role": "user | assistant", "content": "…", "ts": "ISO", "decision": "allow"}]}
```

Правила для бэка, на которые опирается фронт:

- В сессии `context.history` собирает сервер из сохранённых реплик; клиент историю не присылает. Заблокированная реплика остаётся в истории с пометкой `decision`, её содержимое агенту не уходит.
- Подтверждение одноразовое, живёт 10 минут, принадлежит `user_id` из исходной проверки.
- В журнале и во входящих агента текст маскируется: пароли, токены, ключи, приватные ключи заменяются на `[скрыто]`.
- `policy_version` меняется при каждом применении политики.
