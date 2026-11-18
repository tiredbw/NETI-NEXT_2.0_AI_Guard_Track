# REST API и модель данных

Контракт P0, версия `/v1`. Все запросы JSON UTF-8, кроме статического UI и health. Даты UTC ISO8601, UUID v4. Поля неизвестной схемы запрещены. Bearer authentication; identity определяется сервером. Не принимать роль и tenant из body. HTTPS нужен при выходе за loopback.

Реализованные внешние проверки инструментов и недоверенного контента описаны в [INTEGRATION.md](INTEGRATION.md). Для них MVP использует credential конкретного пользователя; общий service account и делегирование пока не реализованы. Остальные разделы этого документа включают целевой контракт P0; фильтры истории и произвольное окно статистики ещё не реализованы.

Lifecycle детектора реализован в [DETECTOR_LIFECYCLE.md](DETECTOR_LIFECYCLE.md). Runtime detector statuses дополнены draining/quarantined/model_changed; соответствующие серверные reason codes — DETECTOR_QUARANTINED и DETECTOR_MODEL_CHANGED. Они останавливают исполнение и не подтверждаются reviewer. Health содержит проверенные метаданные модели; сам health GET не запускает inference.

Реализованное управление политиками и retention описано в [POLICY_OPERATIONS.md](POLICY_OPERATIONS.md). PUT принимает полный JSON с текущим base version и точным If-Match; сервер назначает version+1. Роль policy_admin задаётся только identities-конфигурацией и не входит в редактируемые policy roles. POLICY_CHANGED — серверное основание REVIEW при смене политики во время проверки.

## Маршруты

| Метод и путь | Доступ | Результат |
|---|---|---|
| GET `/health/live` | local/public | 200 процесс жив; никаких секретов |
| GET `/health/ready` | local/public | 200 ready или 503 degraded, статусы DB/policy/detector |
| GET `/v1/me` | user | subject ID, tenant ID, роли, доступные policy profiles |
| POST `/v1/sessions` | user | 201 `{session_id,expires_at}` |
| POST `/v1/checks` | user | 201 сохранённая оценка; ничего не исполняет |
| GET `/v1/checks/{id}` | owner или reviewer своего tenant | 200 результат, иначе 404 |
| GET `/v1/checks?decision=&category=&limit=&cursor=` | owner; reviewer своего tenant | 200 `{items,next_cursor}`; limit 1..100, default 20 |
| POST `/v1/tool-checks` | adapter с credential пользователя | 201 оценка конкретного typed tool intent; самостоятельно не исполняет |
| POST `/v1/content-checks` | adapter с credential пользователя | 201 оценка недоверенного tool/RAG-текста; не включает его в контекст |
| POST `/v1/reviews/{check_id}/approve` | security_reviewer | 201 `{approval_id,expires_at}` только подтверждаемое действие |
| POST `/v1/agent/turns` | user | 200 gate + execution; gateway сам проверяет и исполняет |
| GET `/v1/policies` | user | 200 доступные profile ID/version и безопасное описание |
| GET `/v1/policies/{id}` | policy_admin | 200 полная активная версия JSON + ETag |
| PUT `/v1/policies/{id}` | policy_admin | 200 новая версия, обязательный If-Match; безопасная атомарная активация |
| GET `/v1/stats?from=&to=` | reviewer | 200 статистика своего tenant, окно ≤7 дней |

Создание произвольных профилей и удаление политик — P1. P0 PUT меняет только существующий профиль в ограниченной схеме; непереопределяемые tenant/tool запреты в коде executor. Idempotency-Key обязателен для `/agent/turns` с изменяющим действием; повтор с тем же ключом/телом возвращает сохранённый результат без повторного исполнения, другое тело →409. TTL ключа 24 часа, уникальность tenant/subject/key, reserve + выполнение SQLite action + запись результата в одной транзакции. P1 внешние side effects требуют отдельного протокола idempotency исполнителя.

## Проверка запроса

```json
{
  "text": "Объясни, как защищаться от prompt injection",
  "session_id": "c1454b44-ef8a-4daa-8dd5-a1fc1d853ca8",
  "policy_id": "strict-demo-v1"
}
```

`text`: непустая строка, ≤6000 символов; `session_id` обязателен, сервер проверяет владельца и TTL. `policy_id` должен быть назначен данному principal; выбрать ослабленный чужой профиль нельзя. Все поля выше обязательны. История/role/source/user_id от клиента запрещены. Проверка `/checks` не добавляет turn в агентскую историю; историю добавляет только успешный forwarding `/agent/turns`.

Ответ (значения иллюстративны, это не измерение):

```json
{
  "id": "fe2c147e-e7b3-4af8-aac9-9d236ced1835",
  "created_at": "2026-11-20T10:00:00Z",
  "decision": "ALLOW",
  "risk": "low",
  "threats": [],
  "reason_codes": ["BENIGN_SECURITY_EDUCATION"],
  "explanation": "Запрос обсуждает защиту и не требует изменить инструкции или права.",
  "policy_ids": [],
  "policy_version": 1,
  "detector": {"status": "ok", "model": "qwen3.5:4b", "digest": "configured-digest"},
  "timing_ms": {"total": 1000, "rules": 1, "policy": 1, "queue": 0, "llm": 990, "audit": 8},
  "review": {"approvable": false, "expires_at": null}
}
```

Threat item: `{category, severity, source:"rules|llm|policy", rule_id:null|string}`. Enum категорий и рисков в ARCHITECTURE.md. `detector.status`: `ok|skipped_hard_deny|unavailable|timeout|invalid_output|context_overflow`. `timing_ms` — неотрицательные числа; этапы не обязаны суммироваться точно из-за overhead. В GET возвращается исходный timing, не время чтения.

Reason codes серверные, enum: `BENIGN_REQUEST`, `BENIGN_SECURITY_EDUCATION`, `ACTIVE_OVERRIDE`, `SYSTEM_EXTRACTION`, `ROLE_SPOOFING`, `TOOL_NOT_ALLOWED`, `TENANT_BOUNDARY`, `RESOURCE_NOT_FOUND_OR_HIDDEN`, `ACTION_REQUIRES_APPROVAL`, `UNTRUSTED_ROLE_CLAIM`, `AMBIGUOUS_INTENT`, `OBFUSCATION`, `SESSION_ESCALATION`, `CONTEXT_INCOMPLETE`, `DETECTOR_UNAVAILABLE`, `DETECTOR_TIMEOUT`, `DETECTOR_INVALID_OUTPUT`, `DETECTOR_CONTEXT_OVERFLOW`, `JAILBREAK_ATTEMPT`, `PRIVILEGE_ESCALATION`. Не давать модели добавлять произвольные коды.

## Tool intent и forwarding

`POST /tool-checks`:

```json
{
  "session_id": "c1454b44-ef8a-4daa-8dd5-a1fc1d853ca8",
  "parent_check_id": "fe2c147e-e7b3-4af8-aac9-9d236ced1835",
  "tool": "documents.read",
  "arguments": {"document_id": "A1"}
}
```

Adapter использует credential исходного principal; пользователь не назначает себе service role. `parent_check_id` должен быть исходным ALLOW того же владельца и сессии; это не заменяет новую policy check. Arguments валидируются схемой выбранного инструмента из registry. Неизвестный инструмент даёт BLOCK с `TOOL_NOT_ALLOWED`, известный с неправильными args →422. Чтение проходит детерминированный ACL; свободный текст `drafts.update.content` проходит detector, повторно не использовать оценку другого текста. Внешняя запись остаётся REVIEW и не подтверждается через demo approval workflow. Оба интеграционных маршрута возвращают `review.approvable=false` и `forwarded=false`.

`POST /agent/turns`: те же поля, что `/checks`, плюс необязательный `approval_id`. На первом вызове выполняет оценку, сохраняет её и при ALLOW отправляет агенту. REVIEW/BLOCK → `forwarded:false`, `target_invocations:0`. При approval gateway извлекает исходный pending payload из RAM, требует совпадения session/text/policy/args, проверяет новую policy version и исполняет только подтверждённое действие. Если pending content утрачен —409, новая проверка. Ответ: `{check:<CheckResult>,execution:{status:"not_forwarded|completed|failed",forwarded:boolean,agent_invocation_id:null|uuid,target_invocations:integer,result:null|object}}`.

`check.decision` для уже одобренного подтверждаемого действия становится ALLOW только после успешной повторной policy check; `approved_check_id` в audit связывает с исходным REVIEW. Нельзя переписать исходный event. Policy denial при повторной проверке →новый BLOCK. Агентская ошибка → `execution.failed`, без автоматического повтора side effects. Runtime tool denials отражать отдельными дочерними check и финальным отсутствием результата запрещённого действия.

Approval body `{}`; ответ не содержит сам текст/аргументы. UI показывает digest действия, описание операции и ресурс только в пределах прав reviewer. Не может подтвердить сам запросивший principal: для demo две отдельные identity.

## Policy schema

```yaml
id: strict-demo-v1
version: 1
roles:
  viewer:
    allowed_tools: [documents.read]
    resource_scope: own_tenant
    confirmation_actions: []
  operator:
    allowed_tools: [documents.read, drafts.update]
    resource_scope: own_tenant
    confirmation_actions: [drafts.update]
```

Reviewer/admin capabilities задаются серверной identity-конфигурацией, а не этим редактируемым YAML. Только известные enum инструментов и `own_tenant` scope; нельзя активировать wildcard/all-tenants. Version назначает сервер монотонно, If-Match на текущий ETag предотвращает lost update. Новый профиль валидируется целиком до активации, ошибка сохраняет старую версию. Каждая версия immutable в БД. YAML — стартовый seed при пустой БД, не перезаписывает изменения на restart. Экспорт YAML — P1.

## Ошибки и отказоустойчивость

Единый envelope `{error:{code,message,request_id}}`, без stacktrace и raw validation input.

| HTTP | Случай |
|---|---|
| 400 | Некорректный JSON |
| 401 | Нет/неверный credential |
| 403 | Нет права на endpoint/профиль |
| 404 | Не найден либо скрыт чужой event/session/resource |
| 409 | Approval expired/used/mismatch, idempotency conflict, сессия утрачена |
| 412 | If-Match устарел |
| 413 | Body/text превышают лимит |
| 415 | Неподдерживаемый Content-Type/вложения |
| 422 | Ошибка schema/enum/типов; без input echo |
| 428 | Нет обязательного If-Match |
| 429 | Rate limit или очередь, Retry-After |
| 503 | DB/audit/policy недоступны; никаких side effects |

BLOCK и REVIEW — нормальные результаты 201 `/checks` и 200 `/agent/turns`, а не 403 транспорта. Сбой LLM при работоспособных DB/policy → сохранённый REVIEW. Readiness при этом 503, liveness 200. Ограничение per-principal 30 запросов/мин и глобальная bounded inference очередь; health не запускает генерацию на каждом запросе. Compatibility/warm-up выполняется один раз на старте, readiness отражает результат; рабочие вызовы обновляют статус.

## Хранение

| Таблица | Поля |
|---|---|
| audit_events | id PK, created_at, tenant_id, subject_id, session_id, parent_id nullable, decision, risk, categories_json, reason_codes_json, policy_ids_json, policy_id, policy_version, rules_version, detector_prompt_version, model_digest, detector_status, request_hmac, timing_json, forwarded, approved_check_id nullable |
| policy_versions | policy_id + version PK, schema_json, created_at, author_id, content_hash |
| active_policies | policy_id PK, version FK |
| approvals | id PK, check_id FK, tenant_id, requester_id, reviewer_id, binding_hmac, policy_version, expires_at, consumed_at nullable |
| resources | id PK, tenant_id, owner_id, kind, synthetic_content, version |
| execution_requests | tenant_id + subject_id + idempotency_key UNIQUE, payload_hmac, status, result_json, expires_at |

`resources` содержит только синтетические demo данные; реальные данные в MVP не импортировать. Credentials не сохранять plaintext в БД. Сессии/limited history/pending payload — bounded RAM с TTL. Индексы audit `(tenant_id,created_at,id)`, `(tenant_id,subject_id,created_at)`. UUID/cursor не являются авторизацией. Миграция v1 через `PRAGMA user_version`, последующие изменения транзакционно без удаления audit.

Stats: totals по decision/category, review_rate, detector_error_rate, forwarded_total, tool_denied_total, latency p50/p95 с размером выборки и окном. Это операционная статистика, не Precision/Recall: для последних нужна эталонная разметка тестового корпуса.
