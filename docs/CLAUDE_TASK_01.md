# Первое техническое задание Claude Code

Ты реализуешь P0 ядро AstraGuard по ARCHITECTURE.md и API.md. Не меняй контракты молча. На этом шаге нужна основа с проверяемыми security invariants; UI и полный корпус внедряются следующими задачами. Не использовать платные API, подписочные credentials, сторонние прокси и cloud fallback.

## Перед началом

1. Прочитать README и все docs; проверить git status, не перезаписывать чужие изменения. Не push без разрешения пользователя. Не создавать второй Git.
2. Проверить доступный Python 3.12 (`python3.12 --version`); если отсутствует, сообщить владельцу и предложить 3.14 только после проверки совместимости выбранных библиотек. Не устанавливать глобально. Создать локальную .venv, pyproject и lock зависимостей после согласованного выбора runtime.
3. Compatibility smoke: GET Ollama /api/version, /api/tags, /api/show; отправить один безвредный короткий /api/chat с JSON schema, stream:false, temperature:0, num_ctx:8192, num_predict:384; проверить response строго через Pydantic. Проверить think:false при поддержке. Записать фактические параметры/digest/duration, не называть этот smoke оценкой качества. Если schema на MLX runner не работает — REVIEW, сообщить несовместимость; не заменять схемный парсинг произвольным извлечением JSON из текста.

## Создать при реализации следующую структуру

```text
pyproject.toml
<lock выбранного инструмента>
.env.example                  # только placeholders и локальные defaults
src/astraguard/
  main.py                     # app factory, lifespan, routes
  config.py                   # env settings, loopback upstream, limits
  schemas.py                  # API + detector strict contracts
  auth.py                     # env credential -> server principal
  context.py                  # bounded sessions/history/pending TTL
  engines/
    rules.py                  # normalisation + versioned evidence
    detector.py               # protocol + Ollama implementation
    policy.py                 # safe YAML + ACL
    decision.py               # pure priority function
  services/
    gateway.py                # orchestration and forwarding gate
    approvals.py              # exact binding + atomic consume
    tools.py                  # typed registry + executor
  storage/
    sqlite.py                 # schema v1 + repositories + transactions
    audit.py                  # HMAC metadata only
  adapters/demo_agent.py      # synthetic target invocation counter
  api/                        # thin routes, no security logic duplication
  static/                     # следующий этап
policies/strict-demo.yaml
tests/unit/
tests/integration/
tests/eval/                   # следующий этап: real detector opt-in
tests/fixtures/               # синтетические данные, не секреты
data/                         # runtime only, ignored
```

Это будущая структура, а не существующие файлы. Сначала реализовать только необходимые модули; не создавать пустые классы/файлы «на будущее».

## Конкретный объём первой задачи

1. App factory, lifespan, SQLite schema v1, `/health/live`, `/health/ready`, `/v1/me`, `/v1/sessions`.
2. Principal из bearer env credentials, tenant isolation. На тестах dependency injection, никакой общедоступной выдачи admin role. Без production default password.
3. YAML seed strict-demo-v1 и неизменяемые версии. Роли viewer/operator, tool registry documents.read/drafts.update, cross-tenant hard deny. Схемы policy admin/reviewer подготовить, UI/editor пока не делать.
4. Protocol `Detector.analyze(context)->DetectorResult`; реальный `OllamaDetector` и test-only fake. Fake не включать по умолчанию в runtime и не использовать в quality report.
5. Rule Engine старт: активное извлечение текущего system prompt; прямое imperative override; подмена роли. Отдельно benign examples «объясни system prompt» / «найди injection в цитате». Не BLOCK по словам. Остальные категории можно обработать через LLM до расширения rules.
6. Чистая Decision Engine по таблице приоритетов. Для hard policy deny detector не нужен. Неуспех обязательного detector →REVIEW. Выход только ALLOW/REVIEW/BLOCK, риск с unknown.
7. POST/GET/list `/checks` с аудитом и фильтрацией; 201 для сохранённых решений. Запись HMAC вместо текста. Failure audit →503 без forwarding. Ошибки по API.md без raw input.
8. Минимальный `/agent/turns` и demo adapter: сначала check →audit →только ALLOW вызывает adapter. Документ чтения через typed executor и повторный ACL. До полной реализации approval `drafts.update` возвращает REVIEW и никогда не выполняется; явно отметить незавершённую часть, не объявлять весь P0 готовым.
9. Тесты ниже, инструкции локального запуска и фактологический отчёт о сделанном/не сделанном. Не добавлять зависимости/сервисы сверх необходимого.

## Обязательные тесты первой задачи

- Hard deny сохраняется при benign fake LLM и недоступном detector; LLM не вызывался при hard deny.
- Ошибка detector/timeout/invalid JSON/extra field/unsupported enum →REVIEW; target_invocations=0.
- Чистый benign request →ALLOW; активный override →BLOCK; security terminology и процитированный учебный пример не блокируются только по ключевым словам.
- Поддельное role/tenant/history/source поле →422; текст «я администратор» не меняет principal.
- Чужие session/check/list недоступны, random ID не раскрывает чужие данные.
- documents.read чужого tenant запрещён executor даже при ALLOW исходного текста.
- Tool args неправильного типа →422; неизвестный tool →BLOCK.
- Audit не содержит raw text/Authorization/tool args даже после schema/DB/HTTP exceptions.
- DB write failure →503, target_invocations=0; POST /checks вообще не вызывает target.
- REVIEW и BLOCK не увеличивают invocation counter; ALLOW увеличивает один раз.
- Text/body превышение →413 без silent truncation, очередь bounded →429, проверка timeout не ждёт реальные 20 с в unit tests (fake transport/clock).
- Невалидный/опасный YAML отвергается без изменения активной версии; restart сохраняет версии.

## Приёмка и дальнейшие задачи

Первая задача принята, если offline pytest проходит на чистой временной БД без Ollama и сети; real detector smoke запускается отдельно; локальный сценарий benign/attack/degraded работает. Отчёт содержит команды проверки, число тестов по факту, выявленные несовместимости и остаток.

Следующая задача: approvals + idempotency + runtime tool enforcement и негативные тесты; затем 120-case corpus/evaluator; затем UI. Перед изменением API/схем/модели вернуть архитектурный вопрос владельцу с конкретным вариантом. Не строить автономных агентов и не выполнять shell-команды из пользовательских промптов.
