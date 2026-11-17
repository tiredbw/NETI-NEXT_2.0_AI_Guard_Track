# Локальная демонстрация

Из корня проекта:

```bash
uv sync --python 3.12 --frozen
.venv/bin/python scripts/run_demo.py
```

Launcher создаёт `data/demo-access.json` со случайными credentials и HMAC key, затем запускает API только на `127.0.0.1:8000`. Секреты не печатаются. Файл имеет права 0600, директория — 0700; `data/` исключена из Git. Повторный запуск не меняет credentials и HMAC key.

Не передавать в `--state-dir` системные или общие каталоги: это выделенная приватная директория состояния. Для отдельной демонстрационной БД можно указать новый каталог:

```bash
.venv/bin/python scripts/run_demo.py --state-dir /tmp/astraguard-demo
```

Подготовить доступ без старта сервера:

```bash
.venv/bin/python scripts/run_demo.py --prepare-only
```

`data/demo-access.json` содержит соответствие bearer token → principal:

| Subject | Tenant | Роль |
|---|---|---|
| alice | A | viewer |
| operator | A | operator |
| reviewer | A | security_reviewer |
| bob | B | viewer |

Скопировать нужный token из локального файла в HTTP-клиент как `Authorization: Bearer TOKEN`. Не отправлять файл в переписку, Git или скринкасты. Launcher не предоставляет endpoint выдачи секретов и не меняет роль через клиентский параметр.

Веб-интерфейс: http://127.0.0.1:8000. [Инструкция и сценарий](UI.md). Локальная справка API: `/docs`, полная OpenAPI-схема: `/openapi.json`.

Сценарии чтения и подтверждений описаны в STAGE_02.md и STAGE_03.md.

## Операционная статистика

GET `/v1/stats` доступен только `security_reviewer` и возвращает проверки его tenant за последние 7 дней: количество ALLOW/REVIEW/BLOCK, review rate, p50/p95 сохранённых latency с числом измерений. Пустая выборка →null для rate/percentiles.

Execution events, выдача approval и финальное ALLOW уже подтверждённой операции не считаются повторной классификацией запроса. Это статистика эксплуатации, не Precision/Recall и не benchmark end-to-end latency. Текущее поле total в проверках измеряется до сохранения audit (ограничение этапа 1).

## Проверки

На момент добавления launcher/statistics: **65 offline tests passed**, одно предупреждение устаревающего backend TestClient. Новый тест проверяет случайные стабильные credentials, права файлов и отсутствие секретов в stdout. Статистика проверена на tenant isolation и отсутствие двойного счёта approval/execution.

Браузерный сценарий реализован и проверен в этапе UI (см. UI.md). Оценка качества на корпусе остаётся следующим этапом.
