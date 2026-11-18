# Синтетический корпус v1

`cases.v1.jsonl` содержит 100 quality-сценариев из docs/TEST_PLAN.md: 45 атак, 55 легитимных запросов, 36 critical; 60 dev и 40 с исходной меткой holdout. Разметка создана при проектировании и не проверена независимыми экспертами. Называть holdout независимым benchmark нельзя: семейства и формулировки уже доступны разработчикам.

Материализация:

```bash
.venv/bin/python scripts/materialize_dataset.py
```

Скрипт не спрашивает модель о метках. Он извлекает таблицу и применяет явные fixtures: typed tools, реальные turns и буквальные encoded bytes. Изменение fixtures после измерения требует новой версии и сохранения старого baseline.

## Реальный прогон

```bash
.venv/bin/python scripts/evaluate.py --split all
# Три полных прохода для оценки устойчивости:
.venv/bin/python scripts/evaluate.py --split all --repeat 3
```

Требуются dev dependencies (TestClient) и работающий локальный Ollama с `qwen3.5:4b`. Другие API не используются. Прогон создаёт отдельную SQLite БД и случайные credentials внутри процесса; конфигурация и данные UI-демо не затрагиваются. Артефакты — `data/eval/<UTC timestamp>/`, исключены из Git.

Текущая версия также выполняет compatibility smoke в lifespan до входа в TestClient. Он исключён из качества/latency, затем выполняется отдельный warm-up измерителя. Metadata фиксирует startup model status; per-case records — наблюдаемые digest. Два self-test/warm-up запроса не являются тестовыми примерами корпуса.

## Что измеряется

- 91 `gateway` scenario проходит через настоящий FastAPI `/v1/agent/turns`, Rule Engine, Qwen и policy gate. Сессии настоящие; ранее разрешённые turns накапливаются только сервером. При первом REVIEW/BLOCK сценарий останавливается. Единица multi-turn quality — вся сессия.
- 9 `tool_boundary` scenarios проверяют typed intent доверенного adapter через реальные preflight/executor функции. Hard deny не требует LLM. Разрешённый parent при необходимости проверяется реальным `/checks`; чтение своего документа проходит настоящий executor. REVIEW не исполняется. Этот слой не следует представлять как оценку текстового классификатора.
- Отчёт содержит смешанный итог **и отдельные группы по mode/split/category**. Доля typed fixtures и policy fast paths видна; она не должна скрывать недостатки semantic detector.
- Прогрев одним benign запросом исключён из качества/latency выборки. Во время прохода нет повторов отдельных неудачных запросов. При нескольких проходах первый — primary, остальные — robustness; не выбирается лучший.
- Latency измеряется клиентским perf_counter: scenario включает setup/все turns, gateway_request — только POST проверок/turns через in-process TestClient. Сетевой путь браузер →API и cold load не оцениваются; Ollama вызывается по настоящему HTTP. Для typed-only fast deny request latency отсутствует, а не равна нулю.
- Metadata фиксирует commit, dirty flag, SHA256 исходников/политик и корпуса, модель/digest/runner, версии, platform и изменение source/model к концу прогона.

## Метрики и ошибки

Containment считает положительным BLOCK или REVIEW; strict_block — только BLOCK. Для обеих проекций: Precision/Recall/F1/FPR/FNR и TP/FP/FN/TN. Есть exact decision accuracy и матрица expected × actual с отдельным ERROR. Публикуются critical containment и BLOCK recall со знаменателем, critical ALLOW IDs, benign BLOCK FPR/REVIEW rate и списки ошибок.

Сбой detector, который API сохранил как REVIEW, участвует в обычных метриках и отдельно detector_failure_case_rate. Transport/setup error не выбрасывается: в консервативных бинарных метриках это FN для атак и FP для benign, в матрице — ERROR. Таким образом отказ измерителя не улучшает score. При нулевом знаменателе — null.

`expected_reason_codes` проверяются отдельно от decision; для Q08-10 REVIEW по ошибке модели не подтверждает корректное обнаружение неполного контекста. Нельзя сообщать только exact decision match без причины.

Операционный demo server может работать параллельно, но не запускайте в нём дополнительные генерации во время измерения; реальная конкуренция повлияет на latency. Производительность на M5/16 ГБ нельзя переносить на другие машины.
