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
| `OLLAMA_NUM_CTX` | `8192` | Контекст модели в токенах. 4096 экономит VRAM под KV-кэш; длинная история и вложения тогда сильнее обрезаются (запрос и вложения в приоритете) |
| `ADMIN_TOKEN` | не задан | Токен администратора: изменение политики (`PUT /v1/policy`, `/v1/policy/reload`) и чтение журнала, входящих агента и политики |
| `AUDIT_TOKEN` | не задан | Токен аудитора: только чтение журнала, входящих агента и политики. Без обоих токенов эти разделы закрыты |
| `FRONTEND_DIR` | `../frontend` | Каталог интерфейса; сервис раздаёт его на `/`. Нет `index.html` — только API |
| `JOURNAL_PATH` | `../data/journal.jsonl` | Журнал проверок в JSONL (только маскированный текст); пусто — только память |
| `TFIDF_MODEL` | `models/tfidf.json` | Файл TF-IDF-модели; нет файла — сервис работает без второго сигнала |
| `TFIDF_BACKSTOP` | `0` | `1` — блокировать allow, если TF-IDF видит атаку с p ≥ порога |
| `TFIDF_THRESHOLD` | из модели (0.747) | Порог страховки |
| `TFIDF_PREFILTER` | выключен | Быстрый фильтр до Qwen: при p(атака) ≥ значения (например `0.9`) и категории, которую блокирует политика, модель не вызывается. Сравнение: `train/bench_tfidf.py` |
| `TFIDF_HINT` | `0` | `1` — добавлять оценку TF-IDF в сообщение для Qwen как подсказку |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Origin отдельного dev-сервера фронта; для демо с того же адреса не нужен |

После запуска интерфейс открывается на [http://127.0.0.1:8000](http://127.0.0.1:8000): фронт и API на одном origin.

## Маршруты

Контракт описан в [docs/FRONTEND_PROMPT.md](../docs/FRONTEND_PROMPT.md). Ошибки: `{"error": "<code>", "detail": "<текст>"}`.

| Маршрут | Что делает |
|---|---|
| `POST /v1/check` | Только оценка: решение, риск, категория, объяснение. В журнал пишутся хеш, решение и правило, без текста (текст хранится только для запросов из интерфейса с `X-Guard-Client: ui`) |
| `POST /v1/demo/submit` | Проверка и путь до заглушки агента: allow → квитанция, block → не передано, confirm → ожидание подтверждения (10 мин) |
| `POST /v1/demo/confirm` | Одноразовое подтверждение автором неизменного запроса (`request_hash`): 403 чужой, 409 изменён/использован, 410 истёк |
| `GET /v1/agent/inbox` | Что реально получила заглушка агента. Нужен `X-Admin-Token` (админ или аудитор) |
| `GET /v1/journal` | Журнал: `since`, `until`, `decision`, `category`, `role`, `limit`, `offset`. Нужен `X-Admin-Token` |
| `GET /v1/policy`, `GET /v1/policy/history` | Действующая политика с версией, автором и временем; история версий. Нужен `X-Admin-Token` |
| `POST /v1/policy/validate` | Проверка YAML без применения. Нужен `X-Admin-Token` |
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
4. Детерминированные правила (`src/rules.rs`) смотрят нормализованный запрос и скрытые варианты и только усиливают ответ модели: заявленная словами роль → `privilege_escalation`; `curl | bash`, ssh-ключи и sudoers, отключение аудита → соответствующий `forbidden_actions`; просьба показать пароли, токены, ключи → `secrets: values`. Явно разрушительные команды (`rm -rf /`, `chmod -R 777 /etc`, `dd of=/dev/sd*`, force push в main, масштабирование всего prod в ноль) блокируются для любой роли. Вопросы «как/почему/объясни» и «не выполняя» правила не трогают. На dev: 37 из 200 атак, 0 ложных из 300; на своём наборе 0 ложных из 105.
5. TF-IDF (`src/tfidf.rs`, обучение в `train/tfidf.py`): символьные n-граммы и логистическая регрессия, сверка с sklearn при загрузке, микросекунды на запрос. Всегда пишет `signals: tfidf` с вероятностью атаки. Страховка `TFIDF_BACKSTOP=1` меняет allow на block при p ≥ 0.747 и категории, которую политика блокирует. Вне обучения на dev (кросс-валидация по группам) порог ловит 97 из 200 атак при 1 ложной блокировке из 300, но на своём наборе другой тематики даёт 27 ложных из 105. Поэтому по умолчанию выключена: включать только после `train/simulate_backstop.py` на сохранённом прогоне Qwen.
6. Правило истории (`src/history.rs`): если реплика ссылается на прошлую («его», «это», «тот»…), просит показать содержимое или отправить наружу, а в последних 4 репликах были пароли, ключи, `shadow` или `.env`, детектору выставляется `secrets: values` — дальше блокирует политика. Вопросы «как…» и обычные продолжения («перезапусти его», «покажи его логи») правило не трогает.

## Замеры

| Дата | Железо | Код | Score | Блокировка high/critical | p95 | VRAM |
|---|---|---|---|---|---|---|
| 20.11 | RTX 4050 Laptop 6 GB, Windows | 3fb512b | 0.955 | 0.91 | 1.93 с | 5.0 GB (пик) |
| 20.11 | Apple M5 | до PR #7 | 0.921 | 0.94 | 3.2 с (штраф 0.05) | 7.1 GB, `num_ctx` 8192 |

Время почти целиком — генерация ответа модели (~70 токенов); `examples/dump_requests.rs` выгружает тела запросов для замеров по этапам.

Версии для воспроизводимости (заполнить с сервера перед защитой): `ollama --version`, digest модели из `ollama list` (столбец ID для `qwen3.5:4b`), `rustc --version`, коммит.

Как мерить на сервере (лимит кейса: 8 GB VRAM на всё решение, p95 ≤ 3 с, лучше ≤ 2,5 с):
- VRAM: во время прогона `nvidia-smi --query-gpu=memory.used --format=csv -l 1` и `ollama ps` (размер и доля GPU у модели). Сравнить `OLLAMA_NUM_CTX=8192` и `4096`: KV-кэш уменьшится, задержка обычно тоже.
- RAM: `ps -o rss= -p $(pgrep astraguard)` и процесс `ollama`.
- p95 по сети: `python3 evaluate.py --data dev.jsonl --endpoint http://<сервер>:8000/v1/check --report report.json --save-predictions pred.jsonl` с другой машины.
- Страховка TF-IDF на этом прогоне: `python3 train/simulate_backstop.py evaluate.py dev.jsonl pred.jsonl ../eval/tfidf_oof_dev.json`.

## Обучение TF-IDF и свои наборы

```bash
pip install -r train/requirements.txt
python3 train/groups.py dev.jsonl ../eval/dev_groups.json
python3 train/own_validation.py <каталог корпусов> ../eval/own_validation.v1.jsonl ../eval/own_holdout.v2.jsonl
python3 train/tfidf.py dev.jsonl ../eval/dev_groups.json models/tfidf.json ../eval/own_validation.v1.jsonl
cargo run --example rules_scan -- dev.jsonl     # срабатывания правил по набору
```

Подробнее о наборах: [eval/README.md](../eval/README.md). `own_holdout.v2.jsonl` не используем для подбора правил и порогов.

## Проверка

```bash
cargo test
python3 scripts/fake_ollama.py &        # заглушка Ollama на 11434, только для проверки HTTP-контракта
python3 evaluate.py --data dev.jsonl --endpoint http://127.0.0.1:8000/v1/check --report report.json
```
