# AstraGuard — ИИ-сторож для it_ops_agent

Решение кейса «ИИ-сторож» («Группа Астра», НЭТИ-НЕКСТ 2.0, 20–22 ноября 2026).
Сторож стоит между пользователем и DevOps-агентом `it_ops_agent` и на каждый запрос отвечает `allow`, `confirm` или `block`
по контракту `POST /v1/check` кейса v2.0.

| Часть | Где | Что |
|---|---|---|
| Сервис | [`backend/`](backend/README.md) | Rust (Axum): `/v1/check`, демо-путь до заглушки агента, журнал, политика, сессии |
| Модель | Ollama, `astraguard-ft` (qwen3.5:4b, дообученная LoRA) | Обязательна на каждой проверке; без ответа модели — `block` (fail-closed) |
| Политика | [`policies/security_policy.yaml`](policies/security_policy.yaml) | Файл кейса; перечитывается без перезапуска |
| Интерфейс | [`frontend/`](frontend/README.md) | HTML/CSS/JS без сборки; сервис раздаёт его на `/` |
| Обучение и наборы | [`backend/train/`](backend/train), [`eval/`](eval/README.md) | TF-IDF, разбиение dev на группы, свой набор проверки |
| Контракт фронта | [`docs/FRONTEND_PROMPT.md`](docs/FRONTEND_PROMPT.md) | Все маршруты и форматы |
| Архив | [`archive/python-v1/`](archive/python-v1/ARCHIVE.md) | Первая версия на Python/FastAPI, не используется |

## Быстрый запуск

### Windows: одна команда

Нужны [Ollama](https://ollama.com), Rust (`rustup`) и файл модели `astraguard-qwen4b.fixed.gguf` ([скачать, 2,8 ГБ](https://drive.google.com/drive/folders/1naIrO2Bc4f882FR5p5XNr5hOHYjTJYyG?usp=sharing)) в `backend/models/`
(или уже созданная в Ollama модель `astraguard-ft`).

```powershell
powershell -ExecutionPolicy Bypass -File .\start.ps1          # первый запуск или после git pull: добавьте -Build
```

Скрипт проверяет Ollama и модель (при необходимости запускает `ollama serve` и выполняет `ollama create`), задаёт переменные
боевого режима, берёт токены из `backend/.env.local` (создаёт их при первом запуске; файл в git не попадает), собирает сервис,
ждёт прогрева модели и делает контрольный запрос. Если сервер упадёт, скрипт поднимет его снова через 5 секунд.
Логи: `backend/logs/`. Режим итоговой оценки: **GPU** (RTX 4050 Laptop 6 ГБ: VRAM ≈ 3,8 ГБ, p95 ≈ 1,5 с на dev).

### Вручную (Linux, macOS, Windows)

```bash
cd backend/models && ollama create astraguard-ft -f Modelfile && cd ..   # GGUF положить рядом с Modelfile, см. backend/README.md
ADMIN_TOKEN=<случайная строка> cargo run --release
```

Интерфейс: <http://127.0.0.1:8000>. Журнал, входящие агента и политика в интерфейсе открываются токеном `ADMIN_TOKEN`
(или `AUDIT_TOKEN` только для чтения). Все переменные окружения, замеры и порядок решения — в [backend/README.md](backend/README.md).

## Как принимается решение

1. Нормализация: невидимые символы, гомоглифы, leetspeak, разрядка, буквы через дефис («п-р-а-в-и-л-а»), base64 и обратный текст; раскодированные варианты идут модели вместе с исходным.
2. Qwen возвращает категорию, риск, инструмент, запрещённое действие и работу с секретами (JSON-схема, без рассуждений).
3. Детерминированные правила только усиливают ответ модели (заявленная словами роль, curl | bash, sudoers, разрушительные команды, просьбы показать пароли).
4. Политика из YAML: `forbidden_actions`, `always_block`, секреты, затем роль → инструмент → окружение. Неизвестное окружение = prod.
5. TF-IDF-классификатор — второй сигнал в `signals`; как страховка (block, если Qwen пропустил) включена по умолчанию, `TFIDF_BACKSTOP=0` выключает.
