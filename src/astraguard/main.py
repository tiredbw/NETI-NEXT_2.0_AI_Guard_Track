import asyncio  # Очередь inference, фоновые задачи и ограниченные ожидания.
import json  # Сериализация контрактов и разбор структурированных ответов.
import os  # Переменные окружения, права файлов и операции процесса.
import secrets  # Случайные credentials и сравнение без раннего выхода.
import sqlite3  # Транзакции локального аудита и обработка отказов БД.
import time  # TTL объектов и монотонное измерение длительности.
from collections import defaultdict, deque  # Счётчики и очереди ограниченного состояния.
from datetime import datetime, timezone  # UTC-время событий и сроки действия данных.
from pathlib import Path  # Явные пути к локальным данным и ресурсам проекта.
from uuid import uuid4  # Случайные идентификаторы сессий, событий и операций.
from contextlib import asynccontextmanager, suppress  # Управление ресурсами и ожидаемыми исключениями при shutdown.
import logging  # Операционные сообщения без исходных пользовательских запросов.

from fastapi import Depends, FastAPI, HTTPException, Query, Request  # HTTP-контракты, ответы и безопасное выполнение синхронных операций.
from fastapi.exceptions import RequestValidationError  # HTTP-контракты, ответы и безопасное выполнение синхронных операций.
from fastapi.responses import JSONResponse, FileResponse  # HTTP-контракты, ответы и безопасное выполнение синхронных операций.
from fastapi.staticfiles import StaticFiles  # HTTP-контракты, ответы и безопасное выполнение синхронных операций.
from starlette.exceptions import HTTPException as StarletteHTTPException  # HTTP-контракты, ответы и безопасное выполнение синхронных операций.
from starlette.concurrency import run_in_threadpool  # HTTP-контракты, ответы и безопасное выполнение синхронных операций.

from .engines import DetectorFailure, OllamaDetector, Policy, decide, rule_signal  # Подключает engines для текущего компонента.
from .schemas import CheckRequest, ContentCheckRequest, Principal, StrictModel, ToolCheckRequest, TurnRequest  # Подключает schemas для текущего компонента.
from .storage import AuditStore  # Подключает storage для текущего компонента.
from .demo import DemoAgent, plan  # Подключает demo для текущего компонента.
from .approvals import ApprovalService  # Подключает approvals для текущего компонента.
from .policies import PolicyService, policy_etag  # Подключает policies для текущего компонента.
from .integration import IntegrationChecks  # Подключает integration для текущего компонента.
from .pipeline import DemoPipeline, pipeline_reply  # Связывает классификацию, фактический инструмент и проверку его результата.


def create_app(*, credentials=None, db_path=None, hmac_key=None, detector=None, policy_path=None, retention_days=None):  # Собирает API, зависимости и состояние одного процесса шлюза.
    credentials = credentials if credentials is not None else {  # Берёт identity из инъекции зависимостей или серверного окружения.
        token: Principal.model_validate(value)  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
        for token, value in json.loads(os.environ.get("ASTRAGUARD_IDENTITIES", "{}")).items()  # Выбирает элементы составного результата по условию генератора.
    }  # Завершает составное значение или вызов, начатый выше.
    if not credentials or any(len(token) < 24 for token in credentials):  # Credentials должны существовать и иметь достаточную длину.
        raise ValueError("Configure ASTRAGUARD_IDENTITIES with random credentials (>=24 characters)")  # Отклоняет недопустимое состояние: Configure ASTRAGUARD_IDENTITIES with random credentials (>=24 characters).
    key = hmac_key or os.environ.get("ASTRAGUARD_HMAC_KEY", "").encode()  # Секретный ключ HMAC остаётся на сервере.
    if len(key) < 32:  # Ключ HMAC должен иметь достаточную длину.
        raise ValueError("Configure ASTRAGUARD_HMAC_KEY (>=32 bytes)")  # Отклоняет недопустимое состояние: Configure ASTRAGUARD_HMAC_KEY (>=32 bytes).
    retention_days = int(os.environ.get("ASTRAGUARD_AUDIT_RETENTION_DAYS", "7")) if retention_days is None else retention_days  # Срок хранения аудита задаётся в допустимых пределах.
    store = AuditStore(Path(db_path or os.environ.get("ASTRAGUARD_DB_PATH", "data/audit.sqlite3")), key, retention_days)  # Единое хранилище транзакций и журнала этого приложения.
    policy_service = PolicyService(store, Path(policy_path or "policies/strict-demo.yaml"))  # Загружает существующую политику или начальный YAML seed.
    detector = detector or OllamaDetector()  # Использует переданный анализатор либо native Ollama.
    if isinstance(detector, OllamaDetector):  # Native детектору нужен собственный lifecycle и общее хранилище latch.
        detector.store = store  # Единое хранилище транзакций и журнала этого приложения.

    @asynccontextmanager  # Оформляет безопасную пару захват/освобождение ресурса.
    async def lifespan(app):  # Управляет startup, фоновыми задачами и завершением детектора.
        async def housekeeping():  # Периодически удаляет просроченные данные аудита.
            while True:  # Повторяет обработку, пока выполняется True.
                await asyncio.sleep(3600)  # Пауза уступает event loop и не блокирует обработку HTTP.
                try:  # Ограничивает участок, где ожидаемый отказ требует отдельной обработки.
                    await run_in_threadpool(store.cleanup)  # Вызывает run_in_threadpool в рамках текущей операции.
                    app.state.retention_status = "ok"  # Публикует зависимость или операционный статус в состоянии текущего приложения.
                except sqlite3.Error:  # Обрабатывает только указанные ошибки, сохраняя режим остановки при отказе.
                    app.state.retention_status = "unavailable"  # Публикует зависимость или операционный статус в состоянии текущего приложения.
                    logging.getLogger("astraguard").warning("Audit retention cleanup failed")  # Вызывает logging.getLogger('astraguard').warning в рамках текущей операции.
        task = asyncio.create_task(housekeeping())  # Фоновая задача имеет отдельный lifecycle и обработку завершения.
        monitor = None  # Ссылка на задачу обновления метаданных нужна для корректного shutdown.
        try:  # Ограничивает участок, где ожидаемый отказ требует отдельной обработки.
            if isinstance(detector, OllamaDetector):  # Native детектору нужен собственный lifecycle и общее хранилище latch.
                await detector.startup()  # Вызывает detector.startup в рамках текущей операции.
                monitor = asyncio.create_task(detector.monitor())  # Ссылка на задачу обновления метаданных нужна для корректного shutdown.
            yield  # Передаёт ресурс вызывающему, сохраняя управление его завершением.
        finally:  # Этот блок освобождения выполняется и при успешном результате, и при ошибке.
            task.cancel()  # Отменяет ожидание задачи; это не гарантирует остановку backend.
            with suppress(asyncio.CancelledError):  # Ограничивает время жизни ресурса suppress(asyncio.CancelledError) текущим блоком.
                await task  # Дожидается завершения фоновой задачи перед выходом из lifecycle.
            if monitor:  # При shutdown нужно остановить реально созданную задачу мониторинга.
                monitor.cancel()  # Отменяет ожидание задачи; это не гарантирует остановку backend.
                with suppress(asyncio.CancelledError):  # Ограничивает время жизни ресурса suppress(asyncio.CancelledError) текущим блоком.
                    await monitor  # Дожидается завершения фоновой задачи перед выходом из lifecycle.
            if isinstance(detector, OllamaDetector):  # Native детектору нужен собственный lifecycle и общее хранилище latch.
                await detector.close()  # Освобождает ресурс после завершения либо ошибки.

    app = FastAPI(title="AstraGuard", version="0.1.0", docs_url=None, redoc_url=None, lifespan=lifespan)  # Создаёт локальный API с собственным lifecycle и без CDN-документации.
    app.state.store = store  # Публикует зависимость или операционный статус в состоянии текущего приложения.
    app.state.detector = detector  # Публикует зависимость или операционный статус в состоянии текущего приложения.
    app.state.policies = policy_service  # Публикует зависимость или операционный статус в состоянии текущего приложения.
    app.state.retention_status = "ok"  # Публикует зависимость или операционный статус в состоянии текущего приложения.
    app.state.detector_status = "unavailable"  # Публикует зависимость или операционный статус в состоянии текущего приложения.
    agent = DemoAgent(store, policy_service)  # Демонстрационный исполнитель использует то же хранилище и политики.
    app.state.agent = agent  # Публикует зависимость или операционный статус в состоянии текущего приложения.
    approvals = ApprovalService(store, policy_service, agent)  # Подтверждения связаны с тем же demo executor.
    app.state.approvals = approvals  # Публикует зависимость или операционный статус в состоянии текущего приложения.
    integration = IntegrationChecks(store, policy_service, detector)  # Внешние проверки используют общие policy, detector и audit.
    pipeline = DemoPipeline(agent, integration)  # Контролируемый demo использует те же проверки, что внешний адаптер.
    static_dir = Path(__file__).parent / "static"  # Статические ресурсы читаются из пакета приложения.
    app.mount("/static", StaticFiles(directory=static_dir), name="static")  # Вызывает app.mount в рамках текущей операции.

    @app.get("/", include_in_schema=False)  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def home():  # Отдаёт локальный демонстрационный интерфейс.
        return FileResponse(static_dir / "index.html")  # Возвращает структурированный результат текущей операции.

    @app.get("/docs", include_in_schema=False)  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def api_documentation():  # Отдаёт справку без внешних CDN.
        return FileResponse(static_dir / "api.html")  # Возвращает структурированный результат текущей операции.
    sessions = {}  # RAM-хранилище сессий с серверной identity и TTL.
    histories = {}  # Ограниченная история успешно переданных demo turns.
    session_locks = {}  # Исключает параллельное действие в одной сессии.
    requests = defaultdict(deque)  # Поминутные окна лимитов по tenant и subject.

    @app.middleware("http")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    async def body_limit(request, call_next):  # Ограничивает входной HTTP body и задаёт защитные заголовки.
        request.state.request_id = str(uuid4())  # Вызывает str в рамках текущей операции.
        if request.method in ("POST", "PUT"):  # Для запросов с телом нужны ограничения размера и JSON Content-Type.
            chunks, size = [], 0  # Накапливает HTTP body с отдельным счётчиком байтов.
            async for chunk in request.stream():  # Обрабатывает каждый chunk из request.stream().
                size += len(chunk)  # Обновляет size с учётом выполненной операции.
                if size > 65536:  # Суммарный HTTP body ограничен 64 КиБ.
                    return error(413, "INPUT_TOO_LARGE", request)  # Возвращает структурированный результат текущей операции.
                chunks.append(chunk)  # Добавляет элемент в ограниченное состояние текущего процесса.
            if size and request.headers.get("content-type", "").split(";")[0] != "application/json":  # Непустое тело принимается только как application/json.
                return error(415, "UNSUPPORTED_MEDIA_TYPE", request)  # Возвращает структурированный результат текущей операции.
            request._body = b"".join(chunks)  # Вызывает b''.join в рамках текущей операции.
        response = await call_next(request)  # Собирает HTTP-ответ или сохранённое решение текущего маршрута.
        response.headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"  # Сохраняет response.headers['Content-Security-Policy'] для следующей проверки в этой ветви.
        response.headers["X-Content-Type-Options"] = "nosniff"  # Сохраняет response.headers['X-Content-Type-Options'] для следующей проверки в этой ветви.
        response.headers["Referrer-Policy"] = "no-referrer"  # Сохраняет response.headers['Referrer-Policy'] для следующей проверки в этой ветви.
        response.headers["Cache-Control"] = "no-store"  # Сохраняет response.headers['Cache-Control'] для следующей проверки в этой ветви.
        return response  # Возвращает сформированный ответ вызывающему маршруту.

    def error(status, code, request):  # Формирует обезличенный JSON-конверт ошибки.
        return JSONResponse(status_code=status, content={"error": {  # Возвращает структурированный результат текущей операции.
            "code": code, "message": code, "request_id": request.state.request_id}},  # Поле code входит в структурированный контракт текущего результата.
            headers={"Retry-After": "2"} if status == 429 else None)  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.

    @app.exception_handler(StarletteHTTPException)  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    async def http_error(request, exc):  # Преобразует HTTP-исключение в единый формат API.
        return error(exc.status_code, str(exc.detail), request)  # Возвращает структурированный результат текущей операции.

    @app.exception_handler(RequestValidationError)  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    async def validation_error(request, exc):  # Разделяет некорректный JSON и нарушение схемы без эха input.
        status = 400 if any(e["type"] == "json_invalid" for e in exc.errors()) else 422  # Операционный статус компонента для ответа и диагностики.
        return error(status, "INVALID_REQUEST", request)  # Возвращает структурированный результат текущей операции.

    @app.exception_handler(sqlite3.Error)  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    async def db_error(request, exc):  # Останавливает обработку при отказе аудита.
        return error(503, "AUDIT_UNAVAILABLE", request)  # Возвращает структурированный результат текущей операции.

    def identity(request: Request):  # Определяет principal по серверному credential, а не по body.
        authorization = request.headers.get("authorization", "")  # Читает заголовок, не принимая credential из body.
        token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""  # Выделяет credential либо ограниченную кодированную последовательность.
        if not token.isascii():  # Недопустимое кодирование credential получает обычный отказ авторизации.
            raise HTTPException(401, "UNAUTHORIZED")  # Останавливает обработку с HTTP 401 и кодом UNAUTHORIZED.
        principal = next((p for credential, p in credentials.items() if secrets.compare_digest(token, credential)), None)  # Серверная identity для последующих проверок полномочий.
        if principal is None:  # Неизвестный credential не получает identity по умолчанию.
            raise HTTPException(401, "UNAUTHORIZED")  # Останавливает обработку с HTTP 401 и кодом UNAUTHORIZED.
        return principal  # Возвращает значение текущей ветви вызывающему компоненту.

    @app.get("/health/live")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def live():  # Сообщает только о живости процесса.
        return {"status": "live"}  # Возвращает структурированный результат текущей операции.

    @app.get("/health/ready")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def ready():  # Проверяет БД, политику и кешированную готовность детектора.
        with store.connect() as db:  # Соединение обеспечивает commit при успехе и rollback при исключении.
            db.execute("SELECT 1")  # Читает состояние для проверки условий; значения передаются SQL-параметрами.
        policy_service.snapshot()  # Вызывает policy_service.snapshot в рамках текущей операции.
        native = detector.health() if isinstance(detector, OllamaDetector) else None  # Native readiness использует lifecycle детектора вместо общего флага.
        status = native["status"] if native else app.state.detector_status  # Операционный статус компонента для ответа и диагностики.
        ok = (native["ready"] if native else status == "ok") and app.state.retention_status == "ok"  # Готовность требует исправности всех обязательных компонентов.
        return JSONResponse(status_code=200 if ok else 503, content={  # Возвращает структурированный результат текущей операции.
            "status": "ready" if ok else "degraded", "database": "ok", "policy": "ok",  # Явный статус отделяет разрешение, отсутствие передачи и завершённое действие.
            "detector": status, "retention": app.state.retention_status,  # Статус и digest показывают, вызывалась ли закреплённая модель.
            "model": native})  # Фиксирует используемую модель и параметры вызова.

    @app.get("/v1/me")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def me(principal=Depends(identity)):  # Возвращает серверную identity и назначенный профиль.
        return {"subject_id": principal.subject_id, "tenant_id": principal.tenant_id,  # Возвращает структурированный результат текущей операции.
                "roles": [principal.role], "policy_ids": [policy_service.id]}  # Поле roles входит в структурированный контракт текущего результата.

    @app.post("/v1/sessions", status_code=201)  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def session(principal=Depends(identity)):  # Создаёт ограниченную по TTL и владельцу сессию.
        now = time.time()  # Текущее время для проверки срока действия.
        for sid in list(sessions):  # Обрабатывает каждый sid из list(sessions).
            if sessions[sid][1] < now:  # Удаляет только сессии с истёкшим TTL.
                del sessions[sid]  # Удаляет устаревшее состояние, не затрагивая историю Git или файлы.
                histories.pop(sid, None)  # Удаляет устаревшее или больше не используемое значение.
                session_locks.pop(sid, None)  # Удаляет устаревшее или больше не используемое значение.
        if len(sessions) >= 1000:  # Ограничивает число сессий текущего процесса.
            raise HTTPException(429, "SESSION_CAPACITY")  # Останавливает обработку с HTTP 429 и кодом SESSION_CAPACITY.
        sid = str(uuid4())  # Строковое представление UUID сессии.
        sessions[sid] = (principal, now + 1800)  # Связывает новый UUID с серверным principal и тридцатиминутным TTL.
        histories[sid] = []  # Новая сессия начинает с пустой разрешённой истории.
        session_locks[sid] = asyncio.Lock()  # Каждой сессии соответствует отдельный asyncio lock.
        return {"session_id": sid, "expires_at": datetime.fromtimestamp(now + 1800, timezone.utc).isoformat()}  # Возвращает структурированный результат текущей операции.

    @app.get("/v1/policies")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def policies(principal=Depends(identity)):  # Показывает идентификатор и активную версию профиля.
        policy = policy_service.snapshot()  # Снимок активной политики, не изменяемый ответом модели.
        return [{"id": policy.id, "version": policy.version}]  # Возвращает структурированный результат текущей операции.

    def require_admin(principal):  # Разрешает административный маршрут только policy_admin.
        if principal.role != "policy_admin":  # Управление политикой требует отдельной серверной роли администратора.
            raise HTTPException(403, "POLICY_ADMIN_REQUIRED")  # Останавливает обработку с HTTP 403 и кодом POLICY_ADMIN_REQUIRED.

    @app.get("/v1/policies/{policy_id}")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def policy_details(policy_id: str, principal=Depends(identity)):  # Возвращает администратору активную политику с ETag.
        require_admin(principal)  # Вызывает require_admin в рамках текущей операции.
        if policy_id != policy_service.id:  # Маршрут работает только с известным профилем MVP.
            raise HTTPException(404, "POLICY_NOT_FOUND")  # Останавливает обработку с HTTP 404 и кодом POLICY_NOT_FOUND.
        policy = policy_service.snapshot()  # Снимок активной политики, не изменяемый ответом модели.
        return JSONResponse(policy.model_dump(), headers={"ETag": policy_etag(policy)})  # Возвращает структурированный результат текущей операции.

    @app.put("/v1/policies/{policy_id}")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def replace_policy(policy_id: str, body: Policy, request: Request, principal=Depends(identity)):  # Меняет существующий профиль при совпадении If-Match.
        require_admin(principal)  # Вызывает require_admin в рамках текущей операции.
        if policy_id != policy_service.id or body.id != policy_id:  # Идентификатор профиля в URL и теле обязан совпасть.
            raise HTTPException(404, "POLICY_NOT_FOUND")  # Останавливает обработку с HTTP 404 и кодом POLICY_NOT_FOUND.
        policy = policy_service.replace(body, request.headers.get("If-Match"), principal)  # Снимок активной политики, не изменяемый ответом модели.
        return JSONResponse(policy.model_dump(), headers={"ETag": policy_etag(policy)})  # Возвращает структурированный результат текущей операции.

    @app.get("/v1/stats")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def statistics(principal=Depends(identity)):  # Считает операционные показатели в пределах полномочий principal.
        if principal.role != "security_reviewer":  # Чтение tenant statistics разрешено только reviewer.
            raise HTTPException(403, "REVIEWER_REQUIRED")  # Останавливает обработку с HTTP 403 и кодом REVIEWER_REQUIRED.
        return store.statistics(principal)  # Возвращает структурированный результат текущей операции.

    def require_session(session_id, principal):  # Проверяет точного владельца сессии и срок действия.
        current = sessions.get(str(session_id))  # Состояние перечитывается для обнаружения гонки или устаревания.
        if not current or current[0] != principal or current[1] < time.time():  # Чужая, отсутствующая и истёкшая сессии недоступны одинаково.
            raise HTTPException(404, "SESSION_NOT_FOUND")  # Останавливает обработку с HTTP 404 и кодом SESSION_NOT_FOUND.
        return current[1]  # Возвращает структурированный результат текущей операции.

    def consume_rate(principal):  # Расходует общий поминутный лимит principal.
        started = time.monotonic()  # Монотонная отметка для измерения времени без влияния перевода часов.
        bucket = requests[(principal.tenant_id, principal.subject_id)]  # Общее окно запросов конкретного principal.
        while bucket and bucket[0] < started - 60:  # Повторяет обработку, пока выполняется bucket and bucket[0] < started - 60.
            bucket.popleft()  # Удаляет устаревшее или больше не используемое значение.
        if len(bucket) >= 30:  # Тридцать запросов в минуту исчерпывают лимит principal.
            raise HTTPException(429, "RATE_LIMIT")  # Останавливает обработку с HTTP 429 и кодом RATE_LIMIT.
        bucket.append(started)  # Добавляет элемент в ограниченное состояние текущего процесса.

    async def evaluate(body, principal, gate=None):  # Объединяет правила, семантику и запреты политики с аудитом.
        started = time.monotonic()  # Монотонная отметка для измерения времени без влияния перевода часов.
        policy = await run_in_threadpool(policy_service.snapshot)  # Снимок активной политики, не изменяемый ответом модели.
        if len(body.text) > 6000:  # Ограничивает размер текста до обращения к локальной модели.
            raise HTTPException(413, "INPUT_TOO_LARGE")  # Останавливает обработку с HTTP 413 и кодом INPUT_TOO_LARGE.
        if not body.text.strip():  # Пробельный текст не считается содержательным запросом.
            raise HTTPException(422, "EMPTY_TEXT")  # Останавливает обработку с HTTP 422 и кодом EMPTY_TEXT.
        require_session(body.session_id, principal)  # Вызывает require_session в рамках текущей операции.
        if body.policy_id != policy.id or principal.role not in policy.roles:  # Проверяет назначение профиля фактической серверной роли.
            raise HTTPException(403, "POLICY_NOT_ASSIGNED")  # Останавливает обработку с HTTP 403 и кодом POLICY_NOT_ASSIGNED.
        consume_rate(principal)  # Вызывает consume_rate в рамках текущей операции.
        rule = rule_signal(body.text)  # Результат детерминированного поиска активной инструкции.
        hard_rule = rule and rule != "UNTRUSTED_ROLE_CLAIM"  # Точное запрещённое действие имеет приоритет над LLM.
        rule_ms = (time.monotonic() - started) * 1000  # Длительность проверок до вызова семантического детектора.
        result, failure = None, None  # До анализа сбрасывает признаки угрозы, результат модели и код отказа.
        status = "skipped_hard_deny"  # Операционный статус компонента для ответа и диагностики.
        llm_started = time.monotonic()  # Начало участка ожидания и вызова детектора.
        history = histories[str(body.session_id)]  # Серверная история; клиент не подменяет предыдущие сообщения.
        incomplete = len(history) >= 4 or sum(len(t) for t in history) + len(body.text) > 6000  # Переполнение известного контекста требует остановки передачи.
        hard_policy = gate and gate[0] == "BLOCK"  # Критический отказ ACL не должен отменяться моделью.
        if incomplete and not hard_rule and not hard_policy:  # При неполном контексте не пытается получить формальный допуск от модели.
            status = "unavailable"  # Операционный статус компонента для ответа и диагностики.
        if not hard_rule and not hard_policy and not incomplete:  # Модель вызывается только при отсутствии точного отказа и полном контексте.
            try:  # Ограничивает участок, где ожидаемый отказ требует отдельной обработки.
                context = json.dumps({"previous_allowed_turns": history, "current_text": body.text}, ensure_ascii=False) if history else body.text  # Предыдущие разрешённые turns передаются только как JSON-контекст.
                result = await detector.analyze(context)  # Результат текущей операции для последующей валидации или ответа.
                status = "ok"  # Операционный статус компонента для ответа и диагностики.
            except DetectorFailure as exc:  # Обрабатывает только указанные ошибки, сохраняя режим остановки при отказе.
                if exc.status == "overloaded":  # Переполнение очереди возвращает явный HTTP 429 вместо нового inference.
                    raise HTTPException(429, "DETECTOR_CAPACITY") from None  # Останавливает обработку с HTTP 429 и кодом DETECTOR_CAPACITY.
                failure = status = exc.status  # Код отказа детектора вместо небезопасного положительного решения.
            app.state.detector_status = status  # Публикует зависимость или операционный статус в состоянии текущего приложения.
        decision, risk, reasons = decide(rule, result, failure)  # Получает согласованное решение, риск и основания проверки.
        current_policy = await run_in_threadpool(policy_service.snapshot)  # Повторный снимок выявляет изменение политики за время inference.
        if hard_policy:  # Детерминированный запрет доступа не должен зависеть от ответа LLM.
            decision, risk, reasons = "BLOCK", "high", [gate[1]]  # Устанавливает BLOCK вместе с риском и основанием этой ветви.
        elif incomplete and not hard_rule:  # Неполный контекст требует REVIEW, если точная атака уже не определена.
            decision, risk, reasons = "REVIEW", "unknown", ["CONTEXT_INCOMPLETE"]  # Устанавливает REVIEW вместе с риском и основанием этой ветви.
        elif gate and gate[0] == "REVIEW" and decision == "ALLOW":  # Семантическая безопасность не отменяет обязательный review политики.
            decision, risk, reasons = "REVIEW", "medium", [gate[1]]  # Устанавливает REVIEW вместе с риском и основанием этой ветви.
        if decision != "BLOCK" and policy_etag(current_policy) != policy_etag(policy):  # Устаревший снимок не может разрешить действие; BLOCK сохраняется.
            decision, risk, reasons = "REVIEW", "unknown", ["POLICY_CHANGED"]  # Устанавливает REVIEW вместе с риском и основанием этой ветви.
        rule_category = {"SYSTEM_EXTRACTION": "system_extraction", "ROLE_SPOOFING": "role_spoofing",  # Связывает код правила с категорией угрозы.
                         "UNTRUSTED_ROLE_CLAIM": "unauthorized_data"}.get(rule, "direct_injection")  # Относит неподтверждённую привилегию к риску доступа без полномочий.
        categories = result.categories if result else ([rule_category] if rule else [])  # Категории берутся из валидированной модели и детерминированных проверок.
        if rule and rule_category not in categories:  # Не теряет категорию детерминированного правила при ответе модели.
            categories = [*categories, rule_category]  # Категории берутся из валидированной модели и детерминированных проверок.
        if hard_policy:  # Детерминированный запрет доступа не должен зависеть от ответа LLM.
            categories = ["unauthorized_data" if gate[1] == "RESOURCE_NOT_FOUND_OR_HIDDEN" else "tool_misuse"]  # Категории берутся из валидированной модели и детерминированных проверок.
        response = {  # Собирает HTTP-ответ или сохранённое решение текущего маршрута.
            "id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),  # UUID события отделяет результат от исходного payload.
            "session_id": str(body.session_id),  # Связывает событие с проверенной сессией.
            "decision": decision, "risk": risk,  # Итоговое решение отделено от факта исполнения.
            "threats": [{"category": c, "severity": risk, "source": "policy" if hard_policy else "rules" if rule else "llm", "rule_id": rule} for c in categories],  # Категории сопровождаются источником и уровнем риска.
            "reason_codes": reasons,  # Машиночитаемые основания объясняют выбор ветви.
            "explanation": {"ALLOW": "Обязательные проверки пройдены.", "BLOCK": "Обнаружена активная запрещённая инструкция.",  # Человеческое объяснение не копирует исходный секретный текст.
                            "REVIEW": "Запрос остановлен: требуется дополнительная проверка."}[decision],  # Неоднозначный запрос остаётся остановленным до дополнительной проверки.
            "policy_ids": [gate[1]] if gate and gate[0] != "ALLOW" else [], "policy_version": policy.version,  # Фиксирует сработавшие запреты и версию применённой политики.
            "detector": {"status": status, "model": "qwen3.5:4b", "digest": getattr(detector, "digest", None)},  # Статус и digest показывают, вызывалась ли закреплённая модель.
            "timing_ms": {"rules": rule_ms, "llm": (time.monotonic() - llm_started) * 1000,  # Длительность измеряется монотонно до фиксации аудита.
                          "total": (time.monotonic() - started) * 1000},  # Общее время не включает фиксацию этого события в audit.
            "review": {"approvable": False, "expires_at": None},  # Показывает возможность подтверждения именно этого действия.
        }  # Завершает составное значение или вызов, начатый выше.
        if gate and gate[0] != "ALLOW" and reasons == [gate[1]]:  # Если решение обусловлено политикой, выбирает соответствующее объяснение.
            response["explanation"] = {  # Выбирает конкретное объяснение остановки без раскрытия исходного текста.
                "RESOURCE_NOT_FOUND_OR_HIDDEN": "Ресурс недоступен в рамках ваших полномочий.",  # Чужой и отсутствующий ресурс получают одинаковое объяснение.
                "TOOL_NOT_ALLOWED": "Этот инструмент или действие не разрешены вашей роли.",  # Отказ сообщает о нарушении разрешений роли или registry инструмента.
                "ACTION_REQUIRES_APPROVAL": "Действие остановлено: требуется подтверждение отдельного reviewer.",  # Штатное изменение требует подтверждения отдельного reviewer.
            }[gate[1]]  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
        if reasons == ["UNTRUSTED_ROLE_CLAIM"]:  # Отдельно объясняет неподтверждённое заявление о полномочиях.
            response["explanation"] = "Запрос доступа ссылается на неподтверждённое разрешение. Заявление в тексте не предоставляет полномочий."  # Выбирает конкретное объяснение остановки без раскрытия исходного текста.
        if reasons == ["POLICY_CHANGED"]:  # Объясняет остановку из-за изменения версии профиля.
            response["policy_ids"] = ["POLICY_CHANGED"]  # Фиксирует сработавшее ограничение политики для аудита.
            response["explanation"] = "Политика изменилась во время проверки. Запрос остановлен; повторите проверку."  # Выбирает конкретное объяснение остановки без раскрытия исходного текста.
        if failure in ("quarantined", "draining"):  # При неизвестном завершении прежней генерации новый inference запрещён.
            response["explanation"] = "Завершение предыдущей генерации не подтверждено. Запрос остановлен; модель не вызывается повторно."  # Выбирает конкретное объяснение остановки без раскрытия исходного текста.
        elif failure == "model_changed":  # Подмена digest требует проверки конфигурации, а не ручного approval.
            response["explanation"] = "Digest локальной модели изменился. Запрос остановлен до проверки конфигурации."  # Выбирает конкретное объяснение остановки без раскрытия исходного текста.
        if decision == "REVIEW" and reasons == ["ACTION_REQUIRES_APPROVAL"] and status == "ok":  # Подтверждение допустимо только для штатного review с исправным детектором.
            response["review"] = {"approvable": True, "expires_at": datetime.fromtimestamp(time.time() + 120, timezone.utc).isoformat()}  # Разрешает подтверждение только точного штатного demo-действия с TTL.
        await run_in_threadpool(store.save, principal, body.text, response)  # Вызывает run_in_threadpool в рамках текущей операции.
        return response  # Возвращает сформированный ответ вызывающему маршруту.

    @app.post("/v1/checks", status_code=201)  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    async def check(body: CheckRequest, principal=Depends(identity)):  # Оценивает проверяемый payload и сохраняет решение до ответа клиенту.
        return await evaluate(body, principal)  # Возвращает структурированный результат текущей операции.

    async def integration_check(body, principal):  # Связывает внешнюю проверку с сессией, лимитом и lock.
        expires = require_session(body.session_id, principal)  # Срок жизни привязки проверяется до и после анализа.
        consume_rate(principal)  # Вызывает consume_rate в рамках текущей операции.
        lock = session_locks[str(body.session_id)]  # Одна блокировка сериализует действия текущей сессии.
        if lock.locked():  # Одновременная операция в той же сессии получает SESSION_BUSY.
            raise HTTPException(409, "SESSION_BUSY")  # Останавливает обработку с HTTP 409 и кодом SESSION_BUSY.
        async with lock:  # Удерживает блокировку на время критического участка.
            return await integration.check(principal, body, expires)  # Возвращает структурированный результат текущей операции.

    @app.post("/v1/tool-checks", status_code=201)  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    async def tool_check(body: ToolCheckRequest, principal=Depends(identity)):  # Проверяет конкретный внешний tool intent без исполнения.
        return await integration_check(body, principal)  # Возвращает структурированный результат текущей операции.

    @app.post("/v1/content-checks", status_code=201)  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    async def content_check(body: ContentCheckRequest, principal=Depends(identity)):  # Оценивает недоверенный tool/RAG-текст без включения в контекст.
        return await integration_check(body, principal)  # Возвращает структурированный результат текущей операции.

    @app.post("/v1/agent/turns")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    async def turn(body: TurnRequest, request: Request, principal=Depends(identity)):  # Останавливает REVIEW/BLOCK и вызывает demo agent только при допуске.
        sid = str(body.session_id)  # Строковое представление UUID сессии.
        current = sessions.get(sid)  # Состояние перечитывается для обнаружения гонки или устаревания.
        if not current or current[0] != principal or current[1] < time.time():  # Чужая, отсутствующая и истёкшая сессии недоступны одинаково.
            raise HTTPException(404, "SESSION_NOT_FOUND")  # Останавливает обработку с HTTP 404 и кодом SESSION_NOT_FOUND.
        lock = session_locks[sid]  # Одна блокировка сериализует действия текущей сессии.
        if lock.locked():  # Одновременная операция в той же сессии получает SESSION_BUSY.
            raise HTTPException(409, "SESSION_BUSY")  # Останавливает обработку с HTTP 409 и кодом SESSION_BUSY.
        async with lock:  # Удерживает блокировку на время критического участка.
            if body.approval_id is not None:  # Продолжение с approval проходит отдельный транзакционный протокол.
                policy = await run_in_threadpool(policy_service.snapshot)  # Снимок активной политики, не изменяемый ответом модели.
                if body.policy_id != policy.id or principal.role not in policy.roles:  # Проверяет назначение профиля фактической серверной роли.
                    raise HTTPException(403, "POLICY_NOT_ASSIGNED")  # Останавливает обработку с HTTP 403 и кодом POLICY_NOT_ASSIGNED.
                result = await run_in_threadpool(approvals.execute, body, principal,  # Результат текущей операции для последующей валидации или ответа.
                                                request.headers.get("Idempotency-Key"), histories[sid])  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
                if not result["execution"]["replayed"]:  # Идемпотентный replay не добавляет turn в историю второй раз.
                    histories[sid].append(body.text)  # Добавляет элемент в ограниченное состояние текущего процесса.
                result["execution"]["tool_invocations"] = 0 if result["execution"]["replayed"] else 1  # Replay не выполняет новую запись.
                if result["execution"]["replayed"]:  # Cached result не должен завышать фактические вызовы этого запроса.
                    result["execution"]["target_invocations"] = 0  # Сохранённый результат возвращён без повторного запуска executor.
                return pipeline_reply(result["check"], result["execution"])  # Подтверждённая запись также получает фактическую трассу.
            intent = plan(body.text)  # Конкретный инструмент и ресурс, извлечённые из команды.
            gate = await run_in_threadpool(agent.preflight, principal, intent)  # Детерминированный результат проверки фактического инструмента.
            result = await evaluate(body, principal, gate)  # Результат текущей операции для последующей валидации или ответа.
            if result["review"]["approvable"]:  # Только штатное подтверждаемое действие сохраняется в pending.
                await run_in_threadpool(approvals.remember, body, principal, result, histories[sid])  # Вызывает run_in_threadpool в рамках текущей операции.
            reply = await pipeline.run(body, principal, result, current[1])  # Передаёт результат только после всех применимых gates.
            if reply["execution"]["status"] == "completed":  # Заблокированный tool output не попадает в разрешённую историю.
                histories[sid].append(body.text)  # История фиксирует только успешно завершённый turn.
            return reply  # Содержит исходную проверку, итоговое решение и фактическую трассу.

    @app.post("/v1/reviews/{check_id}/approve", status_code=201)  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def approve(check_id: str, body: StrictModel, principal=Depends(identity)):  # Выдаёт одноразовое подтверждение после повторной проверки условий.
        return approvals.approve(check_id, principal)  # Возвращает структурированный результат текущей операции.

    @app.get("/v1/reviews/{check_id}")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def review_details(check_id: str, principal=Depends(identity)):  # Показывает reviewer привязку точного отложенного действия.
        return approvals.describe(check_id, principal)  # Возвращает структурированный результат текущей операции.

    @app.get("/v1/checks")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def history(limit: int = Query(20, ge=1, le=100), principal=Depends(identity)):  # Читает ограниченную правами историю проверок.
        return {"items": store.list(principal, limit), "next_cursor": None}  # Возвращает структурированный результат текущей операции.

    @app.get("/v1/checks/{event_id}")  # Регистрирует маршрут или обработчик в текущем экземпляре API.
    def event(event_id: str, principal=Depends(identity)):  # Возвращает собственное событие или доступный reviewer аудит.
        result = store.get(principal, event_id)  # Результат текущей операции для последующей валидации или ответа.
        if result is None:  # Чужой и отсутствующий event не раскрываются через различие ошибок.
            raise HTTPException(404, "CHECK_NOT_FOUND")  # Останавливает обработку с HTTP 404 и кодом CHECK_NOT_FOUND.
        return result  # Возвращает вычисленный результат текущей операции.

    return app  # Возвращает настроенное приложение для ASGI launcher.
