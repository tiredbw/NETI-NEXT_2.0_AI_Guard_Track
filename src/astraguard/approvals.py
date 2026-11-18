import hashlib  # SHA-256 для digest конфигурации и привязок.
import hmac  # Привязка запроса к секретному ключу без хранения исходного текста.
import json  # Сериализация контрактов и разбор структурированных ответов.
import time  # TTL объектов и монотонное измерение длительности.
from datetime import datetime, timezone  # UTC-время событий и сроки действия данных.
from uuid import uuid4  # Случайные идентификаторы сессий, событий и операций.

from fastapi import HTTPException  # HTTP-контракты, ответы и безопасное выполнение синхронных операций.

from .demo import plan, tool_policy  # Подключает demo для текущего компонента.


class ApprovalService:  # Протокол двух участников и однократного demo-исполнения.
    def __init__(self, store, policies, agent):  # Настраивает зависимости компонента.
        self.store, self.policies, self.agent = store, policies, agent  # Сохраняет общие зависимости компонента для последующих проверок.
        self.pending = {}  # Точные неподтверждённые payload хранятся только в RAM с TTL.

    @property  # Предоставляет чтение вычисляемого состояния без присваивания.
    def policy(self):  # Возвращает отделённый от БД снимок текущей политики.
        return self.policies.snapshot()  # Возвращает структурированный результат текущей операции.

    def binding(self, body):  # Вычисляет HMAC точного текста, сессии и policy_id.
        raw = json.dumps({"text": body.text, "session_id": str(body.session_id), "policy_id": body.policy_id},  # Исходные данные приводятся к явному сериализованному представлению.
                         sort_keys=True, ensure_ascii=False)  # Сериализация сохраняет Unicode и заданный порядок полей для привязки.
        return hmac.new(self.store.key, raw.encode(), hashlib.sha256).hexdigest()  # Возвращает структурированный результат текущей операции.

    def policy_hash(self, db=None):  # Привязывает approval к полному содержимому активной политики.
        return hashlib.sha256(self.policies.snapshot(db).model_dump_json().encode()).hexdigest()  # Возвращает структурированный результат текущей операции.

    def remember(self, body, principal, check, history):  # Держит точное подтверждаемое действие в RAM не дольше TTL.
        now = time.time()  # Текущее время для проверки срока действия.
        self.pending = {k: v for k, v in self.pending.items() if v["expires"] > now}  # Точные неподтверждённые payload хранятся только в RAM с TTL.
        if len(self.pending) >= 1000:  # Ограничивает число незавершённых подтверждаемых действий в RAM.
            raise HTTPException(429, "PENDING_CAPACITY")  # Останавливает обработку с HTTP 429 и кодом PENDING_CAPACITY.
        intent = plan(body.text)  # Конкретный инструмент и ресурс, извлечённые из команды.
        with self.store.connect() as db:  # Соединение обеспечивает commit при успехе и rollback при исключении.
            policy = self.policies.snapshot(db)  # Снимок активной политики, не изменяемый ответом модели.
            if check["policy_version"] != policy.version:  # После исходной проверки политика успела измениться.
                raise HTTPException(409, "POLICY_CHANGED")  # Останавливает обработку с HTTP 409 и кодом POLICY_CHANGED.
            if tool_policy(db, policy, principal, intent)[0] != "REVIEW":  # Отложенное действие должно оставаться разрешённым только через review.
                raise HTTPException(409, "RESOURCE_CHANGED")  # Останавливает обработку с HTTP 409 и кодом RESOURCE_CHANGED.
            version = db.execute("SELECT version FROM resources WHERE id=?", (intent.resource_id,)).fetchone()[0]  # Версия сервера или ресурса проверяется отдельно от содержимого.
            policy_hash = self.policy_hash(db)  # Хеш полного профиля делает approval чувствительным к изменению политики.
        self.pending[check["id"]] = {"body": body, "principal": principal, "check": check,  # В RAM связывает точный payload, identity, версию ресурса, policy hash и историю.
                                      "version": version, "hash": policy_hash, "expires": now + 120,  # Поле version входит в структурированный контракт текущего результата.
                                      "history": list(history)}  # Поле history входит в структурированный контракт текущего результата.

    def approve(self, check_id, reviewer):  # Выдаёт одноразовое подтверждение после повторной проверки условий.
        self.describe(check_id, reviewer)  # Вызывает self.describe в рамках текущей операции.
        pending = self.pending[check_id]  # Точное отложенное действие должно оставаться в RAM до исполнения.
        approval_id = str(uuid4())  # Случайный UUID идентифицирует одноразовый approval.
        with self.store.connect() as db:  # Соединение обеспечивает commit при успехе и rollback при исключении.
            db.execute("BEGIN IMMEDIATE")  # Резервирует транзакцию записи до повторной проверки условий.
            if pending["hash"] != self.policy_hash(db) or pending["expires"] <= time.time():  # Перед выдачей approval повторно сверяет политику и TTL в транзакции.
                raise HTTPException(409, "REVIEW_EXPIRED_OR_CHANGED")  # Останавливает обработку с HTTP 409 и кодом REVIEW_EXPIRED_OR_CHANGED.
            intent = plan(pending["body"].text)  # Конкретный инструмент и ресурс, извлечённые из команды.
            if tool_policy(db, self.policies.snapshot(db), pending["principal"], intent)[0] != "REVIEW":  # Актуальный ACL повторно проверяется от имени исходного requester.
                raise HTTPException(409, "ACTION_NO_LONGER_PERMITTED")  # Останавливает обработку с HTTP 409 и кодом ACTION_NO_LONGER_PERMITTED.
            if db.execute("SELECT version FROM resources WHERE id=?", (intent.resource_id,)).fetchone()[0] != pending["version"]:  # Повторно проверяет версию ресурса перед выдачей подтверждения.
                raise HTTPException(409, "RESOURCE_CHANGED")  # Останавливает обработку с HTTP 409 и кодом RESOURCE_CHANGED.
            if db.execute("SELECT 1 FROM approvals WHERE check_id=?", (check_id,)).fetchone():  # Для одного исходного review нельзя выдать два независимых approval.
                raise HTTPException(409, "ALREADY_APPROVED")  # Останавливает обработку с HTTP 409 и кодом ALREADY_APPROVED.
            db.execute("INSERT INTO approvals(id,check_id,tenant,requester,reviewer,binding,policy_hash,resource_version,expires) VALUES (?,?,?,?,?,?,?,?,?)",  # Записывает новую привязку или событие в текущей транзакции.
                       (approval_id, check_id, reviewer.tenant_id, pending["principal"].subject_id, reviewer.subject_id,  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
                        self.binding(pending["body"]), pending["hash"], pending["version"], pending["expires"]))  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
            self.store.insert(db, reviewer, check_id, {"id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),  # Аудит обязателен до выдачи положительного результата или изменения ресурса.
                "event_type": "approval_granted", "parent_id": check_id, "decision": "REVIEW", "risk": "medium",  # Разделяет проверку, исполнение и административные события аудита.
                "reason_codes": ["ACTION_REQUIRES_APPROVAL"], "policy_version": pending["check"]["policy_version"]})  # Машиночитаемые основания объясняют выбор ветви.
        return {"approval_id": approval_id, "expires_at": datetime.fromtimestamp(pending["expires"], timezone.utc).isoformat()}  # Возвращает структурированный результат текущей операции.

    def describe(self, check_id, reviewer):  # Проверяет reviewer и показывает безопасное описание действия.
        if reviewer.role != "security_reviewer":  # Выдавать подтверждение может только серверный reviewer.
            raise HTTPException(403, "REVIEWER_REQUIRED")  # Останавливает обработку с HTTP 403 и кодом REVIEWER_REQUIRED.
        pending = self.pending.get(check_id)  # Точное отложенное действие должно оставаться в RAM до исполнения.
        if not pending or pending["principal"].tenant_id != reviewer.tenant_id:  # Reviewer не видит отсутствующие и чужие отложенные действия.
            raise HTTPException(404, "REVIEW_NOT_FOUND")  # Останавливает обработку с HTTP 404 и кодом REVIEW_NOT_FOUND.
        if pending["principal"].subject_id == reviewer.subject_id:  # Инициатор не может подтвердить собственное действие.
            raise HTTPException(403, "SELF_APPROVAL_FORBIDDEN")  # Останавливает обработку с HTTP 403 и кодом SELF_APPROVAL_FORBIDDEN.
        if pending["expires"] <= time.time() or pending["hash"] != self.policy_hash():  # Истёкшее review или изменившийся профиль требуют новой проверки.
            raise HTTPException(409, "REVIEW_EXPIRED_OR_CHANGED")  # Останавливает обработку с HTTP 409 и кодом REVIEW_EXPIRED_OR_CHANGED.
        intent = plan(pending["body"].text)  # Конкретный инструмент и ресурс, извлечённые из команды.
        return {"check_id": check_id, "requester_id": pending["principal"].subject_id,  # Возвращает структурированный результат текущей операции.
                "tool": intent.tool, "resource_id": intent.resource_id, "resource_version": pending["version"],  # Поле tool входит в структурированный контракт текущего результата.
                "content_length": len(intent.content), "binding_hmac": self.binding(pending["body"]),  # Поле content_length входит в структурированный контракт текущего результата.
                "expires_at": datetime.fromtimestamp(pending["expires"], timezone.utc).isoformat()}  # Поле expires_at входит в структурированный контракт текущего результата.

    def execute(self, body, principal, key, history):  # В одной транзакции проверяет approval, меняет ресурс и сохраняет replay.
        if not key or not 8 <= len(key) <= 128:  # Изменяющему действию необходим корректный ключ идемпотентности.
            raise HTTPException(400, "IDEMPOTENCY_KEY_REQUIRED")  # Останавливает обработку с HTTP 400 и кодом IDEMPOTENCY_KEY_REQUIRED.
        binding = self.binding(body)  # HMAC связывает точное действие с подтверждением.
        with self.store.connect() as db:  # Соединение обеспечивает commit при успехе и rollback при исключении.
            db.execute("BEGIN IMMEDIATE")  # Резервирует транзакцию записи до повторной проверки условий.
            db.execute("DELETE FROM executions WHERE expires < ?", (time.time(),))  # Удаляет только записи, подходящие под условия SQL и параметры.
            cached = db.execute("SELECT binding,result FROM executions WHERE tenant=? AND requester=? AND key=?",  # Сохранённый результат ищется только в области tenant/subject/key.
                                (principal.tenant_id, principal.subject_id, key)).fetchone()  # SQL-параметры ограничивают выборку проверяемым владельцем или ресурсом.
            if cached:  # Сначала обрабатывает идемпотентный повтор уже завершённой записи.
                if not hmac.compare_digest(cached[0], binding + str(body.approval_id)):  # Повтор с тем же ключом, но иным действием или approval запрещён.
                    raise HTTPException(409, "IDEMPOTENCY_CONFLICT")  # Останавливает обработку с HTTP 409 и кодом IDEMPOTENCY_CONFLICT.
                result = json.loads(cached[1])  # Результат текущей операции для последующей валидации или ответа.
                result["execution"]["replayed"] = True  # Сохраняет result['execution']['replayed'] для следующей проверки в этой ветви.
                return result  # Возвращает вычисленный результат текущей операции.
            row = db.execute("SELECT check_id,tenant,requester,binding,policy_hash,resource_version,expires,consumed FROM approvals WHERE id=?",  # Читает одну запись для проверки доступа или версии.
                             (str(body.approval_id),)).fetchone()  # SQL-параметры ограничивают выборку проверяемым владельцем или ресурсом.
            if not row or row[1:3] != (principal.tenant_id, principal.subject_id):  # Approval доступен только его исходному requester в нужном tenant.
                raise HTTPException(409, "APPROVAL_UNAVAILABLE")  # Останавливает обработку с HTTP 409 и кодом APPROVAL_UNAVAILABLE.
            check_id, _, _, expected, policy_hash, version, expires, consumed = row  # Извлекает сохранённые привязки, срок действия и признак использования approval.
            pending = self.pending.get(check_id)  # Точное отложенное действие должно оставаться в RAM до исполнения.
            if consumed or expires <= time.time() or not pending:  # Использованное, истёкшее или утраченное approval неприменимо.
                raise HTTPException(409, "APPROVAL_EXPIRED_OR_USED")  # Останавливает обработку с HTTP 409 и кодом APPROVAL_EXPIRED_OR_USED.
            if pending["history"] != history:  # Старое подтверждение неприменимо к изменившемуся контексту сессии.
                raise HTTPException(409, "SESSION_CONTEXT_CHANGED")  # Останавливает обработку с HTTP 409 и кодом SESSION_CONTEXT_CHANGED.
            policy = self.policies.snapshot(db)  # Снимок активной политики, не изменяемый ответом модели.
            if not hmac.compare_digest(expected, binding) or policy_hash != self.policy_hash(db):  # Подтверждение не переносится на другой payload или профиль.
                raise HTTPException(409, "APPROVAL_MISMATCH")  # Останавливает обработку с HTTP 409 и кодом APPROVAL_MISMATCH.
            intent = plan(body.text)  # Конкретный инструмент и ресурс, извлечённые из команды.
            if intent is None or intent.tool != "drafts.update" or tool_policy(db, policy, principal, intent) != ("REVIEW", "ACTION_REQUIRES_APPROVAL"):  # Исполнению подлежит только всё ещё разрешённое подтверждаемое изменение.
                raise HTTPException(409, "ACTION_NO_LONGER_PERMITTED")  # Останавливает обработку с HTTP 409 и кодом ACTION_NO_LONGER_PERMITTED.
            current = db.execute("SELECT version FROM resources WHERE id=?", (intent.resource_id,)).fetchone()[0]  # Состояние перечитывается для обнаружения гонки или устаревания.
            if current != version:  # Ресурс изменился после привязки подтверждения.
                raise HTTPException(409, "RESOURCE_CHANGED")  # Останавливает обработку с HTTP 409 и кодом RESOURCE_CHANGED.
            check = dict(pending["check"])  # Новый результат не перезаписывает исходную проверку.
            check.update(id=str(uuid4()), created_at=datetime.now(timezone.utc).isoformat(), decision="ALLOW", risk="low",  # Дополняет результат текущей операции согласованными полями.
                         reason_codes=["BENIGN_REQUEST"], explanation="Действие подтверждено отдельным reviewer и повторно авторизовано.",  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
                         approved_check_id=check_id, policy_ids=[], review={"approvable": False, "expires_at": None})  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
            self.store.insert(db, principal, body.text, check)  # Аудит обязателен до выдачи положительного результата или изменения ресурса.
            db.execute("UPDATE resources SET content=?,version=version+1 WHERE id=?", (intent.content, intent.resource_id))  # Изменяет состояние только после проверок текущей транзакции.
            db.execute("UPDATE approvals SET consumed=1 WHERE id=?", (str(body.approval_id),))  # Изменяет состояние только после проверок текущей транзакции.
            execution = {"status": "completed", "forwarded": True, "agent_invocation_id": str(uuid4()),  # Описывает факт исполнения отдельно от результата классификации.
                         "target_invocations": 1, "replayed": False,  # Поле target_invocations входит в структурированный контракт текущего результата.
                         "result": {"adapter": "deterministic-demo", "updated": True}}  # Выдаёт только разрешённый результат демонстрационного действия.
            result = {"check": check, "execution": execution}  # Результат текущей операции для последующей валидации или ответа.
            db.execute("INSERT INTO executions VALUES (?,?,?,?,?,?)", (principal.tenant_id, principal.subject_id, key,  # Записывает новую привязку или событие в текущей транзакции.
                       binding + str(body.approval_id), json.dumps(result), time.time() + 86400))  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
        self.agent.invocations += 1  # Обновляет self.agent.invocations с учётом выполненной операции.
        return result  # Возвращает вычисленный результат текущей операции.
