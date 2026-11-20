import hashlib  # SHA-256 для digest конфигурации и привязок.
from datetime import datetime, timezone  # UTC-время событий и сроки действия данных.
from uuid import uuid4  # Случайные идентификаторы сессий, событий и операций.

from fastapi import HTTPException  # HTTP-контракты, ответы и безопасное выполнение синхронных операций.
from pydantic import ValidationError  # Строгая валидация входных данных и структурированного output.

from .engines import Policy, load_policy  # Подключает engines для текущего компонента.


def policy_etag(policy):  # Строит сильный ETag из полного JSON активной политики.
    return '"' + hashlib.sha256(policy.model_dump_json().encode()).hexdigest() + '"'  # Возвращает структурированный результат текущей операции.


class PolicyService:  # Управление seed, снимками и неизменяемыми версиями политики.
    id = "strict-demo-v1"  # Сохраняет id для следующей проверки в этой ветви.

    def __init__(self, store, seed_path):  # Настраивает зависимости компонента.
        self.store = store  # Единое хранилище транзакций и журнала этого приложения.
        existing = store.policy_config(self.id, allow_legacy=True)  # Существующее сохранённое состояние имеет приоритет над seed.
        seed = Policy.model_validate_json(existing) if existing else load_policy(seed_path)  # Начальные данные используются только при необходимости инициализации.
        store.seed_policy(seed)  # Вызывает store.seed_policy в рамках текущей операции.
        self.snapshot()  # Вызывает self.snapshot в рамках текущей операции.

    def snapshot(self, db=None):  # Читает валидированное актуальное состояние для текущей проверки.
        raw = self.store.policy_config(self.id, db)  # Исходные данные приводятся к явному сериализованному представлению.
        if raw is None:  # Отсутствие активной политики приводит к отказу, а не permissive default.
            raise HTTPException(503, "POLICY_UNAVAILABLE")  # Останавливает обработку с HTTP 503 и кодом POLICY_UNAVAILABLE.
        try:  # Ограничивает участок, где ожидаемый отказ требует отдельной обработки.
            return Policy.model_validate_json(raw)  # Возвращает структурированный результат текущей операции.
        except ValidationError:  # Обрабатывает только указанные ошибки, сохраняя режим остановки при отказе.
            raise HTTPException(503, "POLICY_UNAVAILABLE") from None  # Останавливает обработку с HTTP 503 и кодом POLICY_UNAVAILABLE.

    def replace(self, candidate, expected, principal):  # Атомарно активирует следующую версию политики вместе с аудитом.
        if principal.role != "policy_admin":  # Управление политикой требует отдельной серверной роли администратора.
            raise HTTPException(403, "POLICY_ADMIN_REQUIRED")  # Останавливает обработку с HTTP 403 и кодом POLICY_ADMIN_REQUIRED.
        if expected is None:  # Для изменения политики необходим явный If-Match.
            raise HTTPException(428, "IF_MATCH_REQUIRED")  # Останавливает обработку с HTTP 428 и кодом IF_MATCH_REQUIRED.
        with self.store.connect() as db:  # Соединение обеспечивает commit при успехе и rollback при исключении.
            db.execute("BEGIN IMMEDIATE")  # Резервирует транзакцию записи до повторной проверки условий.
            current = self.snapshot(db)  # Состояние перечитывается для обнаружения гонки или устаревания.
            if expected != policy_etag(current) or candidate.version != current.version:  # Устаревший If-Match или base version не должен затереть чужое изменение.
                raise HTTPException(412, "POLICY_VERSION_CONFLICT")  # Останавливает обработку с HTTP 412 и кодом POLICY_VERSION_CONFLICT.
            updated = Policy.model_validate(candidate.model_dump() | {"version": current.version + 1})  # Следующая версия создаётся отдельно от предыдущей.
            db.execute("INSERT INTO policies VALUES (?,?,?)", (updated.id, updated.version, updated.model_dump_json()))  # Записывает новую привязку или событие в текущей транзакции.
            db.execute("INSERT INTO policy_metadata VALUES (?,?,?,?,?)", (updated.id, updated.version,  # Записывает новую привязку или событие в текущей транзакции.
                       datetime.now(timezone.utc).isoformat(), principal.subject_id, policy_etag(updated).strip('"')))  # Параметры берутся из серверной identity, без доверия к body.
            db.execute("UPDATE active_policies SET version=? WHERE id=?", (updated.version, updated.id))  # Изменяет состояние только после проверок текущей транзакции.
            self.store.insert(db, principal, updated.model_dump_json(), {  # Аудит обязателен до выдачи положительного результата или изменения ресурса.
                "id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),  # UUID события отделяет результат от исходного payload.
                "event_type": "policy_update", "decision": "ALLOW", "risk": "low",  # Разделяет проверку, исполнение и административные события аудита.
                "reason_codes": ["POLICY_UPDATED"], "policy_version": updated.version,  # Машиночитаемые основания объясняют выбор ветви.
                "previous_version": current.version, "policy_ids": [updated.id],  # Поле previous_version входит в структурированный контракт текущего результата.
            })  # Завершает составное значение или вызов, начатый выше.
        return updated  # Возвращает новую активную версию политики.
