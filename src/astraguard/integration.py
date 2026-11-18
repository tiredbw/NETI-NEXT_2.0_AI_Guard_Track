import json  # Сериализация контрактов и разбор структурированных ответов.
import time  # TTL объектов и монотонное измерение длительности.
from datetime import datetime, timezone  # UTC-время событий и сроки действия данных.
from uuid import uuid4  # Случайные идентификаторы сессий, событий и операций.

from fastapi import HTTPException  # HTTP-контракты, ответы и безопасное выполнение синхронных операций.
from starlette.concurrency import run_in_threadpool  # HTTP-контракты, ответы и безопасное выполнение синхронных операций.

from .demo import ToolIntent, tool_policy  # Подключает demo для текущего компонента.
from .engines import DetectorFailure, decide, rule_signal  # Подключает engines для текущего компонента.


class IntegrationChecks:  # Advisory проверки внешнего агента с повторным ACL и аудитом.
    def __init__(self, store, policies, detector):  # Настраивает зависимости компонента.
        self.store, self.policies, self.detector = store, policies, detector  # Сохраняет общие зависимости компонента для последующих проверок.

    def inspect(self, db, principal, body, expires):  # Проверяет владельца, родительский ALLOW, актуальную политику и ресурс.
        if expires < time.time():  # Повторно проверяет срок сессии после ожидания или inference.
            raise HTTPException(404, "SESSION_NOT_FOUND")  # Останавливает обработку с HTTP 404 и кодом SESSION_NOT_FOUND.
        # Reviewer читает аудит tenant, но не может действовать от имени владельца чужого события.
        row = db.execute("SELECT result FROM events WHERE id=? AND tenant=? AND subject=?",  # Читает одну запись для проверки доступа или версии.
                         (str(body.parent_check_id), principal.tenant_id, principal.subject_id)).fetchone()  # SQL-параметры ограничивают выборку проверяемым владельцем или ресурсом.
        if not row:  # Отсутствующая доступная запись не даёт продолжить операцию.
            raise HTTPException(404, "PARENT_CHECK_NOT_FOUND")  # Останавливает обработку с HTTP 404 и кодом PARENT_CHECK_NOT_FOUND.
        parent = json.loads(row[0])  # Вызывает json.loads в рамках текущей операции.
        if (parent.get("session_id") != str(body.session_id)  # Родитель обязан быть исходным ALLOW запроса в той же сессии.
                or parent.get("event_type", "request_check") != "request_check"  # Дополнительное нарушение также останавливает допуск по этому условию.
                or parent.get("approved_check_id") or parent.get("decision") != "ALLOW"):  # Дополнительное нарушение также останавливает допуск по этому условию.
            raise HTTPException(409, "PARENT_CHECK_NOT_ALLOWED")  # Останавливает обработку с HTTP 409 и кодом PARENT_CHECK_NOT_ALLOWED.
        policy = self.policies.snapshot(db)  # Снимок активной политики, не изменяемый ответом модели.
        if principal.role not in policy.roles:  # Текущей роли должен быть назначен действующий профиль.
            raise HTTPException(403, "POLICY_NOT_ASSIGNED")  # Останавливает обработку с HTTP 403 и кодом POLICY_NOT_ASSIGNED.
        if hasattr(body, "tool"):  # Для tool intent дополнительно проверяет registry и конкретный ресурс.
            args = body.arguments  # Использует уже валидированные аргументы выбранного инструмента.
            intent = ToolIntent(body.tool, args.get("document_id", args.get("draft_id", "")), args.get("content"))  # Конкретный инструмент и ресурс, извлечённые из команды.
            gate = tool_policy(db, policy, principal, intent)  # Детерминированный результат проверки фактического инструмента.
            if gate[0] == "BLOCK":  # Критический ACL-запрет имеет приоритет над оценкой семантики.
                return policy, gate  # Возвращает структурированный результат текущей операции.
            if parent.get("policy_version") != policy.version:  # Родительский ALLOW устарел и больше не разрешает передачу.
                return policy, ("REVIEW", "POLICY_CHANGED")  # Возвращает структурированный результат текущей операции.
            return policy, gate  # Возвращает структурированный результат текущей операции.
        if parent.get("policy_version") != policy.version:  # Родительский ALLOW устарел и больше не разрешает передачу.
            return policy, ("REVIEW", "POLICY_CHANGED")  # Возвращает структурированный результат текущей операции.
        return policy, ("ALLOW", "BENIGN_REQUEST")  # Возвращает структурированный результат текущей операции.

    def snapshot(self, principal, body, expires):  # Читает валидированное актуальное состояние для текущей проверки.
        with self.store.connect() as db:  # Соединение обеспечивает commit при успехе и rollback при исключении.
            return self.inspect(db, principal, body, expires)  # Возвращает структурированный результат текущей операции.

    async def check(self, principal, body, expires):  # Оценивает проверяемый payload и сохраняет решение до ответа клиенту.
        started = time.monotonic()  # Монотонная отметка для измерения времени без влияния перевода часов.
        policy, gate = await run_in_threadpool(self.snapshot, principal, body, expires)  # Получает снимок политики вместе с детерминированным решением ACL.
        is_tool = hasattr(body, "tool")  # Различает typed tool intent и проверку внешнего текста.
        text = body.arguments.get("content") if is_tool else body.text  # Рабочее представление текста текущей проверки.
        signal, result, failure = None, None, None  # До анализа сбрасывает признаки угрозы, результат модели и код отказа.
        status = "skipped_deterministic"  # Операционный статус компонента для ответа и диагностики.
        if gate[0] == "BLOCK":  # Критический ACL-запрет имеет приоритет над оценкой семантики.
            status = "skipped_hard_deny"  # Операционный статус компонента для ответа и диагностики.
        elif gate[1] != "POLICY_CHANGED" and text is not None:  # Проверяет свободный текст только при пригодной версии родительской политики.
            if not text.strip():  # Пустой после удаления пробелов контент отклоняется.
                raise HTTPException(422, "EMPTY_TEXT")  # Останавливает обработку с HTTP 422 и кодом EMPTY_TEXT.
            signal = rule_signal(text)  # Признак активной атаки сохраняется отдельно от результата модели.
            if signal and signal != "UNTRUSTED_ROLE_CLAIM":  # Точная активная атака не требует дополнительного inference.
                status = "skipped_hard_deny"  # Операционный статус компонента для ответа и диагностики.
            else:  # Обрабатывает альтернативную ветвь, если предыдущее условие ложно.
                try:  # Ограничивает участок, где ожидаемый отказ требует отдельной обработки.
                    # Метка источника остаётся недоверенными данными и не становится ролью сообщения.
                    result = await self.detector.analyze(json.dumps({  # Результат текущей операции для последующей валидации или ответа.
                        "untrusted_source": "tool_arguments" if is_tool else body.source,  # Источник остаётся недоверенным независимо от имени tool или документа.
                        "current_text": text}, ensure_ascii=False))  # Передаёт проверяемый текст внутри JSON-данных, не в привилегированной роли.
                    status = "ok"  # Операционный статус компонента для ответа и диагностики.
                except DetectorFailure as exc:  # Обрабатывает только указанные ошибки, сохраняя режим остановки при отказе.
                    if exc.status == "overloaded":  # Переполнение очереди возвращает явный HTTP 429 вместо нового inference.
                        raise HTTPException(429, "DETECTOR_CAPACITY") from None  # Останавливает обработку с HTTP 429 и кодом DETECTOR_CAPACITY.
                    failure = status = exc.status  # Код отказа детектора вместо небезопасного положительного решения.
        decision, risk, reasons = decide(signal, result, failure) if text is not None else ("ALLOW", "low", ["BENIGN_REQUEST"])  # Получает согласованное решение, риск и основания проверки.
        if gate[0] == "BLOCK":  # Критический ACL-запрет имеет приоритет над оценкой семантики.
            decision, risk, reasons = "BLOCK", "high", [gate[1]]  # Устанавливает BLOCK вместе с риском и основанием этой ветви.
        elif gate[0] == "REVIEW" and (decision == "ALLOW" or gate[1] == "POLICY_CHANGED"):  # Учитывает обязательное подтверждение или устаревание политики.
            decision, risk, reasons = "REVIEW", "medium", [gate[1]]  # Устанавливает REVIEW вместе с риском и основанием этой ветви.
        event = {  # Событие аудита не копирует исходный пользовательский payload.
            "id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),  # UUID события отделяет результат от исходного payload.
            "session_id": str(body.session_id), "parent_id": str(body.parent_check_id),  # Связывает событие с проверенной сессией.
            "event_type": "tool_check" if is_tool else "content_check",  # Разделяет проверку, исполнение и административные события аудита.
            "decision": decision, "risk": risk, "reason_codes": reasons,  # Итоговое решение отделено от факта исполнения.
            "policy_ids": [], "policy_version": policy.version,  # Фиксирует сработавшие запреты и версию применённой политики.
            "threats": [{"category": category, "severity": risk, "source": "llm", "rule_id": None}  # Категории сопровождаются источником и уровнем риска.
                        for category in (result.categories if result else [])],  # Для каждой валидированной категории формирует отдельный элемент угрозы.
            "detector": {"status": status, "model": "qwen3.5:4b" if text is not None else None,  # Статус и digest показывают, вызывалась ли закреплённая модель.
                         "digest": getattr(self.detector, "digest", None) if text is not None else None},  # Digest позволяет связать решение с конкретной локальной моделью.
            "review": {"approvable": False, "expires_at": None},  # Показывает возможность подтверждения именно этого действия.
            "forwarded": False,  # Факт передачи учитывается отдельно от допуска.
        }  # Завершает составное значение или вызов, начатый выше.
        if is_tool:  # Tool и content events сохраняют разные безопасные метаданные.
            event["tool"] = body.tool if body.tool in ("documents.read", "drafts.update") else "unknown"  # Журналирует только известный tool; неизвестное имя заменяет на unknown.
        else:  # Обрабатывает альтернативную ветвь, если предыдущее условие ложно.
            event["source"] = body.source  # Сохраняет допустимую метку недоверенного источника без повышения доверия.
        if signal:  # Найденный признак правила дополняет объяснение категории угрозы.
            category = {"SYSTEM_EXTRACTION": "system_extraction", "ROLE_SPOOFING": "role_spoofing",  # Вызывает {'SYSTEM_EXTRACTION': 'system_extraction', 'ROLE_SPOOFING': 'role_spoofing', 'UNTRUSTED_ROLE_CLAIM': 'unauthorized_data'}.get в рамках текущей операции.
                        "UNTRUSTED_ROLE_CLAIM": "unauthorized_data"}.get(signal, "direct_injection")  # Относит неподтверждённую привилегию к риску доступа без полномочий.
            event["threats"].append({"category": category, "severity": risk, "source": "rules", "rule_id": signal})  # Добавляет элемент в ограниченное состояние текущего процесса.
        return await run_in_threadpool(self.persist, principal, body, expires, event, started)  # Возвращает структурированный результат текущей операции.

    def persist(self, principal, body, expires, event, started):  # Повторяет проверки и атомарно сохраняет дочернее решение.
        with self.store.connect() as db:  # Соединение обеспечивает commit при успехе и rollback при исключении.
            db.execute("BEGIN IMMEDIATE")  # Резервирует транзакцию записи до повторной проверки условий.
            policy, gate = self.inspect(db, principal, body, expires)  # Получает снимок политики вместе с детерминированным решением ACL.
            if gate[0] == "BLOCK":  # Критический ACL-запрет имеет приоритет над оценкой семантики.
                event.update(decision="BLOCK", risk="high", reason_codes=[gate[1]])  # Дополняет результат текущей операции согласованными полями.
            elif event["decision"] != "BLOCK" and (gate[1] == "POLICY_CHANGED" or policy.version != event["policy_version"]):  # Изменение политики останавливает прежний допуск, но не снимает BLOCK.
                event.update(decision="REVIEW", risk="unknown", reason_codes=["POLICY_CHANGED"])  # Дополняет результат текущей операции согласованными полями.
            if gate[0] == "BLOCK":  # Критический ACL-запрет имеет приоритет над оценкой семантики.
                category = "unauthorized_data" if gate[1] == "RESOURCE_NOT_FOUND_OR_HIDDEN" else "tool_misuse"  # Сохраняет category для следующей проверки в этой ветви.
                event["threats"] = [{"category": category, "severity": "high", "source": "policy", "rule_id": gate[1]}]  # Перечисляет угрозы фактического ACL-отказа вместо прежнего benign output.
            event["policy_version"] = policy.version  # Привязывает итог к актуальной версии политики.
            event["policy_ids"] = [code for code in event["reason_codes"] if code in (  # Фиксирует сработавшее ограничение политики для аудита.
                "POLICY_CHANGED", "TOOL_NOT_ALLOWED", "RESOURCE_NOT_FOUND_OR_HIDDEN", "ACTION_REQUIRES_APPROVAL")]  # Коды различают штатное approval, спорную привилегию и неоднозначную семантику.
            event["explanation"] = {  # Выбирает конкретное объяснение остановки без раскрытия исходного текста.
                "ALLOW": "Проверка пройдена. Это оценка, исполнение не выполнялось.",  # Поле ALLOW входит в структурированный контракт текущего результата.
                "REVIEW": "Передача остановлена: требуется новая проверка или отдельный протокол подтверждения.",  # Неоднозначный запрос остаётся остановленным до дополнительной проверки.
                "BLOCK": "Передача запрещена: обнаружена опасная инструкция или нарушена политика доступа.",  # Поле BLOCK входит в структурированный контракт текущего результата.
            }[event["decision"]]  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
            event["timing_ms"] = {"total": (time.monotonic() - started) * 1000}  # Сохраняет event['timing_ms'] для следующей проверки в этой ветви.
            self.store.insert(db, principal, body.model_dump_json(), event)  # Аудит обязателен до выдачи положительного результата или изменения ресурса.
        return event  # Возвращает сохранённое дочернее решение.
