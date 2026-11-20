from fastapi import HTTPException  # Не выдаёт неподдерживаемый результат инструмента при нарушении лимита.
from starlette.concurrency import run_in_threadpool  # Синхронный executor не блокирует event loop во время работы SQLite.

from .demo import plan  # Использует тот же фиксированный registry демонстрационных команд.
from .schemas import ContentCheckRequest, ToolCheckRequest  # Внутренние этапы используют валидируемые публичные контракты.


def pipeline_reply(check, execution):  # Строит фактическую трассу без повторного исполнения действий.
    final = check  # Исходная оценка запроса остаётся неизменяемым событием аудита.
    stages = [{"stage": "request_check", "decision": check["decision"], "check_id": check["id"]}]  # Первый этап есть у каждой отправки.
    for field, stage in (("pre_tool_check", "tool_check"), ("tool_check", "execution_acl"), ("content_check", "content_check")):  # Разделяет предварительный ACL, проверку в транзакции и проверку текста.
        child = execution.get(field)  # Пропущенный этап не выдаётся за успешно проверенный.
        if child:  # Добавляет только реально сохранённые дочерние проверки.
            stages.append({"stage": stage, "decision": child["decision"], "check_id": child["id"]})  # UUID связывает видимый этап с аудитом.
            if child["decision"] != "ALLOW":  # Итог учитывает остановку после первоначального разрешения запроса.
                final = child  # Поздний запрет не переписывает исходный ALLOW.
    execution.setdefault("tool_invocations", 0)  # Ветка без инструмента явно показывает нулевое число вызовов.
    return {"check": check, "final_check": final, "execution": execution, "pipeline": stages}  # Исполнение, проверки и итог возвращаются раздельно.


class DemoPipeline:  # Связывает существующие advisory проверки с контролируемым исполнителем.
    def __init__(self, agent, integration):  # Общие зависимости сохраняют единые ACL и аудит.
        self.agent, self.integration = agent, integration  # Новый объект не создаёт второй detector или хранилище.

    async def run(self, body, principal, check, expires):  # Выдаёт содержимое только после всех необходимых этапов.
        execution = {"status": "not_forwarded", "forwarded": False, "agent_invocation_id": None,  # По умолчанию никакого вызова цели нет.
                     "target_invocations": 0, "tool_invocations": 0, "result": None}  # Счётчики описывают этот HTTP-вызов, а не накопленную статистику.
        if check["decision"] != "ALLOW":  # REVIEW и BLOCK останавливают цепочку до executor.
            return pipeline_reply(check, execution)  # Пропущенные этапы не создают ложных успешных записей.
        intent = plan(body.text)  # Аргументы вычисляются из фактической команды, а не из оценки LLM.
        precheck = None  # Для обычного текстового ответа tool intent отсутствует.
        if intent and intent.tool == "documents.read":  # Демонстрационное чтение проходит отдельный typed tool-check.
            tool_body = ToolCheckRequest(session_id=body.session_id, parent_check_id=check["id"],  # Родительский ALLOW связан с этой сессией и владельцем.
                                         tool=intent.tool, arguments={"document_id": intent.resource_id})  # Проверяется тот же ресурс, который будет прочитан.
            precheck = await self.integration.check(principal, tool_body, expires)  # Текущий session lock уже удерживается вызывающим маршрутом.
            execution["pre_tool_check"] = precheck  # Сохраняет факт предварительной проверки для трассы.
            if precheck["decision"] != "ALLOW":  # Изменившийся ACL останавливает исполнение до чтения.
                return pipeline_reply(check, execution)  # Счётчики остаются нулевыми.
        execution = await run_in_threadpool(self.agent.invoke, principal, intent, check)  # Executor ещё раз проверяет ACL внутри транзакции чтения.
        execution["pre_tool_check"] = precheck  # Не теряет сохранённый этап после получения результата executor.
        execution["tool_invocations"] = int(intent is not None and execution["status"] == "completed")  # Отказ транзакционного ACL не считается вызовом инструмента.
        if intent and intent.tool == "documents.read" and execution["status"] == "completed":  # Только реально прочитанный текст требует content gate.
            output = execution.pop("result")  # Удерживает текст локально, пока положительного content-check ещё нет.
            execution["result"] = None  # Ни одна ветвь отказа не возвращает исходный текст клиенту.
            text = output["content"]  # Это результат разрешённого инструмента, всё ещё недоверенный по содержимому.
            if not text.strip() or len(text) > 6000:  # Неподдерживаемый payload нельзя обрезать и считать проверенным.
                raise HTTPException(413, "TOOL_RESULT_UNSUPPORTED")  # Чтение уже зааудировано, но содержимое не выдаётся.
            content_body = ContentCheckRequest(session_id=body.session_id, parent_check_id=check["id"],  # Content gate связан с исходным запросом той же сессии.
                                               source="tool_result", text=text)  # Происхождение задаёт контролируемый executor, а не пользователь.
            content = await self.integration.check(principal, content_body, expires)  # Семантический отказ или атака остановят выдачу.
            execution["content_check"] = content  # Трасса содержит отдельное сохранённое решение о тексте.
            if content["decision"] == "ALLOW":  # Результат становится доступен клиенту только после положительной оценки.
                execution["result"] = output  # Возвращает ровно проверенный текст без повторного чтения ресурса.
            else:  # Любая неоднозначность трактуется как остановка выдачи.
                execution["status"] = "output_blocked"  # Само чтение уже произошло и не скрывается нулевым счётчиком.
        return pipeline_reply(check, execution)  # Итог отражает наиболее поздний отказ в реально выполненной цепочке.
