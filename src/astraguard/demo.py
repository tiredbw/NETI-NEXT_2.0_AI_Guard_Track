import re  # Ограниченные шаблоны команд, идентификаторов и признаков атак.
from dataclasses import dataclass  # Неизменяемый typed intent без логики исполнения.
from datetime import datetime, timezone  # UTC-время событий и сроки действия данных.
from uuid import uuid4  # Случайные идентификаторы сессий, событий и операций.

from .engines import authorize_tool  # Подключает engines для текущего компонента.


@dataclass(frozen=True)  # Запрещает менять поля уже сформированного tool intent.
class ToolIntent:  # Неизменяемое представление конкретного демонстрационного действия.
    tool: str  # Имя инструмента, сверяемое с registry.
    resource_id: str  # Идентификатор ресурса для повторной авторизации.
    content: str | None = None  # Новое содержимое; лимит ограничивает нагрузку детектора.


def plan(text: str) -> ToolIntent | None:  # Разбирает только явные демонстрационные команды /read и /write.
    match = re.fullmatch(r"/read ([A-Za-z0-9_-]{1,64})", text.strip())  # Полное совпадение ограничивает демонстрационную грамматику.
    if match:  # Выполняет ветвь только при полном совпадении демонстрационной команды.
        return ToolIntent("documents.read", match[1])  # Возвращает структурированный результат текущей операции.
    match = re.fullmatch(r"/write ([A-Za-z0-9_-]{1,64}) (.+)", text.strip(), re.DOTALL)  # Полное совпадение ограничивает демонстрационную грамматику.
    if match:  # Выполняет ветвь только при полном совпадении демонстрационной команды.
        return ToolIntent("drafts.update", match[1], match[2])  # Возвращает структурированный результат текущей операции.
    if text.lstrip().startswith("/"):  # Неизвестная slash-команда не становится обычным разрешённым текстом.
        return ToolIntent("unknown", "")  # Возвращает структурированный результат текущей операции.
    return None  # Возвращает отсутствие результата без автоматического разрешения действия.


def tool_policy(db, policy, principal, intent):  # Сверяет registry, вид ресурса, tenant и права инструмента.
    if intent.tool not in ("documents.read", "drafts.update"):  # Инструмент вне фиксированного registry запрещён.
        return "BLOCK", "TOOL_NOT_ALLOWED"  # Возвращает запрет с категорией риска и основанием.
    row = db.execute("SELECT tenant, kind FROM resources WHERE id=?", (intent.resource_id,)).fetchone()  # Читает одну запись для проверки доступа или версии.
    if not row or row[0] != principal.tenant_id:  # Отсутствующий и чужой ресурс неразличимы по ответу шлюза.
        return "BLOCK", "RESOURCE_NOT_FOUND_OR_HIDDEN"  # Возвращает запрет с категорией риска и основанием.
    if row[1] != ("document" if intent.tool == "documents.read" else "draft"):  # Тип ресурса должен соответствовать выбранному инструменту.
        return "BLOCK", "TOOL_NOT_ALLOWED"  # Возвращает запрет с категорией риска и основанием.
    return authorize_tool(policy, principal.role, intent.tool, principal.tenant_id, row[0])  # Возвращает фактическое решение актуальной проверки ACL.


class DemoAgent:  # Детерминированный исполнитель синтетических ресурсов, не целевая LLM.
    def __init__(self, store, policies):  # Настраивает зависимости компонента.
        self.store, self.policies = store, policies  # Сохраняет общие зависимости компонента для последующих проверок.
        self.invocations = 0  # Счётчик отражает фактические вызовы демонстрационного исполнителя.

    @property  # Предоставляет чтение вычисляемого состояния без присваивания.
    def policy(self):  # Возвращает отделённый от БД снимок текущей политики.
        return self.policies.snapshot()  # Возвращает структурированный результат текущей операции.

    def preflight(self, principal, intent):  # Проверяет фактический ресурс до оценки и вызова demo agent.
        if intent is None:  # Обычный текст не требует демонстрационного tool preflight.
            return None  # Возвращает отсутствие результата без автоматического разрешения действия.
        with self.store.connect() as db:  # Соединение обеспечивает commit при успехе и rollback при исключении.
            return tool_policy(db, self.policies.snapshot(db), principal, intent)  # Возвращает структурированный результат текущей операции.

    def invoke(self, principal, intent, parent):  # Повторяет ACL в транзакции до выдачи демонстрационного результата.
        invocation_id = str(uuid4())  # Отдельный UUID связывает аудит с реальным demo-вызовом.
        child = {  # Отдельное событие фиксирует повторную проверку перед исполнением.
            "id": str(uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),  # UUID события отделяет результат от исходного payload.
            "parent_id": parent["id"], "session_id": parent["session_id"],  # Ссылается на исходную проверку без изменения её результата.
            "policy_ids": [],  # Фиксирует сработавшие запреты и версию применённой политики.
            "detector": {"status": "skipped_hard_deny", "model": None, "digest": None},  # Статус и digest показывают, вызывалась ли закреплённая модель.
            "threats": [], "timing_ms": {},  # Категории сопровождаются источником и уровнем риска.
        }  # Завершает составное значение или вызов, начатый выше.
        with self.store.connect() as db:  # Соединение обеспечивает commit при успехе и rollback при исключении.
            db.execute("BEGIN IMMEDIATE")  # Резервирует транзакцию записи до повторной проверки условий.
            policy = self.policies.snapshot(db)  # Снимок активной политики, не изменяемый ответом модели.
            decision, reason = tool_policy(db, policy, principal, intent) if intent else ("ALLOW", "BENIGN_REQUEST")  # Получает согласованное решение, риск и основания проверки.
            if decision != "BLOCK" and parent["policy_version"] != policy.version:  # Смена политики переводит прежний допуск в REVIEW, сохраняя BLOCK.
                decision, reason = "REVIEW", "POLICY_CHANGED"  # Устанавливает REVIEW вместе с риском и основанием этой ветви.
            child["policy_version"] = policy.version  # Привязывает итог к актуальной версии политики.
            child.update(decision=decision, risk="low" if decision == "ALLOW" else "high",  # Дополняет результат текущей операции согласованными полями.
                         reason_codes=[reason], event_type="tool_execution" if intent else "agent_execution",  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
                         agent_invocation_id=invocation_id,  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
                         explanation="Проверка допуска перед исполнением демонстрационного действия.")  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
            if decision != "ALLOW":  # Запрет или review перед исполнением не выдаёт содержимое ресурса.
                child["policy_ids"] = [reason]  # Фиксирует сработавшее ограничение политики для аудита.
            self.store.insert(db, principal, intent.resource_id if intent else "demo_reply", child)  # Аудит обязателен до выдачи положительного результата или изменения ресурса.
            content = None  # Содержимое читается или накапливается только в рамках текущей операции.
            if decision == "ALLOW" and intent:  # Ресурс читается только при актуальном разрешении конкретного инструмента.
                content = db.execute("SELECT content FROM resources WHERE id=?", (intent.resource_id,)).fetchone()[0]  # Содержимое читается или накапливается только в рамках текущей операции.
        self.invocations += 1  # Обновляет self.invocations с учётом выполненной операции.
        return {  # Возвращает структурированный результат текущей операции.
            "status": "completed" if decision == "ALLOW" else "failed", "forwarded": True,  # Явный статус отделяет разрешение, отсутствие передачи и завершённое действие.
            "agent_invocation_id": invocation_id, "target_invocations": 1,  # Поле agent_invocation_id входит в структурированный контракт текущего результата.
            "tool_check": child if intent else None,  # Поле tool_check входит в структурированный контракт текущего результата.
            "result": ({"adapter": "deterministic-demo", "content": content if intent else  # Выдаёт только разрешённый результат демонстрационного действия.
                        "Демонстрационный агент получил разрешённый запрос. Это синтетический ответ, не генерация LLM."}  # Фиксированная строка задаёт часть контракта; пользователь не может расширить enum.
                       if decision == "ALLOW" else None),  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
        }  # Завершает составное значение или вызов, начатый выше.
