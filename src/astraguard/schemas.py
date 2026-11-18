from typing import Literal  # Типы фиксированных enum и интерфейсов компонентов.
from uuid import UUID  # Случайные идентификаторы сессий, событий и операций.

from pydantic import BaseModel, ConfigDict, Field, model_validator  # Строгая валидация входных данных и структурированного output.


class StrictModel(BaseModel):  # Базовая схема запрещает лишние поля и неявное приведение типов.
    model_config = ConfigDict(extra="forbid", strict=True)  # Запрещает неизвестные поля и неявное преобразование типов.


class Principal(StrictModel):  # Полномочия пользователя приходят из серверной конфигурации.
    subject_id: str  # Идентификатор субъекта, назначенный сервером.
    tenant_id: str  # Граница организации, назначенная сервером.
    role: Literal["viewer", "operator", "security_reviewer", "policy_admin"]  # Роль из фиксированного набора без доверия к текстовым заявлениям.


class CheckRequest(StrictModel):  # Контракт текста с обязательной сессией и policy_id.
    text: str = Field(min_length=1)  # Проверяемый текст; пустая строка не принимается.
    session_id: UUID = Field(strict=False)  # UUID серверной сессии; строка JSON разбирается явно.
    policy_id: str  # Назначенный профиль, дополнительно проверяемый на сервере.


class TurnRequest(CheckRequest):  # Контракт demo forwarding с необязательным approval_id.
    approval_id: UUID | None = Field(default=None, strict=False)  # Идентификатор точного одноразового подтверждения, если оно выдано.


class ReadArguments(StrictModel):  # Строгие аргументы чтения одного документа.
    document_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")  # Один идентификатор без путей и спецсимволов.


class WriteArguments(StrictModel):  # Строгие аргументы изменения одного черновика.
    draft_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")  # Идентификатор синтетического черновика без путей.
    content: str = Field(min_length=1, max_length=6000)  # Новое содержимое; лимит ограничивает нагрузку детектора.


class ToolCheckRequest(StrictModel):  # Контракт проверки реального инструмента и родительского ALLOW.
    session_id: UUID = Field(strict=False)  # UUID серверной сессии; строка JSON разбирается явно.
    parent_check_id: UUID = Field(strict=False)  # Родительская проверка; её владелец и решение проверяются отдельно.
    tool: str = Field(min_length=1, max_length=80)  # Имя инструмента, сверяемое с registry.
    arguments: dict  # Аргументы; известный инструмент выбирает их строгую схему.

    @model_validator(mode="after")  # Проверяет взаимосвязанные поля после строгой валидации типов.
    def typed_arguments(self):  # Выбирает строгую схему аргументов по известному имени инструмента.
        schema = {"documents.read": ReadArguments, "drafts.update": WriteArguments}.get(self.tool)  # Выбирает строгую схему только для известных инструментов.
        if schema:  # Известный инструмент требует полной строгой валидации аргументов.
            self.arguments = schema.model_validate(self.arguments).model_dump()  # Проверяет аргументы строгой схемой и сохраняет только разрешённые поля.
        return self  # Возвращает успешно валидированный экземпляр схемы.


class ContentCheckRequest(StrictModel):  # Контракт проверки внешнего текста с недоверенной меткой source.
    session_id: UUID = Field(strict=False)  # UUID серверной сессии; строка JSON разбирается явно.
    parent_check_id: UUID = Field(strict=False)  # Родительская проверка; её владелец и решение проверяются отдельно.
    source: Literal["tool_result", "retrieved_document"]  # Метка происхождения данных не предоставляет полномочий.
    text: str = Field(min_length=1, max_length=6000)  # Проверяемый текст; пустая строка не принимается.


Category = Literal[  # Фиксированный enum категорий ограничивает output модели.
    "direct_injection", "jailbreak", "system_extraction", "role_spoofing",  # Перечисляет инъекцию, jailbreak, извлечение инструкций и подделку роли.
    "tool_misuse", "unauthorized_data", "privilege_escalation", "multi_turn", "obfuscation",  # Перечисляет злоупотребление инструментами, чужой доступ, escalation и обфускацию.
]  # Завершает составное значение или вызов, начатый выше.
Reason = Literal[  # Допустимые reason codes исключают произвольный текст от модели.
    "BENIGN_REQUEST", "BENIGN_SECURITY_EDUCATION", "ACTIVE_OVERRIDE", "SYSTEM_EXTRACTION",  # Разделяет обычный запрос, учебное обсуждение и активные попытки подмены.
    "ROLE_SPOOFING", "TOOL_NOT_ALLOWED", "TENANT_BOUNDARY", "RESOURCE_NOT_FOUND_OR_HIDDEN",  # Коды фиксируют подделку роли, запрет инструмента и границу tenant.
    "ACTION_REQUIRES_APPROVAL", "UNTRUSTED_ROLE_CLAIM", "AMBIGUOUS_INTENT", "OBFUSCATION",  # Коды различают штатное approval, спорную привилегию и неоднозначную семантику.
    "SESSION_ESCALATION", "CONTEXT_INCOMPLETE", "DETECTOR_UNAVAILABLE", "DETECTOR_TIMEOUT",  # Коды отмечают многоходовую атаку, неполный контекст и сбои детектора.
    "DETECTOR_INVALID_OUTPUT", "DETECTOR_CONTEXT_OVERFLOW", "JAILBREAK_ATTEMPT", "PRIVILEGE_ESCALATION",  # Коды отдельно учитывают некорректный output, переполнение и escalation.
    "POLICY_CHANGED",  # Изменившаяся политика требует заново проверить актуальные полномочия.
]  # Завершает составное значение или вызов, начатый выше.


class DetectorResult(StrictModel):  # Единственная допустимая структура семантического ответа.
    schema_version: Literal["1"]  # Фиксированная версия JSON-контракта детектора.
    intent: Literal["benign", "attack", "ambiguous"]  # Классификация намерения, а не выдача полномочий.
    categories: list[Category] = Field(max_length=5)  # Ограниченный список категорий обнаруженной угрозы.
    severity: Literal["none", "low", "medium", "high", "critical"]  # Оценка опасности из фиксированного enum.
    reason_codes: list[Reason] = Field(min_length=1, max_length=5)  # Машиночитаемые основания из разрешённого набора.
