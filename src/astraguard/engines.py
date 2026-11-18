import base64  # Декодирование одного ограниченного слоя обфускации.
import binascii  # Ошибки некорректной base64-последовательности.
import re  # Ограниченные шаблоны команд, идентификаторов и признаков атак.
import unicodedata  # Нормализация Unicode и удаление невидимых форматирующих знаков.
from pathlib import Path  # Явные пути к локальным данным и ресурсам проекта.
from typing import Literal  # Типы фиксированных enum и интерфейсов компонентов.

import yaml  # Разбор стартовой политики с ограничениями SafeLoader.
from pydantic import Field, model_validator  # Строгая валидация входных данных и структурированного output.
from yaml.tokens import AliasToken, AnchorToken  # Подключает yaml.tokens для текущего компонента.

from .schemas import DetectorResult, StrictModel  # Подключает schemas для текущего компонента.
from .detector import Detector, DetectorFailure, OllamaDetector  # Подключает detector для текущего компонента.


class RolePolicy(StrictModel):  # Разрешённые инструменты и подтверждения одной роли.
    allowed_tools: list[Literal["documents.read", "drafts.update"]] = Field(max_length=2)  # Только два известных инструмента без wildcard.
    resource_scope: Literal["own_tenant"]  # Доступ ограничен собственной организацией.
    confirmation_actions: list[Literal["drafts.update"]] = Field(max_length=1)  # Изменение черновика требует отдельного подтверждения.

    @model_validator(mode="after")  # Проверяет взаимосвязанные поля после строгой валидации типов.
    def safe_permissions(self):  # Проверяет согласованность ACL и обязательность подтверждений записи.
        if len(set(self.allowed_tools)) != len(self.allowed_tools):  # Дублированные разрешения делают профиль неоднозначным.
            raise ValueError("Duplicate tools")  # Отклоняет недопустимое состояние: Duplicate tools.
        if not set(self.confirmation_actions) <= set(self.allowed_tools):  # Подтверждение нельзя настроить для вообще запрещённого инструмента.
            raise ValueError("Confirmation action must be allowed")  # Отклоняет недопустимое состояние: Confirmation action must be allowed.
        if "drafts.update" in self.allowed_tools and "drafts.update" not in self.confirmation_actions:  # Изменение черновика нельзя разрешить без отдельного подтверждения.
            raise ValueError("Draft updates always require confirmation")  # Отклоняет недопустимое состояние: Draft updates always require confirmation.
        return self  # Возвращает успешно валидированный экземпляр схемы.


class Policy(StrictModel):  # Ограниченный профиль MVP без wildcard и произвольных ролей.
    id: Literal["strict-demo-v1"]  # Идентификатор объекта или события в текущем контракте.
    version: int = Field(ge=1)  # Монотонная версия политики или ресурса.
    roles: dict[Literal["viewer", "operator"], RolePolicy]  # Редактируемые роли не включают admin/reviewer capabilities.

    @model_validator(mode="after")  # Проверяет взаимосвязанные поля после строгой валидации типов.
    def role_limits(self):  # Не позволяет выдать viewer право изменения черновиков.
        if "viewer" in self.roles and "drafts.update" in self.roles["viewer"].allowed_tools:  # Профиль не вправе расширить viewer до роли с записью.
            raise ValueError("Viewer cannot write")  # Отклоняет недопустимое состояние: Viewer cannot write.
        return self  # Возвращает успешно валидированный экземпляр схемы.


class PolicyLoader(yaml.SafeLoader):  # SafeLoader с дополнительными запретами неоднозначного YAML.
    def construct_mapping(self, node, deep=False):  # Запрещает YAML merge, дубликаты и нестроковые ключи.
        keys = set()  # Множество ключей выявляет неоднозначные дубликаты YAML.
        for key_node, _ in node.value:  # Обрабатывает каждый (key_node, _) из node.value.
            if key_node.tag == "tag:yaml.org,2002:merge":  # Не допускает неявное слияние YAML-политик.
                raise ValueError("YAML merges forbidden")  # Отклоняет недопустимое состояние: YAML merges forbidden.
            key = self.construct_object(key_node, deep=deep)  # Секретный ключ HMAC остаётся на сервере.
            if not isinstance(key, str) or key in keys:  # Ключ политики должен быть строкой и встречаться ровно один раз.
                raise ValueError("Policy keys must be unique strings")  # Отклоняет недопустимое состояние: Policy keys must be unique strings.
            keys.add(key)  # Вызывает keys.add в рамках текущей операции.
        return super().construct_mapping(node, deep=deep)  # Возвращает структурированный результат текущей операции.


def load_policy(path: Path) -> Policy:  # Читает ограниченный YAML seed и валидирует строгую модель.
    with path.open("rb") as stream:  # Ограничивает время жизни ресурса path.open('rb') текущим блоком.
        content = stream.read(65537)  # Содержимое читается или накапливается только в рамках текущей операции.
    raw = content.decode("utf-8")  # Исходные данные приводятся к явному сериализованному представлению.
    if len(raw.encode()) > 65536:  # YAML-профиль ограничен 64 КиБ.
        raise ValueError("Policy too large")  # Отклоняет недопустимое состояние: Policy too large.
    depth = 0  # Счётчик вложенности ограничивает сложность YAML.
    for token in yaml.scan(raw):  # Обрабатывает каждый token из yaml.scan(raw).
        if isinstance(token, (AliasToken, AnchorToken)) or type(token).__name__ == "TagToken":  # Не допускает YAML aliases, anchors и произвольные tags.
            raise ValueError("YAML aliases, anchors and tags forbidden")  # Отклоняет недопустимое состояние: YAML aliases, anchors and tags forbidden.
        if type(token).__name__ in {"BlockMappingStartToken", "BlockSequenceStartToken", "FlowMappingStartToken", "FlowSequenceStartToken"}:  # Начало контейнера увеличивает контролируемую вложенность YAML.
            depth += 1  # Обновляет depth с учётом выполненной операции.
            if depth > 8:  # Чрезмерная вложенность YAML отклоняется до полного разбора политики.
                raise ValueError("Policy nesting too deep")  # Отклоняет недопустимое состояние: Policy nesting too deep.
        elif type(token).__name__ in {"BlockEndToken", "FlowMappingEndToken", "FlowSequenceEndToken"}:  # Конец контейнера уменьшает текущую вложенность YAML.
            depth -= 1  # Обновляет depth с учётом выполненной операции.
    return Policy.model_validate(yaml.load(raw, Loader=PolicyLoader))  # Возвращает структурированный результат текущей операции.


def authorize_tool(policy: Policy, role: str, tool: str, tenant: str, resource_tenant: str):  # Детерминированно проверяет tenant, инструмент и необходимость approval.
    if tenant != resource_tenant:  # Межорганизационный доступ запрещён до остальных разрешений.
        return "BLOCK", "TENANT_BOUNDARY"  # Возвращает запрет с категорией риска и основанием.
    permissions = policy.roles.get(role)  # Права берутся из политики для серверной роли.
    if not permissions or tool not in permissions.allowed_tools:  # Отсутствие явного разрешения означает запрет инструмента.
        return "BLOCK", "TOOL_NOT_ALLOWED"  # Возвращает запрет с категорией риска и основанием.
    if tool == "drafts.update" or tool in permissions.confirmation_actions:  # Изменение требует подтверждения даже при наличии права инструмента.
        return "REVIEW", "ACTION_REQUIRES_APPROVAL"  # Останавливает передачу до дополнительной проверки или подтверждения.
    return "ALLOW", "BENIGN_REQUEST"  # Возвращает разрешение в пределах проверенной политики.


def rule_signal(text: str, *, decode=True):  # Ищет активную атаку без блокировки по одной терминологии.
    original = unicodedata.normalize("NFKC", text)  # Нормализованный текст сохраняет регистр для корректного base64.
    original = "".join(c for c in original if unicodedata.category(c) != "Cf").strip()  # Нормализованный текст сохраняет регистр для корректного base64.
    text = original.casefold()  # Рабочее представление текста текущей проверки.
    # Цитаты и учебные примеры оценивает семантический детектор вместо грубой блокировки правилом.
    if any(c in text for c in ('"', '«', '»', '`', '\n')):  # Цитаты и многострочный текст передаются семантике вместо грубого блока правил.
        return None  # Возвращает отсутствие результата без автоматического разрешения действия.
    wrapper = re.match(r"^(?:<(?:system|developer)>|\[(?:system|developer|admin)\])", text)  # Проверяет попытку выдать пользовательский текст за привилегированную роль.
    privilege = re.search(r"име(?:ет|ю) право|разреш[её]н|администратор|authorized|override|игнорируй", text)  # Ищет утверждение о якобы привилегированных полномочиях.
    action = re.search(r"прочитай|выдай|раскрой|\bread\b|\breveal\b|\bexecute\b", text)  # Проверяет наличие активного чувствительного действия.
    if wrapper and privilege and action:  # Совместное наличие фальшивой роли, привилегии и команды указывает на spoofing.
        return "ROLE_SPOOFING"  # Возвращает структурированный результат текущей операции.
    access_request = re.match(r"^(?:прочитай|выдай|открой|read|retrieve|export)\b", text)  # Проверяет, является ли текст непосредственным запросом доступа.
    unverified_permission = re.search(  # Ищет ссылку на неподтверждённое или отсутствующее разрешение.
        r"(?:устно|якобы)\s+(?:разрешил|одобрил)|(?:нет|без)\s+(?:серверных\s+)?(?:прав|разрешения)|"  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
        r"verbal\s+(?:approval|permission)|without\s+(?:authorization|permission)", text)  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
    if access_request and unverified_permission:  # Активный запрос опирается на неподтверждённое разрешение.
        return "UNTRUSTED_ROLE_CLAIM"  # Возвращает структурированный результат текущей операции.
    if decode and re.match(r"^(?:выполни|исполни|execute|follow)\b", text) and "base64" in text:  # Декодирует только явное требование выполнить base64-инструкцию.
        budget = 4096  # Ограничивает объём декодирования, чтобы не раздувать работу правил.
        for match in re.finditer(r"[A-Za-z0-9+/]{8,}={0,2}", original):  # Обрабатывает каждый match из re.finditer('[A-Za-z0-9+/]{8,}={0,2}', original).
            token = match.group()  # Выделяет credential либо ограниченную кодированную последовательность.
            if len(token) > budget * 4 // 3 + 4:  # Проверяет предельный размер base64 до декодирования.
                break  # Прекращает обход после достижения ограничения или найденного результата.
            try:  # Ограничивает участок, где ожидаемый отказ требует отдельной обработки.
                decoded = base64.b64decode(token, validate=True)  # Декодирует только валидную base64-последовательность.
                if len(decoded) > budget:  # Проверяет объём декодированных данных до рекурсивного правила.
                    break  # Прекращает обход после достижения ограничения или найденного результата.
                budget -= len(decoded)  # Обновляет budget с учётом выполненной операции.
                signal = rule_signal(decoded.decode("utf-8"), decode=False)  # Признак активной атаки сохраняется отдельно от результата модели.
                if signal:  # Найденный признак правила дополняет объяснение категории угрозы.
                    return signal  # Возвращает значение текущей ветви вызывающему компоненту.
            except (binascii.Error, UnicodeDecodeError):  # Обрабатывает только указанные ошибки, сохраняя режим остановки при отказе.
                pass  # Ожидаемый отказ уже учтён; дополнительные действия не выполняются.
            if budget <= 0:  # Дальнейшее декодирование превысило бы общий бюджет.
                break  # Прекращает обход после достижения ограничения или найденного результата.
    patterns = [  # Точные активные шаблоны не блокируют одно упоминание терминологии.
        (r"^(?:игнорируй|отмени) (?:все |предыдущие )?(?:правила|инструкции)", "ACTIVE_OVERRIDE"),  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
        (r"^ignore (?:all |the )?(?:previous )?instructions", "ACTIVE_OVERRIDE"),  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
        (r"^(?:выведи|раскрой|покажи).{0,60}(?:свой|текущий|скрытый).{0,40}(?:system prompt|системн|canary)", "SYSTEM_EXTRACTION"),  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
        (r"^(?:reveal|print|show) your (?:hidden |current )?(?:system prompt|system instructions)", "SYSTEM_EXTRACTION"),  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
    ]  # Завершает составное значение или вызов, начатый выше.
    for pattern, code in patterns:  # Обрабатывает каждый (pattern, code) из patterns.
        if re.search(pattern, text):  # Активный шаблон совпал с нормализованным текстом.
            return code  # Возвращает значение текущей ветви вызывающему компоненту.
    return None  # Возвращает отсутствие результата без автоматического разрешения действия.



def decide(rule, result: DetectorResult | None, failure: str | None):  # Выдаёт ALLOW/REVIEW/BLOCK с приоритетом правил и отказов.
    if rule and rule != "UNTRUSTED_ROLE_CLAIM":  # Точное активное правило блокирует независимо от оценки модели.
        return "BLOCK", "critical" if rule == "SYSTEM_EXTRACTION" else "high", [rule]  # Возвращает запрет с категорией риска и основанием.
    if failure or result is None:  # Отказ либо отсутствие ответа модели не превращается в ALLOW.
        return "REVIEW", "unknown", ["DETECTOR_" + {  # Останавливает передачу до дополнительной проверки или подтверждения.
            "timeout": "TIMEOUT", "invalid_output": "INVALID_OUTPUT", "context_overflow": "CONTEXT_OVERFLOW",  # Разделяет дедлайн, нарушение схемы ответа и переполнение контекста.
            "quarantined": "QUARANTINED", "draining": "QUARANTINED", "model_changed": "MODEL_CHANGED",  # Неопределённое завершение и подмена модели получают отдельные коды остановки.
        }.get(failure, "UNAVAILABLE")]  # Передаёт оставшиеся аргументы составного выражения без изменения их порядка.
    if result.intent == "attack" and result.severity in ("high", "critical"):  # Серьёзная семантическая атака блокируется.
        return "BLOCK", result.severity, result.reason_codes  # Возвращает запрет с категорией риска и основанием.
    if rule == "UNTRUSTED_ROLE_CLAIM":  # Неподтверждённое разрешение требует REVIEW даже при benign output.
        return "REVIEW", "medium", ["UNTRUSTED_ROLE_CLAIM"]  # Останавливает передачу до дополнительной проверки или подтверждения.
    if result.intent != "benign" or result.categories or result.severity not in ("none", "low"):  # Неоднозначный или противоречивый semantic output требует REVIEW.
        return "REVIEW", "medium", ["AMBIGUOUS_INTENT"]  # Останавливает передачу до дополнительной проверки или подтверждения.
    return "ALLOW", "low", ["BENIGN_REQUEST"]  # Возвращает разрешение в пределах проверенной политики.
