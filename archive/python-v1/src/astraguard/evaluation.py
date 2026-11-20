"""Metrics for synthetic gateway scenarios; no model calls or label generation."""  # Документирует назначение модуля; строка не запускает операций.

import math  # Округление индексов эмпирических перцентилей.
from collections import Counter  # Счётчики и очереди ограниченного состояния.
from typing import Literal  # Типы фиксированных enum и интерфейсов компонентов.

from pydantic import Field, model_validator  # Строгая валидация входных данных и структурированного output.

from .schemas import StrictModel  # Подключает schemas для текущего компонента.


class EvalTool(StrictModel):  # Typed tool fixture для проверки границы авторизации.
    tool: str  # Имя инструмента, сверяемое с registry.
    resource_id: str  # Идентификатор ресурса для повторной авторизации.
    content: str | None  # Новое содержимое; лимит ограничивает нагрузку детектора.


class EvalCase(StrictModel):  # Строгая схема эталонного синтетического сценария.
    id: str  # Идентификатор объекта или события в текущем контракте.
    family_id: str  # Семейство близких сценариев для анализа обобщения.
    category: str  # Эталонная категория сценария.
    split: Literal["dev", "holdout"]  # Фиксированное разделение dev/holdout.
    label: Literal["A", "B"]  # Эталон: A означает атаку, B означает легитимный случай.
    critical: bool  # Эталонная отметка критической угрозы.
    expected_decision: Literal["ALLOW", "REVIEW", "BLOCK"]  # Ожидаемое решение для сравнения с фактическим.
    expected_reason_codes: list[str]  # Ожидаемые основания решения из разметки.
    principal_fixture: Literal["viewer", "operator"]  # Преднастроенная серверная роль тестового пользователя.
    source: Literal["user"]  # Метка происхождения данных не предоставляет полномочий.
    mode: Literal["gateway", "tool_boundary"]  # Разделяет проверку текста и typed tool boundary.
    text: str = Field(min_length=1)  # Проверяемый текст; пустая строка не принимается.
    session_turns: list[str]  # Предшествующие шаги многоходового сценария.
    tool_intent: EvalTool | None  # Конкретный tool fixture либо None для текстового сценария.
    fixture_note: str  # Пояснение синтетических предпосылок сценария.

    @model_validator(mode="after")  # Проверяет взаимосвязанные поля после строгой валидации типов.
    def consistent(self):  # Проверяет согласованность разметки и typed fixtures.
        if (self.mode == "tool_boundary") != (self.tool_intent is not None):  # Typed tool fixture должен присутствовать ровно в режиме tool_boundary.
            raise ValueError("Typed tool fixtures require tool_boundary mode")  # Отклоняет недопустимое состояние: Typed tool fixtures require tool_boundary mode.
        if self.critical and self.label != "A":  # Критическая отметка допустима только для размеченной атаки.
            raise ValueError("Only attacks may carry the critical label")  # Отклоняет недопустимое состояние: Only attacks may carry the critical label.
        return self  # Возвращает успешно валидированный экземпляр схемы.


def divide(a, b):  # Возвращает None вместо недостоверной метрики при нулевом знаменателе.
    return a / b if b else None  # Возвращает структурированный результат текущей операции.


def percentiles(values):  # Считает nearest-rank p50/p95 с размером выборки.
    values = sorted(values)  # Упорядочивает измерения для nearest-rank перцентилей.
    return {"n": len(values), "p50": values[math.ceil(len(values) * .5) - 1] if values else None,  # Возвращает структурированный результат текущей операции.
            "p95": values[math.ceil(len(values) * .95) - 1] if values else None}  # p95 определяется методом nearest rank; для пустой выборки возвращает None.


def binary_metrics(rows, positive_decisions):  # Считает TP/FP/FN/TN и производные метрики по заданному порогу.
    counts = Counter()  # Подсчитывает фактические решения, не заявляя качество классификатора.
    for row in rows:  # Обрабатывает каждый row из rows.
        actual_positive = row["label"] == "A"  # Эталонная атака определяется разметкой корпуса.
        # Технический отказ считается пессимистично: пропуском атаки или прерыванием легитимного запроса.
        predicted_positive = row["decision"] in positive_decisions if row["decision"] is not None else not actual_positive  # Ошибка обработки учитывается пессимистично для текущей метки.
        counts[(actual_positive, predicted_positive)] += 1  # Обновляет counts[actual_positive, predicted_positive] с учётом выполненной операции.
    tp, fp, fn, tn = (counts[(True, True)], counts[(False, True)], counts[(True, False)], counts[(False, False)])  # Разворачивает четыре ячейки матрицы ошибок в TP, FP, FN и TN.
    precision, recall = divide(tp, tp + fp), divide(tp, tp + fn)  # Считает precision и recall с явным None при пустом знаменателе.
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall,  # Возвращает структурированный результат текущей операции.
            "f1": divide(2 * tp, 2 * tp + fp + fn), "fpr": divide(fp, fp + tn), "fnr": divide(fn, fn + tp),  # Поле f1 входит в структурированный контракт текущего результата.
            "technical_failures_scored_pessimistically": True}  # Поле technical_failures_scored_pessimistically входит в структурированный контракт текущего результата.


def summarize(rows):  # Сводит эталонные решения, критические пропуски и задержки.
    critical = [r for r in rows if r["critical"]]  # Выделяет эталонные критические угрозы для отдельного recall.
    benign = [r for r in rows if r["label"] == "B"]  # Выделяет легитимные случаи для false-positive показателей.
    matrix = {expected: {actual: 0 for actual in ("ALLOW", "REVIEW", "BLOCK", "ERROR")}  # Матрица включает ERROR и не скрывает технические отказы.
              for expected in ("ALLOW", "REVIEW", "BLOCK")}  # Создаёт строку матрицы для каждого ожидаемого решения.
    for row in rows:  # Обрабатывает каждый row из rows.
        matrix[row["expected_decision"]][row["decision"] or "ERROR"] += 1  # Обновляет matrix[row['expected_decision']][row['decision'] or 'ERROR'] с учётом выполненной операции.
    return {  # Возвращает структурированный результат текущей операции.
        "n": len(rows), "attacks": sum(r["label"] == "A" for r in rows), "benign": len(benign),  # Размер выборки сопровождает рассчитанные показатели.
        "containment": binary_metrics(rows, {"BLOCK", "REVIEW"}), "strict_block": binary_metrics(rows, {"BLOCK"}),  # Поле containment входит в структурированный контракт текущего результата.
        "confusion_matrix": matrix, "decision_counts": dict(Counter(r["decision"] or "ERROR" for r in rows)),  # Поле confusion_matrix входит в структурированный контракт текущего результата.
        "exact_decision_accuracy": divide(sum(r["decision"] == r["expected_decision"] for r in rows), len(rows)),  # Поле exact_decision_accuracy входит в структурированный контракт текущего результата.
        "critical": {"n": len(critical), "containment_recall": divide(sum(r["decision"] in ("BLOCK", "REVIEW") for r in critical), len(critical)),  # Поле critical входит в структурированный контракт текущего результата.
                     "block_recall": divide(sum(r["decision"] == "BLOCK" for r in critical), len(critical)),  # Поле block_recall входит в структурированный контракт текущего результата.
                     "allowed_ids": [r["id"] for r in critical if r["decision"] == "ALLOW"],  # Поле allowed_ids входит в структурированный контракт текущего результата.
                     "unresolved_ids": [r["id"] for r in critical if r["decision"] is None]},  # Поле unresolved_ids входит в структурированный контракт текущего результата.
        "benign_block_fpr": divide(sum(r["decision"] == "BLOCK" for r in benign), len(benign)),  # Поле benign_block_fpr входит в структурированный контракт текущего результата.
        "benign_review_rate": divide(sum(r["decision"] == "REVIEW" for r in benign), len(benign)),  # Поле benign_review_rate входит в структурированный контракт текущего результата.
        "review_rate": divide(sum(r["decision"] == "REVIEW" for r in rows), len(rows)),  # Поле review_rate входит в структурированный контракт текущего результата.
        "technical_error_ids": [r["id"] for r in rows if r["decision"] is None],  # Поле technical_error_ids входит в структурированный контракт текущего результата.
        "detector_failure_case_rate": divide(sum(r["detector_failed"] for r in rows), len(rows)),  # Поле detector_failure_case_rate входит в структурированный контракт текущего результата.
        "scenario_latency_ms": percentiles([r["elapsed_ms"] for r in rows]),  # Поле scenario_latency_ms входит в структурированный контракт текущего результата.
        "gateway_request_latency_ms": percentiles([v for r in rows for v in r["request_ms"]]),  # Поле gateway_request_latency_ms входит в структурированный контракт текущего результата.
        "false_negative_ids": [r["id"] for r in rows if r["label"] == "A" and r["decision"] == "ALLOW"],  # Поле false_negative_ids входит в структурированный контракт текущего результата.
        "benign_intervention_ids": [r["id"] for r in benign if r["decision"] in ("BLOCK", "REVIEW")],  # Поле benign_intervention_ids входит в структурированный контракт текущего результата.
    }  # Завершает составное значение или вызов, начатый выше.
