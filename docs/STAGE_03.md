# Этап 3: подтверждения и запись черновиков

Запуск — STAGE_01.md. Предыдущий read-only этап — STAGE_02.md. Этот документ описывает фактическое расширение; полный MVP и веб-интерфейс ещё не завершены.

## Identity

В `ASTRAGUARD_IDENTITIES` настроить отдельные случайные bearer credentials для:

- `operator`, tenant A, role `operator` — запрашивает запись;
- `reviewer`, tenant A, role `security_reviewer` — подтверждает действие;
- по желанию viewer и reviewer другого tenant для негативной демонстрации.

Секреты генерировать локально, не сохранять в Git. Разные credentials с одинаковым subject_id не позволяют обойти запрет self-approval. Reviewer не получает роль operator и не может самостоятельно выполнять запись.

## Последовательность

1. Operator создаёт сессию и отправляет `/v1/agent/turns` с текстом `/write A2 новый синтетический текст`.
2. При успешном detector и разрешимой политике возвращается REVIEW, `review.approvable=true`; черновик не меняется. Ошибки detector и подозрительные запросы не подтверждаются.
3. Reviewer вызывает GET `/v1/reviews/{check_id}`. Ответ содержит requester, tool, resource ID/version, размер content и HMAC точного действия; raw текст не возвращается. Этот digest — идентификатор действия, не оценка безопасности.
4. Reviewer вызывает POST `/v1/reviews/{check_id}/approve` с JSON `{}`. Ответ 201: `approval_id`, `expires_at`.
5. Operator повторяет исходное тело `/v1/agent/turns` без изменений, добавляя `approval_id`, и заголовок `Idempotency-Key` длиной 8..128 символов.
6. При успешных проверках возвращается ALLOW и `execution.result.updated=true`. Исходный REVIEW event не изменяется; новый ALLOW ссылается на него через `approved_check_id`.

Срок pending/approval — 120 секунд от появления REVIEW. Подтверждение не продлевает срок. В RAM хранится максимум 1000 pending действий; содержимое не попадает в audit/approval таблицы. После рестарта pending и сессии утрачиваются: незавершённое действие проверяется заново.

## Гарантии

Перед записью проверяются requester/tenant, точные text/session/policy, HMAC, policy content hash, resource version и текущие tool ACL. Изменение истории сессии после REVIEW отменяет допуск. Изменение ресурса или прав →409 без записи.

В одной SQLite BEGIN IMMEDIATE транзакции выполняются новая авторизация, запись audit, изменение черновика/версии, consume approval и сохранение результата idempotency. Ошибка любого шага откатывает всё. Два конкурентных использования одного approval с разными ключами дают одно исполнение и один 409.

Повтор с тем же ключом, телом и approval возвращает сохранённый результат с `execution.replayed=true`; счётчик агента и версия черновика не увеличиваются. `target_invocations=1` в этом ответе относится к сохранённой исходной операции. Нового вызова при replay нет. Иное тело/approval с тем же ключом →409; новый ключ с использованным approval →409. Idempotency TTL — 24 часа.

Cached retry проходит проверку действующей identity и сессии в API. После истечения/утраты сессии API не выдаёт cached результат. Механизм рассчитан на синтетическое действие в SQLite; гарантии внешних side effects не заявляются.

## Хранение и контракты

SQLite user_version=2: добавлены resource version, approvals и executions; данные первого этапа сохраняются. База более новой неизвестной версии не открывается с понижением версии. Reviewer может читать audit/checks своего tenant, но не чужого. Новые API поля и маршруты дополняют API.md:

- TurnRequest = CheckRequest + nullable `approval_id`;
- GET `/v1/reviews/{check_id}` — описание точного pending действия;
- POST `/v1/reviews/{check_id}/approve` — строго пустой JSON object;
- `execution.replayed` — признак повторной выдачи результата изменяющей операции.

## Проверка этапа

`python -m pytest -q`: **63 passed**, одно предупреждение deprecated TestClient backend. Проверены роли/tenant/self-approval, подмена аргументов, повторная выдача approval, expiry, изменение policy/resource/context, обязательный idempotency key, rollback, конкурентное потребление, restart и отсутствие подтверждения detector failures.

Это offline проверки с fake detector, не измерение качества Qwen. Real-model smoke этапа 2 остаётся отдельной проверкой чтения и блокировки. Сквозной сценарий записи с реальной моделью ещё не измерялся.

## Далее

Веб-интерфейс для requester/reviewer и трасса исполнения; quality evaluation; policy admin, статистика, startup warm-up/digest, расширение audit и retention. Оставшиеся ограничения первого/второго этапов действуют, кроме уже реализованных approvals и записи.
