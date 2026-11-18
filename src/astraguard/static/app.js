"use strict"; // Строгий режим запрещает неявные глобальные переменные и часть небезопасных операций.
const el = (id) => document.getElementById(id); // Единая функция доступа к DOM по заранее известному id.
const state = {token: "", me: null, session: null, turns: 0, pending: null, review: null}; // Credential и состояние вкладки остаются в памяти, без browser storage.
const errors = { // Сопоставляет серверные коды с понятными сообщениями интерфейса.
  UNAUTHORIZED: "Ключ не принят. Проверьте его и войдите заново.", // При отказе авторизации предлагает проверить credential.
  SESSION_NOT_FOUND: "Сессия истекла или сервер перезапущен. Создайте новую сессию.", // Истёкшая или утраченная RAM-сессия требует нового создания.
  RATE_LIMIT: "Слишком много запросов. Подождите минуту.", // Поминутный лимит останавливает чрезмерную частоту запросов.
  DETECTOR_CAPACITY: "Детектор занят. Повторите запрос через несколько секунд.", // Переполненная очередь детектора требует повторной попытки позднее.
  APPROVAL_EXPIRED_OR_USED: "Подтверждение истекло или использовано. Проверьте действие заново.", // Истёкшее или использованное approval нельзя применить повторно.
  APPROVAL_MISMATCH: "Точное действие или политика изменились. Нужна новая проверка.", // Изменение точного действия делает прежнее подтверждение недействительным.
  SESSION_CONTEXT_CHANGED: "Контекст сессии изменился. Проверьте действие и подтвердите его заново.", // Изменение серверной истории требует нового подтверждения.
  RESOURCE_CHANGED: "Ресурс изменился. Нужна новая проверка.", // Изменение версии ресурса останавливает запись по старой привязке.
  REVIEW_NOT_FOUND: "Подтверждаемое действие не найдено в пределах ваших полномочий.", // Чужое и отсутствующее действие не различаются для клиента.
  ALREADY_APPROVED: "Подтверждение уже выдано. Используйте ранее полученный approval ID.", // Повторная выдача approval не создаёт второе подтверждение.
  AUDIT_UNAVAILABLE: "Журнал недоступен. Исполнение остановлено. Повторите позже.", // Отказ обязательного аудита должен остановить исполнение.
  POLICY_CHANGED: "Политика изменилась. Повторите проверку и подтверждение действия.", // Смена политики требует заново оценить допустимость действия.
  REVIEW_EXPIRED_OR_CHANGED: "Проверка истекла или политика изменилась. Нужна новая проверка.", // Показывает истечение review или изменение политики без обхода проверки.
}; // Завершает таблицу сообщений об ошибках.
function message(text, error = false) { // Единая точка вывода сообщения о состоянии операции.
  el("message").textContent = text; // textContent выводит пользовательские строки без интерпретации HTML.
  el("message").className = error ? "error" : ""; // CSS-класс отличает ошибку от обычного уведомления.
} // Завершает функцию вывода уведомления.
async function api(path, options = {}) { // Общий HTTP-клиент для защищённых маршрутов текущей вкладки.
  const response = await fetch(path, {...options, headers: { // Передаёт параметры вызова и формирует набор заголовков.
    ...(options.body ? {"Content-Type": "application/json"} : {}), // JSON Content-Type добавляется только при наличии тела.
    Authorization: `Bearer ${state.token}`, ...(options.headers || {}), // Bearer берётся из RAM; дополнительные заголовки поддерживают идемпотентность.
  }, signal: AbortSignal.timeout(30000)}); // Ограничивает ожидание браузера 30 секундами, без гарантии отмены backend.
  const data = await response.json(); // Разбирает структурированный JSON-ответ API.
  if (!response.ok) { // Отличает HTTP-ошибку от успешного результата проверки.
    const code = data.error?.code || `HTTP_${response.status}`; // Извлекает безопасный код ошибки либо использует HTTP-статус.
    throw new Error(errors[code] || `Запрос остановлен: ${code}.`); // Останавливает действие с локализованным сообщением, не продолжая исполнение.
  } // Завершает ветвь отказа HTTP-запроса.
  return data; // Передаёт успешное JSON-тело вызывающему обработчику.
} // Завершает общий HTTP-клиент.
async function action(work) { // Оборачивает UI-действие состояниями ожидания, ошибки и завершения.
  document.querySelectorAll("button").forEach((button) => {button.disabled = true;}); // Блокирует повторные нажатия кнопок во время текущей операции.
  el("workspace").setAttribute("aria-busy", "true"); // Сообщает assistive technology о занятости рабочей области.
  message("Обработка запроса…"); // Показывает пользователю, что запрос ещё обрабатывается.
  try {await work();} catch (error) { // Дожидается операции и перехватывает её ошибку для интерфейса.
    message(error.name === "TimeoutError" ? "Время ожидания истекло. Для подтверждённой записи повтор использует прежний ключ операции." : // Таймаут подтверждённой записи не меняет сохранённый ключ повтора.
      error instanceof TypeError ? "Нет связи с сервером. Проверьте локальный запуск и повторите запрос." : error.message, true); // Отделяет сетевой отказ от остальных сообщений об ошибках.
  } finally { // Восстановление UI выполняется и при успехе, и при исключении.
    document.querySelectorAll("button").forEach((button) => {button.disabled = false;}); // Возвращает доступность кнопок после завершения ожидания.
    el("approve-action").disabled = !state.review; // Подтвердить можно только предварительно выбранное review.
    el("workspace").setAttribute("aria-busy", "false"); // Снимает состояние занятости для доступности интерфейса.
  } // Завершает обязательное восстановление элементов.
} // Завершает оболочку UI-действия.
async function newSession() { // Создаёт новую серверную сессию вместо локальной подмены её состояния.
  const session = await api("/v1/sessions", {method: "POST"}); // Запрашивает UUID и TTL с текущим Bearer credential.
  state.session = session.session_id; // Сохраняет только полученный серверный идентификатор сессии.
  state.turns = 0; // Начинает счёт завершённых отправок новой сессии с нуля.
  state.pending = null; // Отбрасывает отложенное действие предыдущей сессии.
  el("pending-panel").hidden = true; // Скрывает панель применения старого approval.
  el("result-content").hidden = true; // Убирает результат предыдущей проверки.
  el("result-empty").hidden = false; // Возвращает честное пустое состояние результата.
  el("checked-input").textContent = ""; // Очищает ранее показанный фрагмент входного текста.
  sessionLabel(); // Обновляет подпись новой сессии и её счётчик.
} // Завершает создание новой сессии в интерфейсе.
function sessionLabel() { // Формирует краткую подпись текущего серверного контекста.
  el("session-label").textContent = `Сессия ${state.session?.slice(0, 8)} · завершённых отправок: ${state.turns}/4`; // Показывает сокращённый UUID и лимит четырёх завершённых demo turns.
} // Завершает обновление подписи сессии.
async function health() { // Получает готовность сервиса без вызова модели из браузера.
  try { // Сетевой отказ readiness не должен ломать остальной интерфейс.
    const response = await fetch("/health/ready", {signal: AbortSignal.timeout(3000)}); // Ограничивает ожидание readiness тремя секундами.
    const data = await response.json(); // Разбирает статусы компонентов из JSON readiness.
    el("health").textContent = data.status === "ready" ? "Сервис готов · детектор доступен" : // Сообщает готовность только при явном серверном ready.
      "Детектор ещё не проверен или недоступен. При сбое запрос будет остановлен для проверки."; // Объясняет, что отсутствие детектора приведёт к остановке запроса.
  } catch {el("health").textContent = "Состояние сервиса не удалось получить.";} // При сетевом отказе не выдаёт неизвестное состояние за готовность.
} // Завершает проверку состояния сервиса.
function showResult(data, checkedText = null) { // Отображает проверку отдельно от необязательного исполнения агента.
  const check = data.check || data; // Поддерживает ответы и advisory check, и demo forwarding.
  const execution = data.execution; // Выделяет исполнение, которое может отсутствовать у advisory API.
  el("result-empty").hidden = true; // Скрывает пустое состояние после получения реального события.
  el("result-content").hidden = false; // Открывает панель результата.
  el("checked-input").textContent = checkedText === null ? "Исходный текст этого события в журнале не хранится." : // История не восстанавливает исходный текст из аудита.
    `Проверено: ${checkedText.slice(0, 160)}${checkedText.length > 160 ? "…" : ""}`; // Для текущего запроса показывает максимум 160 символов через textContent.
  el("result-stale").hidden = checkedText === null || el("prompt").value === checkedText; // Помечает результат устаревшим, если поле ввода уже изменено.
  el("decision").textContent = check.decision; // Показывает фактическое решение сервера.
  el("decision").className = ["ALLOW", "REVIEW", "BLOCK"].includes(check.decision) ? check.decision : ""; // Разрешает CSS-класс только из фиксированного enum решений.
  el("risk").textContent = `Риск: ${check.risk || "не указан"}`; // Показывает риск и явно учитывает отсутствие поля.
  el("explanation").textContent = check.explanation || "Событие аудита."; // Отображает серверное объяснение либо нейтральное описание события.
  el("threats").textContent = (check.threats || []).map((t) => t.category).join(", ") || "Не обнаружены / не оценивались"; // Выводит категории угроз, не трактуя пустой список как гарантию безопасности.
  el("reasons").textContent = (check.reason_codes || []).join(", ") || "Нет"; // Показывает машинные reason codes для разбора решения.
  el("policy-ids").textContent = (check.policy_ids || []).join(", ") || "Запреты политик не сработали"; // Показывает сработавшие запреты политики либо их отсутствие.
  el("timing").textContent = typeof check.timing_ms?.total === "number" ? `${Math.round(check.timing_ms.total)} мс (до сохранения аудита)` : "Не измерялось"; // Округляет доступное время; подпись указывает границу измерения до аудита.
  el("detector").textContent = check.detector?.status || "Не вызывался"; // Отличает статус детектора от отсутствия его вызова.
  const steps = ["Результат проверки зарегистрирован в аудите."]; // Начинает трассу с зарегистрированного результата проверки.
  if (!execution) steps.push("Передача агенту не запрашивалась; для событий истории трасса не восстанавливается."); // Для advisory и истории не придумывает факт передачи агенту.
  else if (execution.replayed) steps.push("Возвращён сохранённый результат. Агент повторно не вызывался."); // Идемпотентный replay явно отличается от нового исполнения.
  else if (!execution.forwarded) steps.push("Остановлено на шлюзе. Вызовов целевого агента: 0."); // При остановке на шлюзе показывает ноль вызовов цели.
  else { // В эту ветвь попадает ответ с фактической передачей demo agent.
    steps.push("Запрос передан демонстрационному агенту. Вызовов: 1."); // Демонстрационный executor учитывает один вызов на отправку.
    if (execution.tool_check) steps.push(`Повторная проверка инструмента: ${execution.tool_check.decision}.`); // Показывает отдельную повторную проверку перед доступом к ресурсу.
    steps.push(execution.status === "completed" ? "Демонстрационное действие выполнено." : "Исполнение остановлено; результат не выдан."); // Отличает завершённое действие от отказа исполнителя после передачи.
  } // Завершает построение статусов переданного действия.
  el("trace").replaceChildren(...steps.map((text) => {const item = document.createElement("li"); item.textContent = text; return item;})); // Создаёт элементы трассы DOM-методами без вставки недоверенного HTML.
  el("agent-output").hidden = !execution?.result; // Не показывает панель ответа, если разрешённого результата нет.
  el("agent-output").textContent = execution?.result?.content || (execution?.result?.updated ? "Синтетический черновик обновлён." : ""); // Выводит текст документа либо факт синтетического изменения черновика.
} // Завершает отображение одной проверки.
async function refresh() { // Обновляет доступные политики, историю и reviewer statistics.
  const policies = await api("/v1/policies"); // Политики получает с сервера, а не из выбранной пользователем роли.
  el("policy").replaceChildren(...policies.map((policy) => { // Строит select из фактически доступных профилей.
    const option = document.createElement("option"); option.value = policy.id; // Значение option содержит серверный policy_id.
    option.textContent = `${policy.id} · версия ${policy.version}`; return option; // Подпись показывает активную версию профиля.
  })); // Заменяет старый список политик целиком.
  const history = await api("/v1/checks?limit=20"); // Запрашивает максимум двадцать доступных событий истории.
  const rows = history.items.map((event) => { // Для каждого события формирует отдельную строку таблицы.
    const row = document.createElement("tr"); // Создаёт DOM-строку без парсинга серверного HTML.
    const values = [new Date(event.created_at).toLocaleTimeString("ru-RU"), event.decision, // Время события форматируется локально, рядом выводится решение.
      (event.reason_codes || []).join(", "), event.id]; // Причины и UUID дополняют строку без хранения исходного запроса.
    values.forEach((value, index) => { // Преобразует каждое значение события в отдельную ячейку.
      const cell = document.createElement("td"); cell.textContent = value; // textContent предотвращает исполнение HTML из значений.
      if (index === 1 && ["ALLOW", "REVIEW", "BLOCK"].includes(value)) cell.className = value; // Цвет решения назначается только для известных ALLOW/REVIEW/BLOCK.
      row.append(cell); // Добавляет проверенную текстовую ячейку в строку.
    }); // Завершает заполнение основных ячеек события.
    const cell = document.createElement("td"); // Отдельная ячейка отведена под действие пользователя.
    const button = document.createElement("button"); button.className = "text-button"; // Кнопка подробностей использует штатный текстовый стиль.
    const canReview = state.me.roles.includes("security_reviewer") && event.review?.approvable; // UI предлагает review только reviewer и только при approvable; сервер проверяет повторно.
    button.textContent = canReview ? "Рассмотреть" : "Подробнее"; // Надпись различает рассмотрение действия и обычные подробности.
    button.addEventListener("click", () => action(async () => { // Оборачивает открытие события общей обработкой ожидания и ошибок.
      if (state.me.roles.includes("security_reviewer") || state.me.roles.includes("policy_admin")) { // Административные роли получают свой вариант представления истории.
        if (canReview) {el("review-id").value = event.id; await inspectReview();} // Подтверждаемое событие загружается через защищённый review endpoint.
        else message(`${event.decision}: ${(event.reason_codes || []).join(", ")}. ID ${event.id}`); // Для остальных событий показывает решение, основания и идентификатор.
      } else {showResult(event); message(`Показано событие ${event.id}.`);} // Инициатор может открыть обычный результат собственной проверки.
    })); // Завершает обработчик кнопки подробностей.
    cell.append(button); row.append(cell); return row; // Собирает ячейку действия и возвращает готовую строку.
  }); // Завершает преобразование истории в DOM-строки.
  if (!rows.length) { // Пустая история получает отдельное понятное состояние.
    const row = document.createElement("tr"); const cell = document.createElement("td"); // Создаёт одну строку-заглушку для отсутствующих событий.
    cell.colSpan = 5; cell.textContent = "Проверок пока нет."; row.append(cell); rows.push(row); // Пустая ячейка занимает все пять колонок таблицы.
  } // Завершает обработку пустой выборки.
  el("history-body").replaceChildren(...rows); // Заменяет содержимое таблицы актуальными DOM-узлами.
  if (state.me.roles.includes("security_reviewer")) { // Запрашивает статистику только в reviewer UI; сервер также проверяет роль.
    const stats = await api("/v1/stats"); // Получает агрегаты только своего tenant.
    el("stats").textContent = `За ${stats.window_days} дней: ALLOW ${stats.decisions.ALLOW}, REVIEW ${stats.decisions.REVIEW}, BLOCK ${stats.decisions.BLOCK}. Операционная статистика, не оценка точности.`; // Отделяет операционные количества от измерения точности детектора.
  } // Завершает reviewer-часть обновления.
} // Завершает обновление политик и истории.
async function inspectReview() { // Загружает безопасное описание точного действия для рассмотрения.
  state.review = null; // Сбрасывает прежний выбор до получения нового review.
  el("review-details").hidden = true; // Скрывает старое описание, чтобы его нельзя было принять за новое.
  const id = el("review-id").value.trim(); // Удаляет пробелы вокруг введённого UUID проверки.
  const details = await api(`/v1/reviews/${encodeURIComponent(id)}`); // Экранирует UUID в URL; права и TTL проверяет сервер.
  state.review = details; // Сохраняет только успешно полученное описание review.
  const pairs = [["Инициатор", details.requester_id], ["Инструмент", details.tool], ["Ресурс", `${details.resource_id}, версия ${details.resource_version}`], // Готовит инициатора, tool и ресурс с версией для ручной проверки.
    ["Размер нового текста", `${details.content_length} символов`], ["HMAC точного действия", details.binding_hmac], ["Срок действия", new Date(details.expires_at).toLocaleTimeString("ru-RU")]]; // Добавляет размер, HMAC точного действия и срок его действия.
  el("review-summary").replaceChildren(...pairs.flatMap(([name, value]) => { // Строит пары термин/значение вместо HTML из ответа API.
    const dt = document.createElement("dt"); dt.textContent = name; // Название свойства помещается в dt как текст.
    const dd = document.createElement("dd"); dd.textContent = value; return [dt, dd]; // Значение помещается в dd как текст без HTML-интерпретации.
  })); // Завершает обновление списка свойств review.
  el("approval-result").textContent = ""; // Убирает approval ID предыдущего рассмотрения.
  el("review-details").hidden = false; // Показывает успешно загруженное описание.
  message("Проверьте инициатора, ресурс и HMAC перед подтверждением."); // Напоминает проверить привязку действия перед выдачей разрешения.
} // Завершает загрузку review.
el("login-form").addEventListener("submit", (event) => { // Перехватывает отправку формы входа без перезагрузки страницы.
  event.preventDefault(); // Не допускает обычную отправку credential браузерной формой.
  state.token = el("token").value.trim(); el("token").value = ""; // Переносит credential в RAM и сразу очищает поле ввода.
  action(async () => { // Вход использует общую оболочку блокировки UI и ошибок.
    state.me = await api("/v1/me"); // Получает identity и роли только из защищённого /me.
    const reviewer = state.me.roles.includes("security_reviewer"); // Проверяет серверный capability reviewer для выбора панели.
    const administrator = state.me.roles.includes("policy_admin"); // Проверяет серверный capability администратора политики.
    el("subject").textContent = state.me.subject_id; // Показывает серверный subject_id текстом.
    el("role").textContent = `Роль: ${state.me.roles.join(", ")}`; // Показывает фактическую роль, не позволяя менять её локальным select.
    el("tenant").textContent = `Tenant: ${state.me.tenant_id}`; // Показывает организацию из серверной identity.
    if (!reviewer && !administrator) await newSession(); // Рабочая сессия создаётся для обычного requester, не reviewer/admin.
    el("requester").hidden = reviewer || administrator; // Панель отправки скрыта от административных identity.
    el("reviewer").hidden = !reviewer; // Панель рассмотрения доступна reviewer.
    el("administrator").hidden = !administrator; // Административная панель видна только соответствующей identity.
    await refresh(); await health(); // После входа получает актуальные политики, историю и readiness.
    el("login-panel").hidden = true; el("workspace").hidden = false; // Показывает рабочую область только после успешной загрузки.
    message("Вход выполнен. Полномочия получены с сервера."); // Сообщает, что полномочия подтверждены ответом сервера.
  }); // Завершает асинхронную операцию входа.
}); // Завершает обработчик формы входа.
el("logout").addEventListener("click", () => { // Локальный выход очищает данные текущей вкладки.
  state.token = ""; state.me = null; state.session = null; state.pending = null; state.review = null; // Удаляет credential, identity, сессию и отложенные действия из RAM.
  el("workspace").hidden = true; el("login-panel").hidden = false; // Возвращает форму входа вместо рабочей области.
  ["prompt", "approval", "review-id"].forEach((id) => {el(id).value = "";}); // Очищает поля запроса, approval и идентификатора review.
  ["history-body", "review-summary", "agent-output", "approval-result"].forEach((id) => el(id).replaceChildren()); // Удаляет DOM-узлы с историей и результатами предыдущей identity.
  ["subject", "role", "tenant", "pending-check", "explanation", "reasons", "threats", "policy-ids", "stats", "checked-input"].forEach((id) => {el(id).textContent = "";}); // Убирает текстовые метаданные предыдущего пользователя.
  el("review-details").hidden = true; el("result-content").hidden = true; el("result-empty").hidden = false; // Возвращает панели результата и review к пустому состоянию.
  message("Вы вышли. Ключ удалён из состояния страницы."); el("token").focus(); // Подтверждает локальный выход и переводит фокус в поле входа.
}); // Завершает обработчик выхода; серверный credential этим не отзывается.
function edited() {if (!el("result-content").hidden) el("result-stale").hidden = false;} // Любое редактирование помечает показанный результат как устаревший.
el("prompt").addEventListener("input", edited); // Отслеживает ручной ввод нового текста.
document.querySelectorAll("[data-example]").forEach((button) => button.addEventListener("click", () => {el("prompt").value = button.dataset.example; edited(); el("prompt").focus();})); // Пример подставляется в поле и требует новой проверки.
async function submit(forward) { // Отправляет запрос либо на advisory check, либо на demo forwarding.
  const body = {text: el("prompt").value, session_id: state.session, policy_id: el("policy").value}; // Тело содержит текст, сессию и профиль, без role/tenant/subject.
  if (!body.text.trim()) throw new Error("Введите запрос для проверки."); // Не отправляет пустое или пробельное значение.
  const data = await api(forward ? "/v1/agent/turns" : "/v1/checks", {method: "POST", body: JSON.stringify(body)}); // Маршрут выбирается по действию; тело передаётся как JSON.
  showResult(data, body.text); // Сохраняет связь показанного решения с точным отправленным текстом.
  const check = data.check || data; // Извлекает проверку из обоих допустимых форматов ответа.
  state.pending = forward && check.review?.approvable ? {body, key: crypto.randomUUID(), checkId: check.id} : null; // Для подтверждаемого demo-действия фиксирует исходное тело и один ключ повтора.
  el("pending-panel").hidden = !state.pending; // Показывает панель продолжения только при наличии такого действия.
  el("pending-check").textContent = state.pending?.checkId || ""; // Показывает UUID исходного review для передачи reviewer.
  el("approval").value = ""; // Не переносит ранее введённый approval на новое действие.
  if (data.execution?.status === "completed") state.turns++; // Увеличивает счётчик только после завершённого исполнения.
  sessionLabel(); await refresh(); await health(); // Обновляет контекст, аудит и статус сервиса после операции.
  message(`Решение: ${check.decision}. ${data.execution?.forwarded ? "Запрос передан агенту." : "Агент не вызывался."}`); // Явно различает решение и факт передачи агенту.
} // Завершает первичную отправку запроса.
el("request-form").addEventListener("submit", (event) => {event.preventDefault(); action(() => submit(true));}); // Обычная отправка формы запрашивает контролируемое demo forwarding.
el("check-only").addEventListener("click", () => action(() => submit(false))); // Отдельная кнопка проверяет текст без вызова агента.
el("new-session").addEventListener("click", () => action(async () => {await newSession(); message("Создана новая сессия. Предыдущие отложенные действия не используются этой вкладкой.");})); // Новая сессия сбрасывает локальную привязку к прежнему pending payload.
el("refresh").addEventListener("click", () => action(async () => {await refresh(); await health(); message("История обновлена.");})); // Ручное обновление перечитывает историю и readiness.
el("review-form").addEventListener("submit", (event) => {event.preventDefault(); action(inspectReview);}); // Форма reviewer загружает описание до возможности подтверждения.
el("approve-action").addEventListener("click", () => action(async () => { // Выдача approval является отдельным действием reviewer.
  if (!state.review) throw new Error("Сначала выберите действие."); // Без выбранного review подтверждение не отправляется.
  const response = await api(`/v1/reviews/${encodeURIComponent(state.review.check_id)}/approve`, {method: "POST", body: "{}"}); // Отправляет пустое тело: сервер использует ранее связанное точное действие.
  el("approval-result").textContent = `Approval ID: ${response.approval_id}`; // Показывает выданный UUID подтверждения для передачи инициатору.
  state.review = null; await refresh(); message("Подтверждение выдано. Передайте approval ID инициатору в его вкладку."); // Сбрасывает текущий выбор и обновляет историю после выдачи approval.
})); // Завершает обработчик подтверждения.
el("resume-form").addEventListener("submit", (event) => { // Форма инициатора применяет полученный approval к сохранённому payload.
  event.preventDefault(); action(async () => { // Останавливает обычную отправку формы и включает общую обработку ошибок.
    if (!state.pending) throw new Error("Нет сохранённого действия. Проверьте запрос заново."); // Без сохранённого точного действия нельзя продолжить исполнение.
    const data = await api("/v1/agent/turns", {method: "POST", headers: {"Idempotency-Key": state.pending.key}, // Повтор отправляется с тем же Idempotency-Key, чтобы исключить дубль записи.
      body: JSON.stringify({...state.pending.body, approval_id: el("approval").value.trim()})}); // Сохраняет исходное тело и добавляет только введённый approval_id.
    showResult(data, state.pending.body.text); if (!data.execution.replayed) state.turns++; // Replay показывает прежний результат без увеличения счётчика исполнений.
    sessionLabel(); el("pending-panel").hidden = true; // Обновляет подпись сессии и скрывает панель уже обработанного действия.
    await refresh(); message(data.execution.replayed ? "Получен сохранённый результат без повторного исполнения." : "Подтверждённое действие исполнено."); // Сообщает, было ли новое исполнение или возврат сохранённого результата.
  }); // Завершает асинхронную операцию применения approval.
}); // Завершает обработчик формы продолжения.
