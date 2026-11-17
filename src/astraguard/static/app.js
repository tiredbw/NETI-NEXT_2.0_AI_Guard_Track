"use strict";
const el = (id) => document.getElementById(id);
const state = {token: "", me: null, session: null, turns: 0, pending: null, review: null};
const errors = {
  UNAUTHORIZED: "Ключ не принят. Проверьте его и войдите заново.",
  SESSION_NOT_FOUND: "Сессия истекла или сервер перезапущен. Создайте новую сессию.",
  RATE_LIMIT: "Слишком много запросов. Подождите минуту.",
  DETECTOR_CAPACITY: "Детектор занят. Повторите запрос через несколько секунд.",
  APPROVAL_EXPIRED_OR_USED: "Подтверждение истекло или использовано. Проверьте действие заново.",
  APPROVAL_MISMATCH: "Точное действие или политика изменились. Нужна новая проверка.",
  SESSION_CONTEXT_CHANGED: "Контекст сессии изменился. Проверьте действие и подтвердите его заново.",
  RESOURCE_CHANGED: "Ресурс изменился. Нужна новая проверка.",
  REVIEW_NOT_FOUND: "Подтверждаемое действие не найдено в пределах ваших полномочий.",
  ALREADY_APPROVED: "Подтверждение уже выдано. Используйте ранее полученный approval ID.",
  AUDIT_UNAVAILABLE: "Журнал недоступен. Исполнение остановлено. Повторите позже.",
};
function message(text, error = false) {
  el("message").textContent = text;
  el("message").className = error ? "error" : "";
}
async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers: {
    ...(options.body ? {"Content-Type": "application/json"} : {}),
    Authorization: `Bearer ${state.token}`, ...(options.headers || {}),
  }, signal: AbortSignal.timeout(30000)});
  const data = await response.json();
  if (!response.ok) {
    const code = data.error?.code || `HTTP_${response.status}`;
    throw new Error(errors[code] || `Запрос остановлен: ${code}.`);
  }
  return data;
}
async function action(work) {
  document.querySelectorAll("button").forEach((button) => {button.disabled = true;});
  el("workspace").setAttribute("aria-busy", "true");
  message("Обработка запроса…");
  try {await work();} catch (error) {
    message(error.name === "TimeoutError" ? "Время ожидания истекло. Для подтверждённой записи повтор использует прежний ключ операции." :
      error instanceof TypeError ? "Нет связи с сервером. Проверьте локальный запуск и повторите запрос." : error.message, true);
  } finally {
    document.querySelectorAll("button").forEach((button) => {button.disabled = false;});
    el("approve-action").disabled = !state.review;
    el("workspace").setAttribute("aria-busy", "false");
  }
}
async function newSession() {
  const session = await api("/v1/sessions", {method: "POST"});
  state.session = session.session_id;
  state.turns = 0;
  state.pending = null;
  el("pending-panel").hidden = true;
  el("result-content").hidden = true;
  el("result-empty").hidden = false;
  el("checked-input").textContent = "";
  sessionLabel();
}
function sessionLabel() {
  el("session-label").textContent = `Сессия ${state.session?.slice(0, 8)} · завершённых отправок: ${state.turns}/4`;
}
async function health() {
  try {
    const response = await fetch("/health/ready", {signal: AbortSignal.timeout(3000)});
    const data = await response.json();
    el("health").textContent = data.status === "ready" ? "Сервис готов · детектор доступен" :
      "Детектор ещё не проверен или недоступен. При сбое запрос будет остановлен для проверки.";
  } catch {el("health").textContent = "Состояние сервиса не удалось получить.";}
}
function showResult(data, checkedText = null) {
  const check = data.check || data;
  const execution = data.execution;
  el("result-empty").hidden = true;
  el("result-content").hidden = false;
  el("checked-input").textContent = checkedText === null ? "Исходный текст этого события в журнале не хранится." :
    `Проверено: ${checkedText.slice(0, 160)}${checkedText.length > 160 ? "…" : ""}`;
  el("result-stale").hidden = checkedText === null || el("prompt").value === checkedText;
  el("decision").textContent = check.decision;
  el("decision").className = ["ALLOW", "REVIEW", "BLOCK"].includes(check.decision) ? check.decision : "";
  el("risk").textContent = `Риск: ${check.risk || "не указан"}`;
  el("explanation").textContent = check.explanation || "Событие аудита.";
  el("threats").textContent = (check.threats || []).map((t) => t.category).join(", ") || "Не обнаружены / не оценивались";
  el("reasons").textContent = (check.reason_codes || []).join(", ") || "Нет";
  el("policy-ids").textContent = (check.policy_ids || []).join(", ") || "Запреты политик не сработали";
  el("timing").textContent = typeof check.timing_ms?.total === "number" ? `${Math.round(check.timing_ms.total)} мс (до сохранения аудита)` : "Не измерялось";
  el("detector").textContent = check.detector?.status || "Не вызывался";
  const steps = ["Результат проверки зарегистрирован в аудите."];
  if (!execution) steps.push("Передача агенту не запрашивалась; для событий истории трасса не восстанавливается.");
  else if (execution.replayed) steps.push("Возвращён сохранённый результат. Агент повторно не вызывался.");
  else if (!execution.forwarded) steps.push("Остановлено на шлюзе. Вызовов целевого агента: 0.");
  else {
    steps.push("Запрос передан демонстрационному агенту. Вызовов: 1.");
    if (execution.tool_check) steps.push(`Повторная проверка инструмента: ${execution.tool_check.decision}.`);
    steps.push(execution.status === "completed" ? "Демонстрационное действие выполнено." : "Исполнение остановлено; результат не выдан.");
  }
  el("trace").replaceChildren(...steps.map((text) => {const item = document.createElement("li"); item.textContent = text; return item;}));
  el("agent-output").hidden = !execution?.result;
  el("agent-output").textContent = execution?.result?.content || (execution?.result?.updated ? "Синтетический черновик обновлён." : "");
}
async function refresh() {
  const history = await api("/v1/checks?limit=20");
  const rows = history.items.map((event) => {
    const row = document.createElement("tr");
    const values = [new Date(event.created_at).toLocaleTimeString("ru-RU"), event.decision,
      (event.reason_codes || []).join(", "), event.id];
    values.forEach((value, index) => {
      const cell = document.createElement("td"); cell.textContent = value;
      if (index === 1 && ["ALLOW", "REVIEW", "BLOCK"].includes(value)) cell.className = value;
      row.append(cell);
    });
    const cell = document.createElement("td");
    const button = document.createElement("button"); button.className = "text-button";
    const canReview = state.me.roles.includes("security_reviewer") && event.review?.approvable;
    button.textContent = canReview ? "Рассмотреть" : "Подробнее";
    button.addEventListener("click", () => action(async () => {
      if (state.me.roles.includes("security_reviewer")) {
        if (canReview) {el("review-id").value = event.id; await inspectReview();}
        else message(`${event.decision}: ${(event.reason_codes || []).join(", ")}. ID ${event.id}`);
      } else {showResult(event); message(`Показано событие ${event.id}.`);}
    }));
    cell.append(button); row.append(cell); return row;
  });
  if (!rows.length) {
    const row = document.createElement("tr"); const cell = document.createElement("td");
    cell.colSpan = 5; cell.textContent = "Проверок пока нет."; row.append(cell); rows.push(row);
  }
  el("history-body").replaceChildren(...rows);
  if (state.me.roles.includes("security_reviewer")) {
    const stats = await api("/v1/stats");
    el("stats").textContent = `За 7 дней: ALLOW ${stats.decisions.ALLOW}, REVIEW ${stats.decisions.REVIEW}, BLOCK ${stats.decisions.BLOCK}. Операционная статистика, не оценка точности.`;
  }
}
async function inspectReview() {
  state.review = null;
  el("review-details").hidden = true;
  const id = el("review-id").value.trim();
  const details = await api(`/v1/reviews/${encodeURIComponent(id)}`);
  state.review = details;
  const pairs = [["Инициатор", details.requester_id], ["Инструмент", details.tool], ["Ресурс", `${details.resource_id}, версия ${details.resource_version}`],
    ["Размер нового текста", `${details.content_length} символов`], ["HMAC точного действия", details.binding_hmac], ["Срок действия", new Date(details.expires_at).toLocaleTimeString("ru-RU")]];
  el("review-summary").replaceChildren(...pairs.flatMap(([name, value]) => {
    const dt = document.createElement("dt"); dt.textContent = name;
    const dd = document.createElement("dd"); dd.textContent = value; return [dt, dd];
  }));
  el("approval-result").textContent = "";
  el("review-details").hidden = false;
  message("Проверьте инициатора, ресурс и HMAC перед подтверждением.");
}
el("login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  state.token = el("token").value.trim(); el("token").value = "";
  action(async () => {
    state.me = await api("/v1/me");
    const reviewer = state.me.roles.includes("security_reviewer");
    el("subject").textContent = state.me.subject_id;
    el("role").textContent = `Роль: ${state.me.roles.join(", ")}`;
    el("tenant").textContent = `Tenant: ${state.me.tenant_id}`;
    const policies = await api("/v1/policies");
    el("policy").replaceChildren(...policies.map((policy) => {
      const option = document.createElement("option"); option.value = policy.id;
      option.textContent = `${policy.id} · версия ${policy.version}`; return option;
    }));
    if (!reviewer) await newSession();
    el("requester").hidden = reviewer; el("reviewer").hidden = !reviewer;
    await refresh(); await health();
    el("login-panel").hidden = true; el("workspace").hidden = false;
    message("Вход выполнен. Полномочия получены с сервера.");
  });
});
el("logout").addEventListener("click", () => {
  state.token = ""; state.me = null; state.session = null; state.pending = null; state.review = null;
  el("workspace").hidden = true; el("login-panel").hidden = false;
  ["prompt", "approval", "review-id"].forEach((id) => {el(id).value = "";});
  ["history-body", "review-summary", "agent-output", "approval-result"].forEach((id) => el(id).replaceChildren());
  ["subject", "role", "tenant", "pending-check", "explanation", "reasons", "threats", "policy-ids", "stats", "checked-input"].forEach((id) => {el(id).textContent = "";});
  el("review-details").hidden = true; el("result-content").hidden = true; el("result-empty").hidden = false;
  message("Вы вышли. Ключ удалён из состояния страницы."); el("token").focus();
});
function edited() {if (!el("result-content").hidden) el("result-stale").hidden = false;}
el("prompt").addEventListener("input", edited);
document.querySelectorAll("[data-example]").forEach((button) => button.addEventListener("click", () => {el("prompt").value = button.dataset.example; edited(); el("prompt").focus();}));
async function submit(forward) {
  const body = {text: el("prompt").value, session_id: state.session, policy_id: el("policy").value};
  if (!body.text.trim()) throw new Error("Введите запрос для проверки.");
  const data = await api(forward ? "/v1/agent/turns" : "/v1/checks", {method: "POST", body: JSON.stringify(body)});
  showResult(data, body.text);
  const check = data.check || data;
  state.pending = forward && check.review?.approvable ? {body, key: crypto.randomUUID(), checkId: check.id} : null;
  el("pending-panel").hidden = !state.pending;
  el("pending-check").textContent = state.pending?.checkId || "";
  el("approval").value = "";
  if (data.execution?.status === "completed") state.turns++;
  sessionLabel(); await refresh(); await health();
  message(`Решение: ${check.decision}. ${data.execution?.forwarded ? "Запрос передан агенту." : "Агент не вызывался."}`);
}
el("request-form").addEventListener("submit", (event) => {event.preventDefault(); action(() => submit(true));});
el("check-only").addEventListener("click", () => action(() => submit(false)));
el("new-session").addEventListener("click", () => action(async () => {await newSession(); message("Создана новая сессия. Предыдущие отложенные действия не используются этой вкладкой.");}));
el("refresh").addEventListener("click", () => action(async () => {await refresh(); await health(); message("История обновлена.");}));
el("review-form").addEventListener("submit", (event) => {event.preventDefault(); action(inspectReview);});
el("approve-action").addEventListener("click", () => action(async () => {
  if (!state.review) throw new Error("Сначала выберите действие.");
  const response = await api(`/v1/reviews/${encodeURIComponent(state.review.check_id)}/approve`, {method: "POST", body: "{}"});
  el("approval-result").textContent = `Approval ID: ${response.approval_id}`;
  state.review = null; await refresh(); message("Подтверждение выдано. Передайте approval ID инициатору в его вкладку.");
}));
el("resume-form").addEventListener("submit", (event) => {
  event.preventDefault(); action(async () => {
    if (!state.pending) throw new Error("Нет сохранённого действия. Проверьте запрос заново.");
    const data = await api("/v1/agent/turns", {method: "POST", headers: {"Idempotency-Key": state.pending.key},
      body: JSON.stringify({...state.pending.body, approval_id: el("approval").value.trim()})});
    showResult(data, state.pending.body.text); if (!data.execution.replayed) state.turns++;
    sessionLabel(); el("pending-panel").hidden = true;
    await refresh(); message(data.execution.replayed ? "Получен сохранённый результат без повторного исполнения." : "Подтверждённое действие исполнено.");
  });
});
