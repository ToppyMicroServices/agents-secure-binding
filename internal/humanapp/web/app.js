"use strict";

// A fragment never reaches the HTTP server. Clear it before any request and
// keep the login token only until its one POST; never persist it in storage.
let fragmentToken = new URLSearchParams(window.location.hash.slice(1)).get("login");
if (window.location.hash) window.history.replaceState(null, "", window.location.pathname + window.location.search);

const element = (id) => document.getElementById(id);
let csrf = "";
let loggedIn = false;
let loading = false;
let inboxGeneration = 0;
let refreshQueued = false;
let deciding = false;
let selectedDecision = null;
const unknownOperations = new Set();
let renderedCards = new Map();

function setNotice(message, error = false) {
  const notice = element("notice");
  notice.textContent = message;
  notice.classList.toggle("error", error);
  notice.hidden = !message;
}

function showLogin(message = "") {
  inboxGeneration++;
  refreshQueued = false;
  loggedIn = false;
  csrf = "";
  element("dashboard").hidden = true;
  element("login-view").hidden = false;
  element("login-message").textContent = message;
  element("pending-list").replaceChildren();
  element("history-list").replaceChildren();
  renderedCards.clear();
  if (element("decision-dialog").open) element("decision-dialog").close();
}

async function request(path, options = {}) {
  const generation = inboxGeneration;
  let response;
  try {
    response = await fetch(path, {credentials: "same-origin", cache: "no-store", ...options});
  } catch (_) {
    throw {message: "接続を確認できません。操作を繰り返さず、一覧を更新してください。", outcome_unknown: options.method === "POST"};
  }
  if (response.status === 204) return null;
  let body;
  try { body = await response.json(); } catch (_) {
    throw {message: "結果を読み取れません。一覧を更新して状態を確認してください。", outcome_unknown: options.method === "POST"};
  }
  if (!response.ok) {
    if (response.status === 401 && generation === inboxGeneration) showLogin("セッションが終了しました。再度ログインしてください。");
    throw body;
  }
  return body;
}

function post(path, data, includeCSRF = true) {
  const headers = {"Content-Type": "application/json"};
  if (includeCSRF) headers["X-CSRF-Token"] = csrf;
  return request(path, {method: "POST", headers, body: JSON.stringify(data)});
}

async function activateSession(session) {
  inboxGeneration++;
  csrf = session.csrf_token;
  loggedIn = true;
  element("login-view").hidden = true;
  element("dashboard").hidden = false;
  element("human-participant").textContent = session.human_participant;
  element("gateway-actor").textContent = session.gateway_actor;
  element("assurance").textContent = session.assurance;
  await refreshInbox();
}

async function login(token) {
  element("login-button").disabled = true;
  element("login-message").textContent = "ログインしています…";
  try {
    const pending = post("/api/session", {token}, false);
    token = "";
    element("login-token").value = "";
    await activateSession(await pending);
    element("login-message").textContent = "";
  } catch (error) {
    element("login-message").textContent = error.message || "ログインできませんでした。";
  } finally {
    token = "";
    element("login-token").value = "";
    element("login-button").disabled = false;
  }
}

function displaySetting(enabled) { return enabled ? "ON · 有効" : "OFF · 無効"; }
function shortSetting(enabled) { return enabled ? "ON" : "OFF"; }
function displayDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat("ja-JP", {dateStyle:"medium", timeStyle:"short"}).format(date);
}
const stateLabels = {PENDING_REVIEW:"確認待ち", APPLIED:"適用済み", DENIED:"拒否済み", STALE:"更新の競合"};

function operationCard(operation) {
  const card = element("operation-template").content.firstElementChild.cloneNode(true);
  const find = (selector) => card.querySelector(selector);
  find(".proposer").textContent = "提案者  " + operation.proposer;
  find(".state-tag").textContent = stateLabels[operation.state] || "状態を確認してください";
  if (operation.state === "APPLIED") find(".state-tag").classList.add("applied");
  if (operation.state === "DENIED") find(".state-tag").classList.add("denied");
  if (operation.state === "STALE") find(".state-tag").classList.add("stale");
  find(".before-value").textContent = displaySetting(operation.before.enabled);
  find(".before-revision").textContent = "revision " + operation.before.revision;
  find(".proposed-value").textContent = displaySetting(operation.change.enabled);
  find(".operation-id").textContent = operation.operation_id;
  find(".proposal-digest").textContent = operation.proposal_digest;
  find(".created-at").textContent = displayDate(operation.created_at);
  if (operation.decided_at) {
    find(".decided-label").hidden = false;
    find(".decided-at").hidden = false;
    find(".decided-at").textContent = displayDate(operation.decided_at);
  }
  const outcome = find(".operation-outcome");
  if (operation.state === "APPLIED") {
    outcome.textContent = "承認された変更を適用しました。" + (operation.after ? " 適用後 revision " + operation.after.revision : "");
    outcome.hidden = false;
  } else if (operation.state === "DENIED") {
    outcome.textContent = "この提案は拒否されました。この提案による設定変更はありません。";
    outcome.hidden = false;
  } else if (operation.state === "STALE") {
    outcome.textContent = "提案後に設定が変わりました。Agentから最新の設定に対する提案が必要です。";
    outcome.hidden = false;
  }
  const actions = find(".operation-actions");
  actions.hidden = operation.state !== "PENDING_REVIEW";
  if (unknownOperations.has(operation.operation_id)) {
    outcome.textContent = "結果確認待ちです。「一覧を更新」で現在の状態を確認してください。";
    outcome.hidden = false;
    find(".approve-button").disabled = true;
    find(".decline-button").disabled = true;
  }
  find(".approve-button").addEventListener("click", () => openDecision(operation, true));
  find(".decline-button").addEventListener("click", () => openDecision(operation, false));
  return card;
}

function syncOperationCards(list, cards) {
  // Reuse unchanged nodes so polling does not close details or steal focus.
  const retained = new Set(cards);
  for (const card of Array.from(list.children)) {
    if (!retained.has(card)) card.remove();
  }
  for (let index = 0; index < cards.length; index++) {
    if (list.children[index] !== cards[index]) {
      list.insertBefore(cards[index], list.children[index] || null);
    }
  }
}

function renderOperationLists(pending, history) {
  const nextCards = new Map();
  const render = (operation) => {
    const signature = JSON.stringify(operation);
    const unknown = unknownOperations.has(operation.operation_id);
    let cached = renderedCards.get(operation.operation_id);
    if (!cached || cached.signature !== signature || cached.unknown !== unknown) {
      const card = operationCard(operation);
      if (cached) card.querySelector(".operation-details").open = cached.card.querySelector(".operation-details").open;
      cached = {signature, unknown, card};
    }
    nextCards.set(operation.operation_id, cached);
    return cached.card;
  };
  syncOperationCards(element("pending-list"), pending.map(render));
  syncOperationCards(element("history-list"), history.map(render));
  renderedCards = nextCards;
}

async function refreshInbox(manual = false) {
  if (!loggedIn || deciding || element("decision-dialog").open) return;
  if (loading) {
    refreshQueued = true;
    return;
  }
  const generation = inboxGeneration;
  loading = true;
  element("refresh-button").disabled = true;
  try {
    const response = await request("/api/inbox");
    // Discard reads from before a decision or session change, even when its
    // dialog has already closed. An open dialog must also keep its reviewed card.
    if (generation !== inboxGeneration || !loggedIn || deciding || element("decision-dialog").open) return;
    const operations = Array.isArray(response.operations) ? response.operations : [];
    const resolvedUnknown = manual && unknownOperations.size > 0;
    if (manual) unknownOperations.clear();
    const pending = operations.filter((item) => item.state === "PENDING_REVIEW");
    const history = operations.filter((item) => item.state !== "PENDING_REVIEW");
    history.sort((a,b) => String(b.decided_at || b.created_at).localeCompare(String(a.decided_at || a.created_at)));
    renderOperationLists(pending, history);
    const pendingTotal = response.inbox ? response.inbox.pending : pending.length;
    const historyTotal = response.inbox ? response.inbox.total - pendingTotal : history.length;
    const truncated = pendingTotal + historyTotal > operations.length;
    element("pending-count").textContent = String(pendingTotal);
    element("history-count").textContent = historyTotal ? (history.length < historyTotal ? history.length + " / " + historyTotal : historyTotal) + " 件" : "";
    element("inbox-window").hidden = !truncated;
    element("inbox-window").textContent = truncated ? "確認待ち " + pending.length + " / " + pendingTotal + " 件と、判断済み " + history.length + " / " + historyTotal + " 件を表示しています。確認待ちは古い順に優先します。判断後に一覧を更新すると、次の提案を確認できます。" : "";
    element("empty-state").hidden = pendingTotal !== 0;
    element("empty-history").hidden = history.length !== 0;
    element("empty-history").textContent = historyTotal ? "判断済みの記録は " + historyTotal + " 件あります。現在の表示枠は確認待ちの提案に使用しています。" : "判断の記録はまだありません。";
    if (response.setting) {
      element("current-setting").textContent = displaySetting(response.setting.enabled);
      element("current-revision").textContent = "revision " + response.setting.revision;
    }
    element("last-updated").textContent = "最終更新 " + new Intl.DateTimeFormat("ja-JP", {timeStyle:"medium"}).format(new Date());
    if (resolvedUnknown) setNotice("現在の状態を取得しました。対象の操作IDと判断結果を確認してください。");
    else if (manual) setNotice("一覧を更新しました。");
  } catch (error) {
    if (generation === inboxGeneration && loggedIn) setNotice(error.message || "一覧を取得できませんでした。", true);
  } finally {
    loading = false;
    element("refresh-button").disabled = false;
    if (refreshQueued) {
      refreshQueued = false;
      // Only a new manual read may clear uncertainty, never a queued read.
      await refreshInbox();
    }
  }
}

function openDecision(operation, approve) {
  if (deciding) return;
  selectedDecision = {operation, approve};
  element("decision-heading").textContent = approve ? "この変更を承認しますか？" : "この提案を拒否しますか？";
  element("decision-description").textContent = approve ? "確認した差分をローカル設定に適用します。提案後に設定が変わっている場合は適用しません。" : "この提案による設定変更は行いません。拒否の判断を記録します。";
  element("decision-change").textContent = shortSetting(operation.before.enabled) + " → " + shortSetting(operation.change.enabled);
  element("decision-operation").textContent = operation.operation_id;
  element("decision-warning").textContent = "Gatewayがこの判断を人への帰属として送信します。Human本人の鍵による署名ではありません。";
  element("confirm-decision").textContent = approve ? "承認して適用" : "拒否を確定";
  element("confirm-decision").classList.toggle("danger", !approve);
  element("decision-dialog").showModal();
  element("cancel-decision").focus();
}

element("login-form").addEventListener("submit", async (event) => { event.preventDefault(); await login(element("login-token").value); });
element("refresh-button").addEventListener("click", () => refreshInbox(true));
element("cancel-decision").addEventListener("click", () => { if (!deciding) element("decision-dialog").close(); });
element("decision-dialog").addEventListener("cancel", (event) => { if (deciding) event.preventDefault(); });
element("decision-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!selectedDecision || deciding) return;
  const {operation, approve} = selectedDecision;
  inboxGeneration++;
  deciding = true;
  element("confirm-decision").disabled = true;
  element("cancel-decision").disabled = true;
  element("decision-description").textContent = "判断を送信しています…";
  try {
    const response = await post("/api/decision", {operation_id:operation.operation_id, proposal_digest:operation.proposal_digest, expected_revision:operation.before.revision, approve});
    const result = response.operation;
    setNotice(result ? "操作 " + result.operation_id + "：" + (stateLabels[result.state] || result.state) : "判断の応答を受信しました。一覧で結果を確認してください。");
  } catch (error) {
    if (error.outcome_unknown) unknownOperations.add(operation.operation_id);
    setNotice(error.message || "判断の結果を確認できませんでした。", true);
  } finally {
    deciding = false;
    selectedDecision = null;
    element("confirm-decision").disabled = false;
    element("cancel-decision").disabled = false;
    element("decision-dialog").close();
    await refreshInbox();
  }
});
element("logout-button").addEventListener("click", async () => {
  if (deciding) return;
  try { await post("/api/logout", {}); showLogin(); unknownOperations.clear(); }
  catch (error) { setNotice(error.message || "ログアウトできませんでした。", true); }
});

async function start() {
  if (fragmentToken) {
    const token = fragmentToken;
    fragmentToken = null;
    await login(token);
    return;
  }
  fragmentToken = null;
  try { await activateSession(await request("/api/session")); }
  catch (_) { showLogin(); }
}
setInterval(() => { if (!document.hidden) refreshInbox(); }, 10000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshInbox(); });
start();
