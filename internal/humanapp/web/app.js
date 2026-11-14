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
let authenticationAttempt = 0;
let refreshQueued = false;
let deciding = false;
let selectedDecision = null;
const unknownOperations = new Set();
let renderedCards = new Map();
let historyOffset = 0;
let historyLimit = 100;
let historyTotal = 0;
let lastDecisionID = "";
const reviewedOperations = new Map();
let reviewedCards = new Map();
const recoveryStorageKey = "asb-human-unresolved-v1";
let recoveryStateInvalid = false;

function recoveryMetadata(operation) {
  return {operation_id:operation.operation_id, proposal_digest:operation.proposal_digest,
    before:{enabled:operation.before.enabled, revision:operation.before.revision},
    change:{enabled:operation.change.enabled}, proposer:operation.proposer || "agent:local-proposer",
    created_at:operation.created_at || ""};
}

function validRecoveryMetadata(operation) {
  return operation && typeof operation.operation_id === "string" && /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(operation.operation_id) &&
    typeof operation.proposal_digest === "string" && /^sha256:[0-9a-f]{64}$/.test(operation.proposal_digest) && operation.before &&
    typeof operation.before.enabled === "boolean" && Number.isSafeInteger(operation.before.revision) && operation.before.revision >= 0 &&
    operation.change && typeof operation.change.enabled === "boolean" &&
    operation.proposer === "agent:local-proposer" && typeof operation.created_at === "string" && operation.created_at.length <= 40;
}

function recoveryWarning(message) {
  element("recovery-warning").hidden = !message;
  element("recovery-warning").textContent = message;
}

function persistRecovery() {
  try {
    const operations = Array.from(unknownOperations, (id) => recoveryMetadata(reviewedOperations.get(id)));
    if (operations.length) window.sessionStorage.setItem(recoveryStorageKey, JSON.stringify({version:1, operations}));
    else window.sessionStorage.removeItem(recoveryStorageKey);
    if (!recoveryStateInvalid) recoveryWarning("");
    return true;
  } catch (_) {
    recoveryWarning("このブラウザーでは復旧情報を保存できません。結果不明の操作がある間は、このタブを閉じたり再読み込みしないでください。復旧には元のASBサービスを停止して終了を確認し、同じデータディレクトリで再起動してから新しいタブで状態を確認します。");
    return false;
  }
}

function restoreRecovery() {
  let raw;
  try { raw = window.sessionStorage.getItem(recoveryStorageKey); }
  catch (_) {
    recoveryStateInvalid = true;
    recoveryWarning("復旧情報にアクセスできないため判断を停止しています。元のASBサービスを停止して終了を確認し、同じデータディレクトリで再起動してください。その後、タブの保存機能が使えるブラウザーで新しいタブを開き、対象の状態を確認してください。");
    return;
  }
  if (!raw) return;
  try {
    if (raw.length > 4 * 1024 * 1024) throw new Error("recovery data too large");
    const saved = JSON.parse(raw);
    if (saved.version !== 1 || !Array.isArray(saved.operations) || saved.operations.length > 5000 || !saved.operations.every(validRecoveryMetadata)) throw new Error("invalid recovery data");
    for (const operation of saved.operations) {
      if (unknownOperations.has(operation.operation_id)) throw new Error("duplicate recovery operation");
      const metadata = recoveryMetadata(operation);
      reviewedOperations.set(operation.operation_id, {...metadata, state:"PENDING_REVIEW"});
      unknownOperations.add(operation.operation_id);
      lastDecisionID = operation.operation_id;
    }
  } catch (_) {
    recoveryStateInvalid = true;
    recoveryWarning("保存した復旧情報を読み取れないため、判断を停止しています。元のASBサービスを停止してプロセスの終了を確認し、同じデータディレクトリで再起動してください。その後にこのタブを閉じ、新しいタブで対象の状態を確認してください。");
  }
}

restoreRecovery();
if (typeof window.addEventListener === "function") window.addEventListener("beforeunload", (event) => {
  if (unknownOperations.size || deciding || recoveryStateInvalid) { event.preventDefault(); event.returnValue = ""; }
});

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
  element("reviewed-list").replaceChildren();
  reviewedCards.clear();
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
  const attempt = ++authenticationAttempt;
  inboxGeneration++;
  element("login-button").disabled = true;
  element("login-message").textContent = "ログインしています…";
  try {
    const pending = post("/api/session", {token}, false);
    token = "";
    element("login-token").value = "";
    const session = await pending;
    if (attempt !== authenticationAttempt) return;
    await activateSession(session);
    element("login-message").textContent = "";
  } catch (error) {
    if (attempt === authenticationAttempt) element("login-message").textContent = error.message || "ログインできませんでした。";
  } finally {
    token = "";
    element("login-token").value = "";
    if (attempt === authenticationAttempt) element("login-button").disabled = false;
  }
}

function displaySetting(enabled) { return enabled ? "ON · 有効" : "OFF · 無効"; }
function shortSetting(enabled) { return enabled ? "ON" : "OFF"; }
function displayDate(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat("ja-JP", {dateStyle:"medium", timeStyle:"short"}).format(date);
}
const stateLabels = {PENDING_REVIEW:"確認待ち", APPLIED:"適用済み", DENIED:"拒否済み", NOT_APPLICABLE:"該当なし", UNDETERMINED:"判断不明", OUTCOME_UNKNOWN:"処理結果不明", STALE:"更新の競合"};
const decisionChoices = {
  APPROVE: {selector:".approve-button", heading:"この変更を許可しますか？", description:"確認した差分をローカル設定に適用します。提案後に設定が変わっている場合は適用しません。", confirm:"許可して適用"},
  DECLINE: {selector:".decline-button", heading:"この提案を拒否しますか？", description:"この提案による設定変更は行いません。拒否の判断を記録します。", confirm:"拒否を確定"},
  NOT_APPLICABLE: {selector:".not-applicable-button", heading:"この提案は該当なしですか？", description:"自分の判断対象ではないことを記録します。許可として扱わず、この提案による設定変更は行いません。", confirm:"該当なしを確定"},
  UNDETERMINED: {selector:".undetermined-button", heading:"この提案を判断できませんか？", description:"情報不足などで判断できないことを記録します。許可として扱わず、この提案による設定変更は行いません。これは送信後の処理結果不明とは別の判断です。", confirm:"判断不明を確定"},
};
function validDecision(decision) {
  return typeof decision === "string" && Object.prototype.hasOwnProperty.call(decisionChoices, decision);
}

function operationCard(operation) {
  const card = element("operation-template").content.firstElementChild.cloneNode(true);
  const find = (selector) => card.querySelector(selector);
  find(".proposer").textContent = "提案者  " + operation.proposer;
  find(".state-tag").textContent = stateLabels[operation.state] || "状態を確認してください";
  if (operation.state === "APPLIED") find(".state-tag").classList.add("applied");
  if (operation.state === "DENIED") find(".state-tag").classList.add("denied");
  if (operation.state === "NOT_APPLICABLE" || operation.state === "UNDETERMINED") find(".state-tag").classList.add("no-change");
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
    outcome.textContent = "許可された変更を適用しました。" + (operation.after ? " 適用後 revision " + operation.after.revision : "");
    outcome.hidden = false;
  } else if (operation.state === "DENIED") {
    outcome.textContent = "この提案は拒否されました。この提案による設定変更はありません。";
    outcome.hidden = false;
  } else if (operation.state === "NOT_APPLICABLE") {
    outcome.textContent = "自分の判断対象ではないとして、該当なしを記録しました。この提案による設定変更はありません。";
    outcome.hidden = false;
  } else if (operation.state === "UNDETERMINED") {
    outcome.textContent = "判断できないという回答を記録しました。この提案による設定変更はありません。処理結果不明とは別の判断です。";
    outcome.hidden = false;
  } else if (operation.state === "STALE") {
    outcome.textContent = "提案後に設定が変わりました。Agentから最新の設定に対する提案が必要です。";
    outcome.hidden = false;
  }
  const actions = find(".operation-actions");
  actions.hidden = operation.state !== "PENDING_REVIEW";
  const outcomeUnknown = unknownOperations.has(operation.operation_id) || operation.state === "OUTCOME_UNKNOWN";
  if (outcomeUnknown) {
    find(".state-tag").textContent = stateLabels.OUTCOME_UNKNOWN;
    outcome.textContent = "処理結果不明です。判断が記録・適用されたかを確認できません。再送せず「一覧を更新」で現在の状態を確認してください。人間の回答である「判断不明」とは異なります。";
    outcome.hidden = false;
  }
  for (const [decision, choice] of Object.entries(decisionChoices)) {
    find(choice.selector).disabled = recoveryStateInvalid || outcomeUnknown || operation.state !== "PENDING_REVIEW";
    find(choice.selector).addEventListener("click", () => openDecision(operation, decision));
  }
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

function rememberReview(operation) {
  lastDecisionID = operation.operation_id;
  reviewedOperations.set(operation.operation_id, operation);
  for (const id of reviewedOperations.keys()) {
    if (id !== lastDecisionID && !unknownOperations.has(id)) reviewedOperations.delete(id);
  }
}

// Keep the last result and every unresolved request outside either list's
// bounded window. A large pending queue must not hide a lost response.
function renderReviewedOperations() {
  const next = new Map();
  const cards = [];
  for (const operation of reviewedOperations.values()) {
    const signature = JSON.stringify(operation);
    const unknown = unknownOperations.has(operation.operation_id);
    let cached = reviewedCards.get(operation.operation_id);
    if (!cached || cached.signature !== signature || cached.unknown !== unknown) {
      const card = operationCard(operation);
      if (cached) card.querySelector(".operation-details").open = cached.card.querySelector(".operation-details").open;
      cached = {signature, unknown, card};
    }
    next.set(operation.operation_id, cached);
    cards.push(cached.card);
  }
  syncOperationCards(element("reviewed-list"), cards);
  reviewedCards = next;
  element("reviewed-section").hidden = cards.length === 0;
}

function matchingOperation(operation, expected) {
  return operation && operation.operation_id === expected.operation_id &&
    operation.proposal_digest === expected.proposal_digest &&
    operation.before && operation.before.revision === expected.before.revision &&
    ["PENDING_REVIEW", "APPLIED", "DENIED", "NOT_APPLICABLE", "UNDETERMINED", "STALE"].includes(operation.state);
}

async function reconcileUnknown(generation) {
  for (const id of Array.from(unknownOperations)) {
    const expected = reviewedOperations.get(id);
    if (!expected) continue;
    const query = new URLSearchParams({operation_id:id, proposal_digest:expected.proposal_digest});
    const response = await request("/api/operation?" + query);
    if (generation !== inboxGeneration || !loggedIn || deciding || element("decision-dialog").open) return;
    if (!matchingOperation(response.operation, expected)) {
      throw {message:"対象の操作IDと提案digestに一致する結果を取得できませんでした。処理結果不明の表示を維持します。"};
    }
    reviewedOperations.set(id, response.operation);
    // A pending snapshot is not a fence against the original POST arriving
    // later. Keep all choices blocked until an immutable terminal result.
    if (response.operation.state !== "PENDING_REVIEW") { unknownOperations.delete(id); persistRecovery(); }
  }
}

function updateHistoryControls() {
  element("history-previous").disabled = loading || historyOffset === 0;
  element("history-next").disabled = loading || historyOffset + historyLimit >= historyTotal;
  element("history-latest").disabled = loading || historyOffset === 0;
}

function renderCapacity(capacity) {
  element("storage-status").hidden = !capacity;
  if (!capacity) return;
  element("storage-usage").textContent = "保存済み提案 " + capacity.operations + " / " + capacity.operation_limit + " 件 · 変更記録 " + capacity.commands + " / " + capacity.command_limit + " 件";
  const full = capacity.operations >= capacity.operation_limit || capacity.commands >= capacity.command_limit;
  const near = full || capacity.operations >= capacity.operation_limit * .8 || capacity.commands >= capacity.command_limit * .8;
  element("capacity-warning").hidden = !near;
  element("capacity-warning").textContent = full ? "新しい提案の保存上限です。記録の削除や再送では解決せず、保存・検証してから別のデータディレクトリへ移行してください。" : "保存上限の80%以上を使用しています。上限に達する前に記録の保存と次のデータディレクトリを準備してください。";
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
  updateHistoryControls();
  try {
    const response = await request(historyOffset ? "/api/inbox?history_offset=" + historyOffset : "/api/inbox");
    // Discard reads from before a decision or session change, even when its
    // dialog has already closed. An open dialog must also keep its reviewed card.
    if (generation !== inboxGeneration || !loggedIn || deciding || element("decision-dialog").open) return;
    let operations = Array.isArray(response.operations) ? response.operations : [];
    const hadUnknown = manual && unknownOperations.size > 0;
    let reconciliationError;
    if (hadUnknown) {
      try { await reconcileUnknown(generation); } catch (error) { reconciliationError = error; }
      if (generation !== inboxGeneration || !loggedIn || deciding || element("decision-dialog").open) return;
    }
    // A later exact status can resolve a mutation after this inbox snapshot.
    // Terminal decisions are immutable; do not enable an older pending card.
    operations = operations.map((operation) => {
      const reviewed = reviewedOperations.get(operation.operation_id);
      return reviewed && reviewed.state !== "PENDING_REVIEW" && matchingOperation(reviewed, operation) ? reviewed : operation;
    });
    const pending = operations.filter((item) => item.state === "PENDING_REVIEW");
    const history = Array.isArray(response.history) ? response.history : operations.filter((item) => item.state !== "PENDING_REVIEW");
    // The server orders the complete history before applying its page limit.
    renderOperationLists(pending, history);
    renderReviewedOperations();
    const pendingTotal = response.inbox ? response.inbox.pending : pending.length;
    historyTotal = response.inbox ? response.inbox.total - pendingTotal : history.length;
    historyLimit = response.inbox?.history_limit || 100;
    const truncated = pendingTotal > pending.length;
    element("pending-count").textContent = String(pendingTotal);
    element("history-count").textContent = historyTotal ? (history.length ? (historyOffset + 1) + "–" + (historyOffset + history.length) : "0") + " / " + historyTotal + " 件" : "";
    element("inbox-window").hidden = !truncated;
    element("inbox-window").textContent = truncated ? "確認待ち " + pending.length + " / " + pendingTotal + " 件を古い順に表示しています。判断後に次の提案が表示されます。判断済みの履歴は別のページで確認できます。" : "";
    element("empty-state").hidden = pendingTotal !== 0;
    element("empty-history").hidden = history.length !== 0;
    element("empty-history").textContent = historyTotal ? "判断済みの記録は " + historyTotal + " 件あります。「最新の判断へ」で先頭のページを確認してください。" : "判断の記録はまだありません。";
    renderCapacity(response.capacity);
    if (response.setting) {
      element("current-setting").textContent = displaySetting(response.setting.enabled);
      element("current-revision").textContent = "revision " + response.setting.revision;
    }
    element("last-updated").textContent = "最終更新 " + new Intl.DateTimeFormat("ja-JP", {timeStyle:"medium"}).format(new Date());
    if (reconciliationError) setNotice(reconciliationError.message || "対象の結果を照会できませんでした。処理結果不明の表示を維持します。", true);
    else if (hadUnknown && unknownOperations.size === 0) setNotice("対象の操作IDと提案digestを個別に照会しました。「直前の判断・結果確認」で状態を確認してください。");
    else if (hadUnknown) setNotice("対象はまだ確認待ちです。元の送信が処理中の可能性があるため、判断ボタンは無効のままです。再送せず、時間を置いて一覧を更新してください。解消しない場合はガイドの中断した判断の復旧手順を確認してください。", true);
    else if (manual) setNotice("一覧を更新しました。");
    return true;
  } catch (error) {
    if (generation === inboxGeneration && loggedIn) setNotice(error.message || "一覧を取得できませんでした。", true);
    return false;
  } finally {
    loading = false;
    element("refresh-button").disabled = false;
    updateHistoryControls();
    if (refreshQueued) {
      refreshQueued = false;
      // Only a new manual read may clear uncertainty, never a queued read.
      await refreshInbox();
    }
  }
}

function openDecision(operation, decision) {
  if (deciding || recoveryStateInvalid) return;
  if (!validDecision(decision)) {
    selectedDecision = null;
    element("decision-dialog").close();
    setNotice("有効な判断を選んでください。", true);
    return;
  }
  if (operation.state !== "PENDING_REVIEW" || unknownOperations.has(operation.operation_id)) return;
  const choice = decisionChoices[decision];
  selectedDecision = {operation, decision};
  element("decision-heading").textContent = choice.heading;
  element("decision-description").textContent = choice.description;
  element("decision-change").textContent = shortSetting(operation.before.enabled) + " → " + shortSetting(operation.change.enabled);
  element("decision-operation").textContent = operation.operation_id;
  element("decision-warning").textContent = "Gatewayがこの判断を人への帰属として送信します。Human本人の鍵による署名ではありません。";
  element("confirm-decision").textContent = choice.confirm;
  element("confirm-decision").classList.toggle("primary", decision === "APPROVE");
  element("confirm-decision").classList.toggle("danger", decision === "DECLINE");
  element("confirm-decision").classList.toggle("secondary", decision === "NOT_APPLICABLE" || decision === "UNDETERMINED");
  element("decision-dialog").showModal();
  element("cancel-decision").focus();
}

element("login-form").addEventListener("submit", async (event) => { event.preventDefault(); await login(element("login-token").value); });
element("refresh-button").addEventListener("click", () => refreshInbox(true));
for (const [id, offset] of [["history-previous", () => Math.max(0, historyOffset - historyLimit)], ["history-next", () => historyOffset + historyLimit], ["history-latest", () => 0]]) {
  element(id).addEventListener("click", async () => {
    if (loading || deciding || element("decision-dialog").open) return;
    const previousOffset = historyOffset;
    historyOffset = offset();
    inboxGeneration++;
    const generation = inboxGeneration;
    if (await refreshInbox() === false && generation === inboxGeneration) {
      historyOffset = previousOffset;
      updateHistoryControls();
    }
  });
}
element("cancel-decision").addEventListener("click", () => { if (!deciding) element("decision-dialog").close(); });
element("decision-dialog").addEventListener("cancel", (event) => { if (deciding) event.preventDefault(); });
element("decision-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!selectedDecision || deciding) return;
  const {operation, decision} = selectedDecision;
  if (!validDecision(decision) || operation.state !== "PENDING_REVIEW" || unknownOperations.has(operation.operation_id)) {
    selectedDecision = null;
    element("decision-dialog").close();
    setNotice("判断を送信できません。一覧を更新して確認してください。", true);
    return;
  }
  inboxGeneration++;
  deciding = true;
  element("confirm-decision").disabled = true;
  element("cancel-decision").disabled = true;
  element("decision-description").textContent = "判断を送信しています…";
  rememberReview(operation);
  // Record the unresolved request before sending, including reload mid-flight.
  unknownOperations.add(operation.operation_id);
  try {
    if (!persistRecovery()) throw {message:"復旧情報を保存できないため、判断は送信しませんでした。タブの保存機能を確認してください。", outcome_unknown:false};
    const response = await post("/api/decision", {operation_id:operation.operation_id, proposal_digest:operation.proposal_digest, expected_revision:operation.before.revision, decision});
    const result = response.operation;
    if (!matchingOperation(result, operation) || result.state === "PENDING_REVIEW") throw {message:"判断の応答が対象と一致しません。再送せず一覧を更新してください。", outcome_unknown:true};
    reviewedOperations.set(operation.operation_id, result);
    unknownOperations.delete(operation.operation_id);
    persistRecovery();
    setNotice("操作 " + result.operation_id + "：" + stateLabels[result.state]);
  } catch (error) {
    if (error.outcome_unknown === false) unknownOperations.delete(operation.operation_id);
    persistRecovery();
    setNotice(error.message || "判断の結果を確認できませんでした。", true);
  } finally {
    deciding = false;
    selectedDecision = null;
    element("confirm-decision").disabled = false;
    element("cancel-decision").disabled = false;
    element("decision-dialog").close();
    renderReviewedOperations();
    await refreshInbox();
  }
});
element("logout-button").addEventListener("click", async () => {
  if (deciding) return;
  try { await post("/api/logout", {}); showLogin(); historyOffset = 0; }
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
  const attempt = ++authenticationAttempt;
  const generation = inboxGeneration;
  try {
    const session = await request("/api/session");
    if (attempt === authenticationAttempt && generation === inboxGeneration) await activateSession(session);
  } catch (_) {
    if (attempt === authenticationAttempt && generation === inboxGeneration) showLogin();
  }
}
setInterval(() => { if (!document.hidden) refreshInbox(); }, 10000);
document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshInbox(); });
start();
