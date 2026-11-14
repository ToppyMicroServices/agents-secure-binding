// Run with: node --test internal/humanapp/web_ui_test.mjs
// These dependency-free logic tests complement, not replace, browser checks.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("web/app.js", import.meta.url), "utf8");
const markup = readFileSync(new URL("web/index.html", import.meta.url), "utf8");
const choiceSelectors = [".approve-button", ".decline-button", ".not-applicable-button", ".undetermined-button"];

class Element {
  constructor() {
    this.children = [];
    this.open = false;
    this.hidden = false;
    this.textContent = "";
    this.mutations = 0;
    this.disabled = false;
    const classes = new Set();
    this.classList = {toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); }, add(name) { classes.add(name); }, contains(name) { return classes.has(name); }};
    this.details = {open: false};
    this.listeners = new Map();
  }
  addEventListener(type, listener) { this.listeners.set(type, listener); }
  dispatch(type) { return this.listeners.get(type)({preventDefault() {}}); }
  showModal() { this.open = true; }
  close() { this.open = false; }
  focus() {}
  querySelector() { return this.details; }
  get lastElementChild() { return this.children.at(-1); }
  insertBefore(child, before) {
    if (child.parent) child.remove();
    const index = before ? this.children.indexOf(before) : this.children.length;
    assert.notEqual(index, -1);
    this.children.splice(index, 0, child);
    child.parent = this;
    this.mutations++;
  }
  remove() {
    const index = this.parent.children.indexOf(this);
    this.parent.children.splice(index, 1);
    this.parent.mutations++;
    this.parent = null;
  }
  replaceChildren() {
    for (const child of [...this.children]) child.remove();
  }
}

class OperationCard extends Element {
  constructor() {
    super();
    this.parts = new Map([[".operation-details", this.details]]);
    const template = markup.match(/<template id="operation-template">([\s\S]*?)<\/template>/)[1];
    for (const attribute of template.matchAll(/class="([^"]+)"/g)) {
      for (const name of attribute[1].split(" ")) {
        if (!this.parts.has("." + name)) this.parts.set("." + name, new Element());
      }
    }
  }
  querySelector(selector) {
    assert.ok(this.parts.has(selector), `template is missing ${selector}`);
    return this.parts.get(selector);
  }
  cloneNode() { return new OperationCard(); }
}

function memoryStorage() {
  const values = new Map();
  return {getItem(key) { return values.get(key) || null; }, setItem(key, value) { values.set(key, value); }, removeItem(key) { values.delete(key); }};
}

function application({realCards = false, storage = memoryStorage()} = {}) {
  const nodes = new Map();
  const element = (id) => {
    if (!nodes.has(id)) nodes.set(id, new Element());
    return nodes.get(id);
  };
  const context = vm.createContext({
    URLSearchParams, Intl, Date, setInterval() {},
    window: {location: {hash: ""}, sessionStorage:storage},
    document: {getElementById: element, addEventListener() {}},
    makeCard: () => new Element(),
  });
  element("operation-template").content = {firstElementChild: new OperationCard()};
  // Do not start network login. Exercise the shipped render and refresh
  // functions with only operation-card markup replaced by a minimal DOM node.
  assert.match(source, /\nstart\(\);\s*$/);
  vm.runInContext(source.replace(/\nstart\(\);\s*$/, "\n"), context);
  if (!realCards) vm.runInContext("operationCard = () => makeCard();", context);
  vm.runInContext("loggedIn = true;", context);
  const api = vm.runInContext("({operationCard, renderOperationLists, refreshInbox, openDecision, showLogin, activateSession, unknownOperations})", context);
  return {element, context, ...api};
}

const pending = (id) => ({operation_id: id, state: "PENDING_REVIEW"});

test("unchanged polling preserves nodes and expanded details without DOM writes", () => {
  const app = application();
  app.renderOperationLists([pending("one"), pending("two")], []);
  const list = app.element("pending-list");
  const first = list.children[0];
  first.details.open = true;
  const writes = list.mutations;
  app.renderOperationLists([pending("one"), pending("two")], []);
  assert.equal(list.children[0], first);
  assert.equal(first.details.open, true);
  assert.equal(list.mutations, writes);
  app.renderOperationLists([pending("new"), pending("one"), pending("two")], []);
  assert.equal(list.children[1], first);
  assert.equal(first.details.open, true);
  assert.equal(list.mutations, writes + 1);
  app.renderOperationLists([pending("one"), pending("two")], []);
  assert.equal(list.children[0], first);
  assert.equal(list.mutations, writes + 2, "removing a neighbor must not detach the retained card");
});

test("a changed result updates its card but retains expanded details", () => {
  const app = application();
  app.renderOperationLists([pending("one")], []);
  app.element("pending-list").children[0].details.open = true;
  app.renderOperationLists([], [{operation_id: "one", state: "APPLIED"}]);
  assert.equal(app.element("pending-list").children.length, 0);
  assert.equal(app.element("history-list").children.length, 1);
  assert.equal(app.element("history-list").children[0].details.open, true);
});

test("an open confirmation dialog prevents reads and in-flight DOM replacement", async () => {
  const app = application();
  app.context.fetch = () => { throw new Error("unexpected request"); };
  app.element("decision-dialog").open = true;
  await app.refreshInbox();
  app.element("decision-dialog").open = false;
  let complete;
  app.context.fetch = () => new Promise((resolve) => { complete = resolve; });
  const reading = app.refreshInbox();
  app.element("decision-dialog").open = true;
  complete({ok: true, status: 200, json: async () => ({operations: [pending("one")]})});
  await reading;
  assert.equal(app.element("pending-list").children.length, 0);
  assert.equal(app.element("refresh-button").disabled, false);
});

test("a bounded inbox shows total pending and does not claim omitted history is empty", async () => {
  const app = application();
  app.context.fetch = async () => ({ok: true, status: 200, json: async () => ({
    operations: [pending("oldest"), pending("next")],
    inbox: {pending: 120, total: 125, limit: 100},
  })});
  await app.refreshInbox();
  assert.equal(app.element("pending-count").textContent, "120");
  assert.equal(app.element("history-count").textContent, "0 / 5 件");
  assert.equal(app.element("inbox-window").hidden, false);
  assert.match(app.element("inbox-window").textContent, /2 \/ 120/);
  assert.match(app.element("empty-history").textContent, /5 件あります/);
  assert.equal(app.element("empty-state").hidden, true);
});

function deferred() {
  let resolve;
  const promise = new Promise((complete) => { resolve = complete; });
  return {promise, resolve};
}

const response = (body, status = 200) => ({ok: status < 400, status, json: async () => body});
const reviewedOperation = {
  ...pending("reviewed"), proposal_digest: "sha256:" + "a".repeat(64),
  before: {enabled: false, revision: 0}, change: {enabled: true},
};
const appliedOperation = {...reviewedOperation, state: "APPLIED", after: {enabled: true, revision: 1}};
const inbox = (operation, setting) => ({operations: [operation], setting});

const decisions = [
  {decision:"APPROVE", selector:".approve-button", state:"APPLIED", label:"適用済み", heading:"この変更を許可しますか？", confirm:"許可して適用"},
  {decision:"DECLINE", selector:".decline-button", state:"DENIED", label:"拒否済み", heading:"この提案を拒否しますか？", confirm:"拒否を確定"},
  {decision:"NOT_APPLICABLE", selector:".not-applicable-button", state:"NOT_APPLICABLE", label:"該当なし", heading:"この提案は該当なしですか？", confirm:"該当なしを確定"},
  {decision:"UNDETERMINED", selector:".undetermined-button", state:"UNDETERMINED", label:"判断不明", heading:"この提案を判断できませんか？", confirm:"判断不明を確定"},
];

for (const choice of decisions) {
  test(`${choice.decision} sends an explicit decision and renders its own final result`, async () => {
    const app = application({realCards: true});
    const result = {...reviewedOperation, state: choice.state, decided_at:"2026-10-16T01:00:00Z"};
    const setting = choice.decision === "APPROVE" ? appliedOperation.after : reviewedOperation.before;
    if (choice.decision === "APPROVE") result.after = setting;
    const sent = [];
    app.context.fetch = async (path, options) => {
      if (path === "/api/decision") {
        sent.push(JSON.parse(options.body));
        return response({operation: result});
      }
      assert.equal(path, "/api/inbox");
      return response(inbox(result, setting));
    };
    const card = app.operationCard(reviewedOperation);
    card.querySelector(choice.selector).dispatch("click");
    assert.equal(app.element("decision-dialog").open, true);
    assert.equal(app.element("decision-heading").textContent, choice.heading);
    assert.equal(app.element("confirm-decision").textContent, choice.confirm);
    assert.equal(app.element("confirm-decision").classList.contains("primary"), choice.decision === "APPROVE");
    if (choice.decision !== "APPROVE") assert.match(app.element("decision-description").textContent, /設定変更は行いません/);
    if (choice.decision === "UNDETERMINED") assert.match(app.element("decision-description").textContent, /処理結果不明とは別/);
    await app.element("decision-form").dispatch("submit");
    assert.deepEqual(sent, [{operation_id:reviewedOperation.operation_id, proposal_digest:reviewedOperation.proposal_digest, expected_revision:0, decision:choice.decision}]);
    assert.equal(app.element("pending-list").children.length, 0);
    const history = app.element("history-list").children[0];
    assert.equal(history.querySelector(".state-tag").textContent, choice.label);
    assert.equal(history.querySelector(".operation-actions").hidden, true);
    assert.equal(history.querySelector(".operation-outcome").hidden, false);
    for (const selector of choiceSelectors) assert.equal(history.querySelector(selector).disabled, true);
    if (choice.decision !== "APPROVE") assert.match(history.querySelector(".operation-outcome").textContent, /設定変更はありません/);
    assert.equal(app.unknownOperations.size, 0, "human uncertainty must not become transport uncertainty");
    assert.equal(app.element("current-setting").textContent, choice.decision === "APPROVE" ? "ON · 有効" : "OFF · 無効");
    assert.equal(app.element("current-revision").textContent, choice.decision === "APPROVE" ? "revision 1" : "revision 0");
    assert.match(app.element("notice").textContent, new RegExp(choice.label));
  });

  test(`an uncertain ${choice.decision} submission blocks all four choices until exact terminal status`, async () => {
    const app = application({realCards: true});
    let posts = 0;
    app.context.fetch = async (path) => {
      if (path === "/api/decision") {
        posts++;
        return response({message:"処理結果不明", outcome_unknown:true}, 503);
      }
      if (path.startsWith("/api/operation?")) return response({operation:{...reviewedOperation, state:choice.state}});
      assert.equal(path, "/api/inbox");
      return response(inbox(reviewedOperation, reviewedOperation.before));
    };
    app.openDecision(reviewedOperation, choice.decision);
    await app.element("decision-form").dispatch("submit");
    const card = app.element("pending-list").children[0];
    assert.equal(card.querySelector(".state-tag").textContent, "処理結果不明");
    assert.match(card.querySelector(".operation-outcome").textContent, /人間の回答である「判断不明」とは異なります/);
    for (const selector of choiceSelectors) {
      assert.equal(card.querySelector(selector).disabled, true);
      card.querySelector(selector).dispatch("click");
      assert.equal(app.element("decision-dialog").open, false);
      await app.element("decision-form").dispatch("submit");
    }
    assert.equal(posts, 1);
    await app.refreshInbox();
    assert.equal(app.unknownOperations.has(reviewedOperation.operation_id), true);
    await app.refreshInbox(true);
    assert.equal(app.element("pending-list").children.length, 0);
    assert.equal(app.unknownOperations.size, 0);
    const refreshed = app.element("reviewed-list").children[0];
    assert.equal(refreshed.querySelector(".state-tag").textContent, choice.label);
    for (const selector of choiceSelectors) assert.equal(refreshed.querySelector(selector).disabled, true);
  });
}

test("an explicit OUTCOME_UNKNOWN state is not a human UNDETERMINED answer", () => {
  const app = application({realCards:true});
  const card = app.operationCard({...reviewedOperation, state:"OUTCOME_UNKNOWN"});
  assert.equal(card.querySelector(".state-tag").textContent, "処理結果不明");
  assert.equal(card.querySelector(".operation-actions").hidden, true);
  assert.match(card.querySelector(".operation-outcome").textContent, /記録・適用されたかを確認できません/);
  for (const selector of choiceSelectors) {
    assert.equal(card.querySelector(selector).disabled, true);
    card.querySelector(selector).dispatch("click");
    assert.equal(app.element("decision-dialog").open, false);
  }
});

test("unknown, missing, and boolean choices never fall back to permission or send a request", async () => {
  const app = application();
  let requests = 0;
  app.context.fetch = () => { requests++; throw new Error("unexpected request"); };
  for (const invalid of [undefined, null, "", "approve", "UNKNOWN", "OUTCOME_UNKNOWN", "__proto__", "constructor", true, false]) {
    app.openDecision(reviewedOperation, "APPROVE");
    app.openDecision(reviewedOperation, invalid);
    assert.equal(app.element("decision-dialog").open, false);
    await app.element("decision-form").dispatch("submit");
  }
  app.openDecision(reviewedOperation, "APPROVE");
  vm.runInContext("delete selectedDecision.decision", app.context);
  await app.element("decision-form").dispatch("submit");
  assert.equal(requests, 0);
});

for (const arrival of ["during", "after"]) {
  test(`an inbox response from before approval arriving ${arrival} the decision cannot restore old state`, async () => {
    const app = application();
    const oldRead = deferred();
    const decision = deferred();
    let reads = 0;
    app.context.fetch = (path) => {
      if (path === "/api/decision") return decision.promise;
      assert.equal(path, "/api/inbox");
      if (++reads === 1) return oldRead.promise;
      assert.equal(app.element("current-setting").textContent, "", "the old snapshot must not render before the fresh read");
      return Promise.resolve(response(inbox(appliedOperation, appliedOperation.after)));
    };
    app.renderOperationLists([reviewedOperation], []);
    const card = app.element("pending-list").children[0];
    card.details.open = true;
    const reading = app.refreshInbox();
    app.openDecision(reviewedOperation, "APPROVE");
    const submitting = app.element("decision-form").dispatch("submit");
    if (arrival === "during") {
      oldRead.resolve(response(inbox(reviewedOperation, reviewedOperation.before)));
      await reading;
      assert.equal(app.element("pending-list").children[0], card);
      assert.equal(app.element("current-setting").textContent, "");
      assert.equal(app.element("decision-dialog").open, true);
    }
    decision.resolve(response({operation: appliedOperation}));
    await submitting;
    if (arrival === "after") {
      oldRead.resolve(response(inbox(reviewedOperation, reviewedOperation.before)));
      await reading;
    }
    assert.equal(reads, 2, "decision completion must cause a fresh read");
    assert.equal(app.element("current-setting").textContent, "ON · 有効");
    assert.equal(app.element("current-revision").textContent, "revision 1");
    assert.equal(app.element("pending-list").children.length, 0);
    assert.equal(app.element("history-list").children.length, 1);
    assert.equal(app.element("history-list").children[0].details.open, true);
    assert.equal(app.element("refresh-button").disabled, false);
    assert.match(app.element("notice").textContent, /適用済み/);
  });
}

test("an old manual read and its queued automatic refresh cannot clear an uncertain decision", async () => {
  const app = application();
  const oldRead = deferred();
  let reads = 0;
  app.context.fetch = (path) => {
    if (path === "/api/decision") return Promise.resolve(response({message: "result unavailable", outcome_unknown: true}, 503));
    if (path.startsWith("/api/operation?")) return Promise.resolve(response({operation:appliedOperation}));
    assert.equal(path, "/api/inbox");
    return ++reads === 1 ? oldRead.promise : Promise.resolve(response(inbox(reviewedOperation, reviewedOperation.before)));
  };
  const reading = app.refreshInbox(true);
  app.openDecision(reviewedOperation, "APPROVE");
  await app.element("decision-form").dispatch("submit");
  oldRead.resolve(response(inbox(reviewedOperation, reviewedOperation.before)));
  await reading;
  assert.equal(reads, 2);
  assert.equal(app.unknownOperations.has(reviewedOperation.operation_id), true);
  assert.equal(app.element("notice").textContent, "result unavailable");
  await app.refreshInbox(true);
  assert.equal(app.unknownOperations.size, 0, "a new explicit readback may resolve uncertainty");
});

for (const status of [200, 401]) {
  test(`an old session inbox response (${status}) cannot replace a new session`, async () => {
    const app = application();
    const oldRead = deferred();
    let reads = 0;
    app.context.fetch = (path) => {
      assert.equal(path, "/api/inbox");
      return ++reads === 1 ? oldRead.promise : Promise.resolve(response(inbox(appliedOperation, appliedOperation.after)));
    };
    const reading = app.refreshInbox();
    app.showLogin();
    await app.activateSession({csrf_token: "new-session-csrf", human_participant: "human:new", gateway_actor: "gateway:new", assurance: "new-session"});
    oldRead.resolve(response(status === 200 ? inbox(reviewedOperation, reviewedOperation.before) : {message: "old session expired"}, status));
    await reading;
    assert.equal(reads, 2);
    assert.equal(app.element("dashboard").hidden, false);
    assert.equal(app.element("login-view").hidden, true);
    assert.equal(vm.runInContext("csrf", app.context), "new-session-csrf");
    assert.equal(app.element("current-setting").textContent, "ON · 有効");
    assert.equal(app.element("pending-list").children.length, 0);
    assert.equal(app.element("notice").textContent, "");
  });
}

test("a just-decided result stays visible even when both bounded windows omit it", async () => {
  const app = application({realCards:true});
  app.context.fetch = async (path) => {
    if (path === "/api/decision") return response({operation:appliedOperation});
    return response({operations:[], history:[], inbox:{pending:120, total:250, limit:100, history_limit:100}});
  };
  app.openDecision(reviewedOperation, "APPROVE");
  await app.element("decision-form").dispatch("submit");
  assert.equal(app.element("history-list").children.length, 0);
  assert.equal(app.element("reviewed-section").hidden, false);
  assert.equal(app.element("reviewed-list").children[0].querySelector(".state-tag").textContent, "適用済み");
  await app.refreshInbox();
  assert.equal(app.element("reviewed-list").children[0].querySelector(".state-tag").textContent, "適用済み");
});

test("an omitted unknown result needs a successful exact lookup before its warning clears", async () => {
  const app = application({realCards:true});
  let statusResponse = response({message:"temporarily unavailable"}, 503);
  let statusReads = 0;
  app.context.fetch = async (path) => {
    if (path === "/api/decision") return response({message:"lost response", outcome_unknown:true}, 503);
    if (path.startsWith("/api/operation?")) {
      statusReads++;
      const query = new URLSearchParams(path.split("?")[1]);
      assert.equal(query.get("operation_id"), reviewedOperation.operation_id);
      assert.equal(query.get("proposal_digest"), reviewedOperation.proposal_digest);
      return statusResponse;
    }
    return response({operations:[], history:[], inbox:{pending:150, total:151, limit:100, history_limit:100}});
  };
  app.openDecision(reviewedOperation, "APPROVE");
  await app.element("decision-form").dispatch("submit");
  assert.equal(statusReads, 0, "automatic refresh must not clear an unknown outcome");
  await app.refreshInbox(true);
  assert.equal(app.unknownOperations.has(reviewedOperation.operation_id), true);
  assert.equal(app.element("reviewed-list").children[0].querySelector(".state-tag").textContent, "処理結果不明");
  statusResponse = response({operation:reviewedOperation});
  await app.refreshInbox(true);
  assert.equal(app.unknownOperations.has(reviewedOperation.operation_id), true, "pending is not a fence against the delayed original mutation");
  for (const selector of choiceSelectors) assert.equal(app.element("reviewed-list").children[0].querySelector(selector).disabled, true);
  assert.match(app.element("notice").textContent, /まだ確認待ち/);
  statusResponse = response({operation:{...appliedOperation, proposal_digest:"sha256:" + "b".repeat(64)}});
  await app.refreshInbox(true);
  assert.equal(app.unknownOperations.has(reviewedOperation.operation_id), true, "a different proposal must not clear uncertainty");
  statusResponse = response({operation:appliedOperation});
  await app.refreshInbox(true);
  assert.equal(app.unknownOperations.size, 0);
  assert.equal(app.element("reviewed-list").children[0].querySelector(".state-tag").textContent, "適用済み");
  assert.match(app.element("notice").textContent, /個別に照会/);
});

test("a late individual lookup cannot clear uncertainty after a session change", async () => {
  const app = application({realCards:true});
  const lookup = deferred();
  let lookupStarted;
  const began = new Promise((resolve) => { lookupStarted = resolve; });
  app.context.fetch = async (path) => {
    if (path === "/api/decision") return response({message:"lost", outcome_unknown:true}, 503);
    if (path.startsWith("/api/operation?")) { lookupStarted(); return lookup.promise; }
    return response(inbox(reviewedOperation, reviewedOperation.before));
  };
  app.openDecision(reviewedOperation, "APPROVE");
  await app.element("decision-form").dispatch("submit");
  const reading = app.refreshInbox(true);
  await began;
  app.showLogin();
  lookup.resolve(response({operation:appliedOperation}));
  await reading;
  assert.equal(app.unknownOperations.has(reviewedOperation.operation_id), true);
  assert.equal(app.element("dashboard").hidden, true);
});

test("history is independently paged even while pending work fills its window", async () => {
  const app = application({realCards:true});
  const paths = [];
  app.context.fetch = async (path) => {
    paths.push(path);
    const offset = path.includes("history_offset=100") ? 100 : 0;
    return response({operations:[reviewedOperation], history:[{...appliedOperation, operation_id:"history-" + offset}], inbox:{pending:200, total:350, limit:100, history_limit:100, history_offset:offset}});
  };
  await app.refreshInbox();
  assert.equal(app.element("history-list").children.length, 1);
  assert.equal(app.element("history-next").disabled, false);
  assert.equal(app.element("history-previous").disabled, true);
  await app.element("history-next").dispatch("click");
  assert.equal(paths.at(-1), "/api/inbox?history_offset=100");
  assert.equal(app.element("history-next").disabled, true);
  assert.equal(app.element("history-previous").disabled, false);
  assert.match(app.element("history-count").textContent, /101–101 \/ 150/);
  await app.element("history-latest").dispatch("click");
  assert.equal(paths.at(-1), "/api/inbox");
  assert.equal(app.element("history-previous").disabled, true);
});

test("capacity warnings appear before the limit and a capacity refusal is known", async () => {
  const app = application({realCards:true});
  let used = 3999;
  app.context.fetch = async (path) => {
    if (path === "/api/decision") return response({code:"CAPACITY_EXCEEDED", message:"保存上限 storage-status", outcome_unknown:false}, 507);
    return response({...inbox(reviewedOperation, reviewedOperation.before), capacity:{operations:used, operation_limit:5000, commands:used, command_limit:10000}});
  };
  await app.refreshInbox();
  assert.equal(app.element("capacity-warning").hidden, true);
  used = 4000;
  await app.refreshInbox();
  assert.equal(app.element("capacity-warning").hidden, false);
  assert.match(app.element("capacity-warning").textContent, /80%/);
  used = 5000;
  await app.refreshInbox();
  assert.match(app.element("capacity-warning").textContent, /新しい提案の保存上限/);
  app.openDecision(reviewedOperation, "APPROVE");
  await app.element("decision-form").dispatch("submit");
  assert.equal(app.unknownOperations.size, 0);
  assert.match(app.element("notice").textContent, /storage-status/);
});

test("reload during an unresolved POST retains only recovery metadata and keeps choices blocked", async () => {
  const storage = memoryStorage();
  const first = application({realCards:true, storage});
  const post = deferred();
  first.context.fetch = (path) => path === "/api/decision" ? post.promise : Promise.resolve(response(inbox(reviewedOperation, reviewedOperation.before)));
  vm.runInContext('csrf = "must-never-be-persisted"', first.context);
  first.openDecision(reviewedOperation, "APPROVE");
  const submitting = first.element("decision-form").dispatch("submit");
  const saved = storage.getItem("asb-human-unresolved-v1");
  assert.ok(saved);
  assert.equal(saved.includes("must-never-be-persisted"), false);
  assert.equal(saved.includes("csrf"), false);
  assert.equal(saved.includes("token"), false);
  const reloaded = application({realCards:true, storage});
  reloaded.context.fetch = async (path) => path.startsWith("/api/operation?") ? response({operation:reviewedOperation}) : response(inbox(reviewedOperation, reviewedOperation.before));
  await reloaded.refreshInbox(true);
  assert.equal(reloaded.unknownOperations.has(reviewedOperation.operation_id), true);
  for (const selector of choiceSelectors) assert.equal(reloaded.element("pending-list").children[0].querySelector(selector).disabled, true);
  post.resolve(response({operation:appliedOperation}));
  await submitting;
  reloaded.context.fetch = async (path) => path.startsWith("/api/operation?") ? response({operation:appliedOperation}) : response({operations:[], history:[]});
  await reloaded.refreshInbox(true);
  assert.equal(reloaded.unknownOperations.size, 0);
  assert.equal(storage.getItem("asb-human-unresolved-v1"), null);
});

test("corrupt recovery metadata blocks decisions and unavailable storage gives a visible warning", async () => {
  const storage = memoryStorage();
  storage.setItem("asb-human-unresolved-v1", '{"version":1,"operations":[{"operation_id":"bad"}]}');
  const app = application({realCards:true, storage});
  app.openDecision(reviewedOperation, "APPROVE");
  assert.equal(app.element("decision-dialog").open, false);
  assert.equal(app.element("recovery-warning").hidden, false);
  for (const selector of choiceSelectors) assert.equal(app.operationCard(reviewedOperation).querySelector(selector).disabled, true);
  let removes = 0;
  const unavailable = application({realCards:true, storage:{getItem() { throw new Error("disabled"); }, removeItem() { removes++; }}});
  assert.equal(unavailable.element("recovery-warning").hidden, false);
  assert.match(unavailable.element("recovery-warning").textContent, /判断を停止/);
  unavailable.openDecision(reviewedOperation, "APPROVE");
  assert.equal(unavailable.element("decision-dialog").open, false);
  assert.equal(removes, 0, "a read failure must not delete potentially unresolved recovery data");
  for (const selector of choiceSelectors) assert.equal(unavailable.operationCard(reviewedOperation).querySelector(selector).disabled, true);
});

test("a failed history page read does not make the next click skip a page", async () => {
  const app = application();
  const paths = [];
  app.context.fetch = async (path) => {
    paths.push(path);
    if (path.includes("history_offset")) return response({message:"offline"}, 503);
    return response({operations:[], history:[], inbox:{pending:0, total:250, history_limit:100}});
  };
  await app.refreshInbox();
  await app.element("history-next").dispatch("click");
  await app.element("history-next").dispatch("click");
  assert.deepEqual(paths, ["/api/inbox", "/api/inbox?history_offset=100", "/api/inbox?history_offset=100"]);
  assert.equal(app.element("history-previous").disabled, true);
});

test("a recovery metadata write failure prevents sending a new decision", async () => {
  const app = application({storage:{getItem() { return null; }, setItem() { throw new Error("quota"); }, removeItem() {}}});
  let posts = 0;
  app.context.fetch = async (path) => {
    if (path === "/api/decision") posts++;
    return response(inbox(reviewedOperation, reviewedOperation.before));
  };
  app.openDecision(reviewedOperation, "APPROVE");
  await app.element("decision-form").dispatch("submit");
  assert.equal(posts, 0);
  assert.equal(app.unknownOperations.size, 0);
  assert.match(app.element("notice").textContent, /判断は送信しませんでした/);
});

for (const status of [200, 401]) {
  test(`a late initial session GET (${status}) cannot replace a successful manual login`, async () => {
    const app = application();
    const initial = deferred();
    const api = vm.runInContext("({start, login})", app.context);
    app.context.fetch = async (path, options) => {
      if (path === "/api/session") {
        if (options.method === "POST") return response({csrf_token:"new-csrf", human_participant:"human:local-owner", gateway_actor:"gateway:local-human", assurance:"gateway-asserted-for-human"});
        return initial.promise;
      }
      assert.equal(path, "/api/inbox");
      return response({operations:[], history:[]});
    };
    const starting = api.start();
    await api.login("synthetic-login-token");
    initial.resolve(response(status === 200 ? {csrf_token:"stale-csrf"} : {message:"stale session"}, status));
    await starting;
    assert.equal(vm.runInContext("csrf", app.context), "new-csrf");
    assert.equal(app.element("dashboard").hidden, false);
    assert.equal(app.element("login-view").hidden, true);
  });
}
