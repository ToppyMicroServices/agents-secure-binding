// Run with: node --test internal/humanapp/web_ui_test.mjs
// These dependency-free logic tests complement, not replace, browser checks.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("web/app.js", import.meta.url), "utf8");

class Element {
  constructor() {
    this.children = [];
    this.open = false;
    this.hidden = false;
    this.textContent = "";
    this.mutations = 0;
    this.classList = {toggle() {}};
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

function application() {
  const nodes = new Map();
  const element = (id) => {
    if (!nodes.has(id)) nodes.set(id, new Element());
    return nodes.get(id);
  };
  const context = vm.createContext({
    URLSearchParams, Intl, Date, setInterval() {},
    window: {location: {hash: ""}},
    document: {getElementById: element, addEventListener() {}},
    makeCard: () => new Element(),
  });
  // Do not start network login. Exercise the shipped render and refresh
  // functions with only operation-card markup replaced by a minimal DOM node.
  assert.match(source, /\nstart\(\);\s*$/);
  vm.runInContext(source.replace(/\nstart\(\);\s*$/, "\n"), context);
  vm.runInContext("operationCard = () => makeCard(); loggedIn = true;", context);
  const api = vm.runInContext("({renderOperationLists, refreshInbox, openDecision, showLogin, activateSession, unknownOperations})", context);
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
    app.openDecision(reviewedOperation, true);
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
    assert.equal(path, "/api/inbox");
    return ++reads === 1 ? oldRead.promise : Promise.resolve(response(inbox(reviewedOperation, reviewedOperation.before)));
  };
  const reading = app.refreshInbox(true);
  app.openDecision(reviewedOperation, true);
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
