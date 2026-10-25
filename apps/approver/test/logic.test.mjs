// The app's pure rules and the shared review code it renders with. docs/adr/0016.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const L = require(join(here, "..", "src", "logic.js"));
// devicekey.js is the panel's file, loaded the way the page loads it.
const devicekeyPath = join(here, "..", "..", "..", "src", "alerting", "clients", "panel", "static", "devicekey.js");
new Function(readFileSync(devicekeyPath, "utf8"))();
const D = globalThis.DeviceKey;

test("the panel address is https, and nothing else gets through", () => {
  assert.equal(L.normalizePanelUrl("panel.example.ru"), "https://panel.example.ru");
  assert.equal(L.normalizePanelUrl(" https://panel.example.ru/alerting/ "), "https://panel.example.ru/alerting");
  assert.equal(L.normalizePanelUrl("https://panel.example.ru/?x=1#y"), "https://panel.example.ru");
  assert.equal(L.normalizePanelUrl("http://localhost:8090"), "http://localhost:8090");
  assert.throws(() => L.normalizePanelUrl("http://panel.example.ru"), /https/);
  assert.throws(() => L.normalizePanelUrl("ftp://panel.example.ru"), /https/);
  assert.throws(() => L.normalizePanelUrl("https://user:pw@panel.example.ru"), /пароль/);
  assert.throws(() => L.normalizePanelUrl(""), /адрес/);
});

test("requests carry the panel header and the token, never a cookie's worth", () => {
  assert.deepEqual(L.requestHeaders("GET", null), { "X-Alerting-Panel": "1", "X-Alerting-Client": "app" });
  const post = L.requestHeaders("POST", "tok");
  assert.equal(post.Authorization, "Bearer tok");
  assert.equal(post["Content-Type"], "application/json");
  assert.equal(post["X-Alerting-Panel"], "1");
});

test("renewal is offered once six hours or less are left, never before", () => {
  const now = 1_000_000;
  assert.equal(L.needsRenewal({ delegation_until: now + 12 * 3600 }, now), false);
  assert.equal(L.needsRenewal({ delegation_until: now + 6 * 3600 }, now), true);
  assert.equal(L.needsRenewal({ delegation_until: now - 1 }, now), true);
  assert.equal(L.needsRenewal({ delegation_until: null }, now), false);
  assert.equal(L.needsRenewal(null, now), false);
});

test("an audience other than everyone is spelled out", () => {
  assert.deepEqual(L.audienceSummary({ groups: ["all"] }, true), { everyone: true, text: "все" });
  assert.match(L.audienceSummary({ groups: ["all"] }, false).text, /RSS/);
  const odd = L.audienceSummary({ groups: ["all"], persons: ["p-009"] }, false);
  assert.equal(odd.everyone, false);
  assert.match(odd.text, /лично: p-009/);
  assert.match(L.audienceSummary({}, false).text, /ПУСТО/);
});

test("severities follow the scenario's bounds and the policy", () => {
  const severities = { info: {}, warning: {}, critical: {}, catastrophic: {} };
  assert.deepEqual(L.allowedSeverities({ min_severity: "warning", max_severity: "critical" }, severities), ["warning", "critical"]);
  assert.deepEqual(L.allowedSeverities(null, { critical: {} }), ["critical"]);
});

test("every vault code has words, and an unknown one falls back to its message", () => {
  for (const code of ["cancelled", "failed", "locked", "invalidated", "not_found", "not_enrolled", "unavailable"]) {
    assert.ok(L.vaultMessage({ code }).length > 10, code);
  }
  assert.equal(L.vaultMessage({ code: "weird", message: "boom" }), "boom");
  assert.equal(L.isCancel({ code: "cancelled" }), true);
  assert.equal(L.isCancel(new Error("x")), false);
});

test("why a proposal is not sent yet is said in words", () => {
  assert.equal(L.blockingText("quorum_not_met"), "нужна подпись ещё одного ЛПР");
  assert.equal(L.blockingText("something_new"), "something_new");
});

test("only open proposals wait for a signature", () => {
  assert.deepEqual(L.openProposals([{ status: "open", order_id: "a" }, { status: "dispatched", order_id: "b" }])
    .map((p) => p.order_id), ["a"]);
});

// ---- the shared review code (devicekey.js) ------------------------------------------
const payload = {
  v: 1, type: "order", order_id: "o-1", org_id: "acme", stream_id: "s", seq: 3, nonce: "n",
  issued_at: 100, not_valid_after: 1000, severity: "critical", drill: true, scenario: "EVAC.BUILDING",
  action: "START", audience: { groups: ["all"] }, text: "Задымление", requires_ack: true,
  ack_deadline_s: 300, policy_id: "p1",
};

test("the review is rendered from the payload itself", () => {
  const f = D.describe(payload);
  assert.equal(f.scenario, "EVAC.BUILDING");
  assert.equal(f.stream, "s#3");
  assert.deepEqual(f.audience, { sites: [], groups: ["all"], persons: [] });
  assert.deepEqual(f.unexpected_fields, []);
  assert.deepEqual(D.describe({ ...payload, sneaky: 1 }).unexpected_fields, ["sneaky"]);
});

test("a digest the page did not compute, or another organisation, blocks signing", async () => {
  const digest = await D.digestHex("order", payload);
  assert.deepEqual(await D.reviewProblems(payload, digest, "acme"), []);
  assert.match((await D.reviewProblems(payload, "0".repeat(64), "acme"))[0], /разные приказы/);
  assert.match((await D.reviewProblems(payload, digest, "other"))[0], /другой организации/);
});

test("a key generated for the vault signs after the round trip, and only signs", async () => {
  const made = await D.generate();
  assert.match(made.key_id, /^ed25519:[A-Za-z0-9_-]{22}$/);
  assert.equal(made.key_id, await D.keyId(D.fromB64u(made.public_key)));
  const key = await D.importPrivate(made.pkcs8);
  assert.equal(key.extractable, false);
  assert.deepEqual(key.usages, ["sign"]);
  const sig = await D.sign(key, "order", payload);
  assert.equal(await D.verify(made.public_key, "order", payload, sig), true);
});

test("what the screens print: short key, initials, plurals, answer colours", () => {
  assert.equal(L.keyShort("ed25519:AbCdEfGhIjKlMnOpQrStUv"), "AbCdEfGh…");
  assert.equal(L.initials("Иван Петров", "p-001"), "ИП");
  assert.equal(L.initials("Демо-ЛПР 3", "demo-3"), "Д3");
  assert.equal(L.initials("", "p-010"), "P");
  assert.equal(L.plural(1, "подпись", "подписи", "подписей"), "подпись");
  assert.equal(L.plural(3, "подпись", "подписи", "подписей"), "подписи");
  assert.equal(L.plural(11, "подпись", "подписи", "подписей"), "подписей");
  assert.equal(L.plural(22, "подпись", "подписи", "подписей"), "подписи");
  assert.equal(L.ackTone({ ack_status: "acknowledged" }), "ok");
  assert.equal(L.ackTone({ ack_status: "received" }), "warn");
  assert.equal(L.ackTone({ ack_status: null }), "none");
  assert.equal(L.ackTone({ ack_status: "cannot_comply" }), "bad");
  assert.equal(L.ackTone({ ack_status: "acknowledged", ack_valid: false }), "bad", "a forged receipt is never green");
});
