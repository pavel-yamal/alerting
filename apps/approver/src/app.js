// The decision-makers' app: review and sign orders with the device key kept behind
// biometrics. docs/adr/0016.
//
// What the panel page does with a password-wrapped key in the browser (panel.js),
// this does with a key the operating system releases only after Face ID or a
// fingerprint -- and with page code that ships inside the app, so nobody who
// controls the panel's server can change what this page asks the key to sign.
//
// Three rules hold everywhere below:
//   * The key is fetched from the vault for one operation and dropped after it.
//     Logging in, signing an order and renewing the session each ask for biometrics.
//   * Biometrics are asked only when the person pressed a button. A Face ID prompt
//     that appears by itself teaches people to approve prompts without reading them.
//   * The review is rendered from the payload that will be signed (DeviceKey.describe),
//     and the system prompt names what is being signed.
"use strict";

const L = window.ApproverLogic;
const PANEL_KEY = "alerting.approver.panel";
// Where the organisation's panel lives. Only a suggestion in the first screen: the
// person can type another address, and what is used is always what they confirmed.

let panelUrl = null;
let config = null;          // the panel's /api/config
let token = null;           // the session token: in memory only, gone with the process
let me = null;
let meta = null;
let record = null;          // the key this session was opened with (public facts only)
let now = Math.floor(Date.now() / 1000);
let current = null;         // { kind: "proposal" | "order", id }

// ---- helpers ---------------------------------------------------------------------
// Everything from the network goes in through textContent: order text is free text.
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
const $ = (id) => document.getElementById(id);
const fill = (node, ...kids) => node.replaceChildren(...kids.flat().filter((k) => k != null && k !== false));
const msg = (kind, text) => el("div", { class: "msg " + kind }, text);
const modeTag = (drill) => el("span", { class: "tag " + (drill ? "drill" : "real") }, drill ? "УЧЕНИЕ" : "БОЕВОЕ");
const describeScenario = (code) => {
  const s = meta && meta.scenarios.find((x) => x.code === code);
  return s && s.description ? s.description : code;
};

function show(screen) {
  for (const id of ["setup", "login", "main", "detail"]) $(id).classList.toggle("hidden", id !== screen);
}

async function api(path, options = {}) {
  const method = options.method || "GET";
  const init = { method, headers: L.requestHeaders(method, token), credentials: "omit", cache: "no-store" };
  if (method !== "GET") init.body = JSON.stringify(options.body || {});
  let response;
  try {
    response = await fetch(panelUrl + path, init);
  } catch (_) {
    throw new Error("Панель не отвечает. Проверьте связь.");
  }
  let data = null;
  try { data = await response.json(); } catch (_) { /* empty body */ }
  if (response.status === 401 && token && !path.startsWith("/api/device/")) {
    token = null;
    showLogin((data && data.detail) || "Сеанс завершён — войдите снова.");
    throw new Error("401");
  }
  if (!response.ok) {
    const detail = data && data.detail;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail || response.status));
  }
  return data;
}

// The key, out of the vault for exactly one operation. `reason` is what the system
// biometric prompt shows -- it names the operation, so the person knows what the
// fingerprint is for.
async function withKey(keyRecord, reason, operation) {
  const pkcs8 = await Vault.load(keyRecord.key_id, reason);
  const key = await DeviceKey.importPrivate(pkcs8);
  return operation(key);
}

// ---- 1. which panel ----------------------------------------------------------------
function showSetup(reason) {
  show("setup");
  renderChrome();
  $("panel-url").value = panelUrl || "";
  $("setup-msg").replaceChildren(reason ? msg("warn", reason) : "");
}

// The privacy policy is the panel's own page, public and without login (App Store
// rule 5.1.1). It is the operator's and lives on its panel: before a panel is
// known there is nothing to link to, and the link stays hidden.
function privacyUrl() {
  return panelUrl ? panelUrl + "/privacy" : null;
}
function renderChrome() {
  for (const link of document.querySelectorAll(".privacy-link")) {
    const url = privacyUrl();
    if (url) link.href = url;
    link.parentElement.classList.toggle("hidden", !url);
  }
  // A demonstration stand says so on every screen: its orders reach nobody real.
  $("demo-banner").classList.toggle("hidden", !(config && config.demo));
  $("enroll-person-row").classList.toggle("hidden", Boolean(config && config.demo));
  $("enroll-person").required = !(config && config.demo);
}

$("setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("setup-msg");
  try {
    panelUrl = L.normalizePanelUrl($("panel-url").value);
    out.replaceChildren(msg("warn", "Проверяю панель…"));
    config = await api("/api/config");
    if (!config.device_login || !config.org_id) {
      throw new Error("На этой панели не настроен вход ключом устройства (--org и --root-key).");
    }
    localStorage.setItem(PANEL_KEY, panelUrl);
    await showLogin();
  } catch (error) {
    out.replaceChildren(msg("err", error.message));
  }
});

// ---- 2. login ----------------------------------------------------------------------
async function showLogin(reason) {
  token = null; me = null;
  show("login");
  renderChrome();
  $("login-msg").replaceChildren(reason ? msg("warn", reason) : "");
  $("login-panel").textContent = `Панель: ${panelUrl}` + (config ? ` · организация ${config.org_id}` : "");
  let keys = [];
  try {
    keys = (await Vault.list()).filter((k) => k.panel === panelUrl && (!config || k.org_id === config.org_id));
  } catch (error) {
    $("login-msg").replaceChildren(msg("err", L.vaultMessage(error)));
  }
  $("enroll").open = !keys.length;
  fill($("login-keys"), keys.map((k) => el("div", { class: "keycard" },
    el("div", {}, el("b", {}, k.person_id), " · ", el("code", {}, k.key_id.slice(8, 16) + "…")),
    el("div", { class: "row" },
      el("button", { class: "primary", type: "button", onclick: () => login(k) }, "Войти"),
      el("button", { type: "button", onclick: () => forget(k) }, "Удалить ключ")))));
}

async function login(keyRecord) {
  const out = $("login-msg");
  out.replaceChildren(msg("warn", "Проверяю справочник…"));
  try {
    const begun = await api("/api/device/begin", { method: "POST", body: { person_id: keyRecord.person_id, key_id: keyRecord.key_id } });
    // Signed only after checking it is a delegation for this very key, bounded in time.
    DeviceKey.checkDelegation(begun.delegation, keyRecord, Math.floor(Date.now() / 1000));
    const signature = await withKey(keyRecord, `Вход в «Оповещение ЛПР» (${keyRecord.person_id})`,
      (key) => DeviceKey.sign(key, "delegation", begun.delegation));
    const result = await api("/api/device/finish", { method: "POST", body: { challenge: begun.challenge, signature } });
    if (!result.token || !result.device_key) throw new Error("Панель не выдала сеанс приложению.");
    token = result.token;
    me = result;
    record = keyRecord;
    await start();
  } catch (error) {
    out.replaceChildren(msg(L.isCancel(error) ? "warn" : "err", error.code ? L.vaultMessage(error) : error.message));
  }
}

async function forget(keyRecord) {
  if (!confirm("Удалить ключ с телефона? Войти можно будет только после новой регистрации. Если телефон больше не ваш, попросите отозвать ключ в справочнике.")) return;
  try {
    await Vault.remove(keyRecord.key_id);
    await showLogin("Ключ удалён с телефона.");
  } catch (error) {
    $("login-msg").replaceChildren(msg("err", L.vaultMessage(error)));
  }
}

$("enroll-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("enroll-msg");
  const demo = Boolean(config && config.demo);
  let personId = $("enroll-person").value.trim();
  if (!demo && !L.PERSON_ID.test(personId)) { out.replaceChildren(msg("err", "Идентификатор: латиница, цифры и дефис, например p-010.")); return; }
  try {
    const status = await Vault.status();
    if (!status.available) {
      const error = new Error(status.reason || "unavailable");
      error.code = status.reason === "not_enrolled" ? "not_enrolled" : "unavailable";
      throw error;
    }
    const made = await DeviceKey.generate();
    if (demo) {
      // The demo stand enrols the key itself and says who it now is (demo_enroll.py).
      const enrolled = await api("/api/demo/enroll", { method: "POST", body: { public_key: made.public_key } });
      if (enrolled.key_id !== made.key_id) throw new Error("Демо-стенд внёс в справочник другой ключ.");
      personId = enrolled.person_id;
    }
    const keyRecord = {
      person_id: personId, org_id: config.org_id, key_id: made.key_id, public_key: made.public_key,
      panel: panelUrl, created: Math.floor(Date.now() / 1000),
    };
    await Vault.store(keyRecord, made.pkcs8, "Защитить ключ подписи вашей биометрией");
    $("enroll-person").value = "";
    if (demo) {
      fill(out, msg("ok", `Демо-стенд зарегистрировал этот телефон как «${personId}». Нажмите «Войти».`));
      await showLogin();
      return;
    }
    fill(out,
      msg("ok", "Ключ создан и защищён биометрией. Передайте регистрирующему лично:"),
      el("div", { class: "hint" }, "Публичный ключ"), el("div", { class: "keybox" }, keyRecord.public_key),
      el("div", { class: "hint" }, "Идентификатор ключа — сверьте его в справочнике после внесения"),
      el("div", { class: "keybox" }, keyRecord.key_id),
      el("div", { class: "hint" }, "Если на телефоне поменять набор отпечатков или лиц, ключ станет недоступен — это защита, а не сбой: понадобится новая регистрация."));
    await showLogin();
    $("enroll").open = true;
  } catch (error) {
    out.replaceChildren(msg("err", error.code ? L.vaultMessage(error) : error.message));
  }
});

$("change-panel").addEventListener("click", () => showSetup());

$("logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" }).catch(() => {});
  showLogin("Вы вышли.");
});

// ---- 3. lists ----------------------------------------------------------------------
async function start() {
  meta = await api("/api/meta");
  $("who").textContent = `${me.name} · ${me.person_id}`;
  fillForm();
  showTab("sign");
  show("main");
  await refresh();
}

function showTab(name) {
  for (const button of document.querySelectorAll(".tabs button")) button.classList.toggle("active", button.dataset.tab === name);
  for (const tab of ["sign", "events", "orders", "new"]) $(`tab-${tab}`).classList.toggle("hidden", tab !== name);
}
for (const button of document.querySelectorAll(".tabs button")) button.addEventListener("click", () => showTab(button.dataset.tab));

const item = (onclick, top, sub) => el("button", { class: "item", type: "button", onclick },
  el("div", { class: "top" }, top), el("div", { class: "sub" }, sub));

async function refresh() {
  const [proposals, orders, events] = await Promise.all([
    api("/api/proposals"), api("/api/orders"), api("/api/events/active")]);
  now = proposals.now;
  const open = L.openProposals(proposals.proposals);
  $("sign-count").textContent = String(open.length);
  $("sign-count").classList.toggle("hidden", !open.length);
  fill($("proposals"), open.length ? open.map((p) =>
    item(() => openProposal(p.order_id), [modeTag(p.drill), p.cancels ? " Отбой: " : " ", describeScenario(p.scenario)],
      `${L.SEVERITY[p.severity] || p.severity} · подписей: ${p.signed_by.length} · ${L.left(p.not_valid_after, now)}`))
    : el("div", { class: "empty" }, "Нет предложений на подпись."));
  fill($("events"), events.events.length ? events.events.map((e) =>
    item(() => openOrder(e.order_id), [modeTag(e.drill), " ", describeScenario(e.scenario)],
      `${L.SEVERITY[e.severity]} · с ${L.time(e.dispatched_at)} · ` + (e.until_cancelled ? "до отбоя" : `до ${L.time(e.not_valid_after)}`)))
    : el("div", { class: "empty" }, "Всё спокойно: действующих оповещений нет."));
  fill($("orders"), orders.orders.length ? orders.orders.map((o) =>
    item(() => openOrder(o.order_id),
      [modeTag(o.drill), o.cancels ? " Отбой: " : " ", describeScenario(o.scenario), o.cancelled_by ? el("span", { class: "tag ok" }, "отменено") : null],
      `${L.SEVERITY[o.severity]} · ${L.time(o.dispatched_at)}`))
    : el("div", { class: "empty" }, "Пока ничего не рассылалось."));
  renderRenewal();
}

// ---- keeping the session -----------------------------------------------------------
// The delegation lasts 12 h and only the device key can sign the next one -- which
// here means biometrics. So the app never renews on its own: it shows a button.
function renderRenewal() {
  const note = $("renew-note");
  if (!L.needsRenewal(me, Math.floor(Date.now() / 1000))) { note.replaceChildren(); return; }
  fill(note, el("span", { class: "hint" }, `Сеанс до ${L.time(me.delegation_until)} `),
    el("button", { type: "button", class: "small", onclick: renew }, "Продлить"));
}

async function renew() {
  try {
    const begun = await api("/api/device/renew/begin", { method: "POST" });
    DeviceKey.checkDelegation(begun.delegation, record, Math.floor(Date.now() / 1000));
    const signature = await withKey(record, "Продлить сеанс «Оповещение ЛПР»",
      (key) => DeviceKey.sign(key, "delegation", begun.delegation));
    me = await api("/api/device/renew/finish", { method: "POST", body: { signature } });
    renderRenewal();
  } catch (error) {
    if (error.message !== "401") $("renew-note").append(msg("err", error.code ? L.vaultMessage(error) : error.message));
  }
}

// ---- 4. review and sign ------------------------------------------------------------
async function openProposal(id) {
  current = { kind: "proposal", id };
  show("detail");
  const body = $("detail-body");
  body.replaceChildren(msg("warn", "Загружаю приказ…"));
  let view;
  try { view = await api(`/api/proposals/${encodeURIComponent(id)}`); }
  catch (error) { body.replaceChildren(msg("err", error.message)); return; }
  if (view.status === "dispatched") { openOrder(id); return; }
  now = view.now;
  const f = DeviceKey.describe(view.payload);
  const problems = await DeviceKey.reviewProblems(view.payload, view.digest, record.org_id);
  const audience = L.audienceSummary(f.audience, f.drill);
  const rows = [
    ["Что", `${describeScenario(f.scenario)} (${f.scenario})`],
    ["Режим", f.drill ? "учение" : "БОЕВОЕ"],
    ["Уровень", L.SEVERITY[f.severity] || f.severity],
    ["Действие", L.ACTION[f.action] || f.action],
    ["Кому", audience.text],
    ["Пояснение", f.text || "—"],
    ["Действует", `до ${L.time(f.not_valid_after)} (${L.left(f.not_valid_after, now)})`],
    f.cancels ? ["Отменяет приказ", f.cancels] : null,
  ].filter(Boolean);
  const technical = [
    ["Подтверждение", f.requires_ack ? `требуется, срок ${f.ack_deadline_s} с` : "не требуется"],
    ["Поток / номер", f.stream], ["Организация / политика", `${f.org_id} / ${f.policy_id}`],
  ];
  const table = (list) => el("table", {}, list.map(([k, v]) => el("tr", {}, el("th", {}, k), el("td", {}, v))));

  const blocked = f.unexpected_fields.length > 0 || view.signed_by_me || !view.can_sign || problems.length > 0;
  const check = el("input", { type: "checkbox" });
  const signBtn = el("button", { class: (f.drill ? "primary" : "danger") + " big", type: "button", disabled: "" },
    f.drill ? "Подписать учение" : "Подписать БОЕВОЙ приказ");
  const out = el("div");
  check.addEventListener("change", () => { signBtn.disabled = !check.checked || blocked; });
  signBtn.addEventListener("click", async () => {
    signBtn.disabled = true;
    try {
      const reason = `${f.cancels ? "ОТБОЙ · " : ""}${f.drill ? "УЧЕНИЕ" : "БОЕВОЕ"}: ${describeScenario(f.scenario)}`;
      const sig = await withKey(record, `Подписать — ${reason}`, (key) => DeviceKey.sign(key, "order", view.payload));
      const result = await api(`/api/proposals/${encodeURIComponent(id)}/sign`, { method: "POST", body: { digest: view.digest, sig } });
      if (result.dispatched) {
        fill(out, msg("ok", `Кворум набран — разослано ${result.recipients} получателям.`), result.warnings.map((w) => msg("warn", w)));
        setTimeout(() => openOrder(id), 1200);
      } else {
        fill(out, msg("warn", "Подпись принята. Ещё не разослано:"), el("ul", {}, result.blocking.map((b) => el("li", {}, L.blockingText(b)))));
      }
      refresh().catch(() => {});
    } catch (error) {
      out.replaceChildren(msg(L.isCancel(error) ? "warn" : "err", error.code ? L.vaultMessage(error) : error.message));
      signBtn.disabled = !check.checked || blocked;
    }
  });

  fill(body,
    el("div", { class: "banner " + (f.drill ? "drill" : "real") }, (f.cancels ? "ОТБОЙ · " : "") + (f.drill ? "УЧЕНИЕ" : "БОЕВОЕ — реальное оповещение")),
    el("h2", {}, view.can_sign ? "Проверьте и подпишите" : "Ждёт подписи ЛПР"),
    audience.everyone ? null : msg("err", `Необычные получатели: ${audience.text}. Проверьте, прежде чем подписывать.`),
    table(rows),
    el("details", { class: "more" }, el("summary", {}, "Технические поля"), table(technical)),
    f.unexpected_fields.length ? msg("err", `В приказе есть поля, которые экран не показывает: ${f.unexpected_fields.join(", ")}. Не подписывайте.`) : null,
    problems.length ? msg("err", `Подписать нельзя: ${problems.join("; ")}.`) : null,
    el("h3", {}, `Подписи: ${view.signed_by.length} из ${view.required ?? "?"}`),
    view.signed_by.length ? el("ul", {}, view.signed_by.map((s) => el("li", {}, s))) : el("div", { class: "empty" }, "Пока никто не подписал."),
    view.signed_by_me ? msg("warn", "Вы уже подписали. Нужна подпись другого человека.") : null,
    view.can_sign && !view.signed_by_me ? el("label", { class: "inline" }, check, "Я проверил все поля приказа") : null,
    view.can_sign && !view.signed_by_me ? signBtn : null,
    view.can_sign && !view.signed_by_me ? el("div", { class: "hint" }, "Подпись ставит ключ этого телефона после Face ID или отпечатка — над показанными полями.") : null,
    out,
  );
}

async function openOrder(id) {
  current = { kind: "order", id };
  show("detail");
  let s;
  try { s = await api(`/api/orders/${encodeURIComponent(id)}`); }
  catch (error) { $("detail-body").replaceChildren(msg("err", error.message)); return; }
  now = s.now;
  const total = s.people.length;
  const cancelText = el("input", { type: "text", placeholder: "Причина отбоя" });
  const out = el("div");
  const cancelBtn = el("button", { class: "danger", type: "button", onclick: async () => {
    if (!confirm("Создать приказ об отбое? Его тоже нужно будет подписать.")) return;
    try {
      const created = await api(`/api/orders/${encodeURIComponent(s.order_id)}/cancel`, { method: "POST", body: { text: cancelText.value.trim() } });
      openProposal(created.order_id);
    } catch (error) { out.replaceChildren(msg("err", error.message)); }
  }}, "Отбой");
  fill($("detail-body"),
    el("div", { class: "banner " + (s.drill ? "drill" : "real") }, `${s.drill ? "УЧЕНИЕ" : "БОЕВОЕ"} · ${describeScenario(s.scenario)} · ${L.time(s.dispatched_at)}`),
    el("div", { class: "big" }, `Подтвердили: ${s.acknowledged} из ${total}`),
    s.reached_nobody ? msg("err", "Приказ не дошёл ни до кого: в аудитории нет активных контактов.") : null,
    s.outstanding.length ? msg("warn", `Нет подтверждения: ${s.outstanding.length} чел. — идёт эскалация по каналам.`) : (total ? msg("ok", "Все подтвердили.") : null),
    s.cancels ? el("button", { type: "button", onclick: () => openOrder(s.cancels) }, "Открыть событие, которое отменено") : null,
    s.cancelled_by ? msg("ok", "Событие отменено отбоем.") : null,
    !s.cancels && !s.cancelled_by ? el("h3", {}, s.until_cancelled ? "Действует до отбоя" : `Действует до ${L.time(s.not_valid_after)}`) : null,
    me.can_issue && !s.cancels && !s.cancelled_by ? el("div", { class: "row" }, cancelText, cancelBtn) : null,
    el("details", { class: "more" }, el("summary", {}, `Кто ответил (${total})`),
      el("table", {}, s.people.map((p) => el("tr", {},
        el("td", {}, p.name || p.person_id),
        el("td", {}, p.ack_valid === false ? "ПОДДЕЛЬНАЯ РАСПИСКА" : p.ack_status ? (L.ACK[p.ack_status] || p.ack_status) : "нет ответа"))))),
    out,
  );
}

$("back").addEventListener("click", () => { current = null; show("main"); refresh().catch(() => {}); });

// ---- new proposal ------------------------------------------------------------------
const chosenScenario = () => {
  const picked = document.querySelector("input[name=scenario]:checked");
  return picked ? meta.scenarios.find((x) => x.code === picked.value) : null;
};

function fillForm() {
  fill($("scenarios"), meta.scenarios.map((s) => el("label", { class: "choice" },
    el("input", { type: "radio", name: "scenario", value: s.code, onchange: fillSeverity }),
    s.description || s.code, el("small", {}, s.code))));
  $("severity").onchange = updateSummary;
  for (const radio of document.querySelectorAll("input[name=drill]")) radio.onchange = updateSummary;
  fillSeverity();
}

function fillSeverity() {
  const s = chosenScenario();
  const allowed = L.allowedSeverities(s, meta.severities);
  fill($("severity"), allowed.map((level) => el("option", { value: level }, L.SEVERITY[level])));
  $("severity-row").classList.toggle("hidden", !s || allowed.length < 2);
  const parts = [];
  if (s && s.until_cancelled) parts.push("Действует до отбоя.");
  if (s && s.card) parts.push(`Люди увидят: «${s.card}»`);
  $("scenario-hint").textContent = parts.join(" ");
  updateSummary();
}

function updateSummary() {
  const s = chosenScenario();
  const mode = document.querySelector("input[name=drill]:checked");
  const rule = meta.severities[$("severity").value];
  if (!s) { fill($("summary"), el("div", { class: "hint" }, "Выберите, что случилось.")); return; }
  fill($("summary"),
    el("div", {}, `Получат: все (${meta.recipients} чел.)` + (mode && mode.value === "false" ? " и публичная RSS-лента" : "")),
    el("div", {}, `Нужно подписей ЛПР: ${rule ? rule.launch : "?"}` + (rule && rule.launch > 1 ? " — от разных людей" : "")),
    mode ? null : el("div", { class: "hint" }, "Выберите: учение или боевое."));
}

$("new-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("new-msg");
  const s = chosenScenario();
  const mode = document.querySelector("input[name=drill]:checked");
  if (!s) { out.replaceChildren(msg("err", "Выберите, что случилось.")); return; }
  if (!mode) { out.replaceChildren(msg("err", "Выберите: учение или боевое.")); return; }
  try {
    const created = await api("/api/proposals", { method: "POST", body: {
      scenario: s.code, severity: $("severity").value, drill: mode.value === "true",
      text: $("text").value.trim(), ttl_s: Number($("ttl").value),
    }});
    out.replaceChildren();
    $("text").value = "";
    mode.checked = false;
    openProposal(created.order_id);
  } catch (error) {
    out.replaceChildren(msg("err", error.message));
  }
});

// ---- polling -----------------------------------------------------------------------
// Lists refresh while the app is in front. A review screen does not: it must not
// change under the person reading it.
setInterval(() => {
  if (!token || document.visibilityState !== "visible" || current) return;
  refresh().catch(() => { /* shown on the next action */ });
}, 5000);
document.addEventListener("visibilitychange", () => {
  if (token && document.visibilityState === "visible" && !current) refresh().catch(() => {});
});

// ---- boot --------------------------------------------------------------------------
(async () => {
  const problem = await DeviceKey.supported();
  if (problem) {
    fill($("fatal"), msg("err", problem));
    $("fatal").classList.remove("hidden");
    return;
  }
  panelUrl = localStorage.getItem(PANEL_KEY);
  if (!panelUrl) { showSetup(); return; }
  try {
    config = await api("/api/config");
  } catch (error) {
    config = null;
    await showLogin(error.message);
    return;
  }
  await showLogin();
})();
