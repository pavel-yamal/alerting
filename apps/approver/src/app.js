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
let biometry = "none";      // what the vault reports: "face", "fingerprint", ...

// ---- helpers ---------------------------------------------------------------------
// Everything from the network goes in through textContent: order text is free text.
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const child of children.flat(Infinity)) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
const $ = (id) => document.getElementById(id);
const fill = (node, ...kids) => node.replaceChildren(...kids.flat(Infinity).filter((k) => k != null && k !== false));
const icon = (name) => $("icons").content.querySelector(`[data-icon="${name}"]`).cloneNode(true);
const MARK = { ok: "calm", warn: "alert", err: "alert" };
const msg = (kind, ...text) => el("div", { class: "msg " + kind }, el("span", { class: "mark" }, icon(MARK[kind])), el("div", {}, ...text));
const modeTag = (drill) => el("span", { class: "tag " + (drill ? "drill" : "real") }, drill ? "УЧЕНИЕ" : "БОЕВОЕ");
const describeScenario = (code) => {
  const s = meta && meta.scenarios.find((x) => x.code === code);
  return s && s.description ? s.description : code;
};
const biometryName = () => ({ face: "Face ID", fingerprint: "Touch ID", iris: "Optic ID" })[biometry] || "биометрией";
const errorText = (error) => (error.code ? L.vaultMessage(error) : error.message);

// One list row. `lead` is the coloured square on the left, `value` the grey text on
// the right; a row with `onclick` is a button with a chevron.
function cell({ title, sub, value, valueClass, lead, onclick, extra }) {
  const kids = [
    lead || null,
    el("div", { class: "body" }, el("div", { class: "title" }, title), sub ? el("div", { class: "sub" }, sub) : null),
    value != null ? el("div", { class: "value " + (valueClass || "") }, value) : null,
    extra || null,
  ];
  const classes = ["cell", lead ? "with-lead" : "", onclick ? "nav" : ""].join(" ").trim();
  return onclick ? el("button", { type: "button", class: classes, onclick }, kids) : el("div", { class: classes }, kids);
}
const leadIcon = (name, tone) => el("span", { class: "lead-icon " + (tone || "") }, icon(name));
// A field of the review: grey label above, the value below.
const kv = (label, value, cls) => el("div", { class: "cell kv " + (cls || "") },
  el("div", { class: "body" }, el("div", { class: "label" }, label), el("div", { class: "val " + (cls || "") }, value)));
const group = (...rows) => el("div", { class: "group" }, rows);
const sectionTitle = (text) => el("div", { class: "section-title" }, text);
const empty = (name, title, sub) => el("div", { class: "empty" }, icon(name), el("div", { class: "title" }, title), sub ? el("div", { class: "sub" }, sub) : null);

// A button that shows a spinner while its work runs, and cannot be pressed twice.
async function busy(button, work) {
  button.disabled = true;
  button.classList.add("busy");
  try { return await work(); }
  finally { button.classList.remove("busy"); button.disabled = false; }
}

// A sheet from the bottom of the screen: the app's own, instead of confirm() and of
// fields squeezed into a row. `build(close)` returns its content; `onDismiss` runs
// when the person taps outside it, `onGone` once it has left the page either way.
function sheet(build, { onDismiss, onGone } = {}) {
  const layer = el("div", { class: "sheet-layer" });
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    layer.classList.add("closing");
    setTimeout(() => { layer.remove(); if (onGone) onGone(); }, 200);
  };
  const dismiss = () => { close(); if (onDismiss) onDismiss(); };
  layer.append(el("div", { class: "scrim", onclick: dismiss }),
    el("div", { class: "sheet", role: "dialog", "aria-modal": "true" }, el("div", { class: "grabber" }), build(close)));
  document.body.append(layer);
  return close;
}

// Yes or no, in a sheet. Resolves true only on the named action.
function ask({ title, text, ok, danger }) {
  return new Promise((resolve) => {
    sheet((close) => [
      el("h2", {}, title),
      text ? el("p", { class: "sheet-text" }, text) : null,
      el("button", { type: "button", class: "btn " + (danger ? "danger" : "primary"), onclick: () => { close(); resolve(true); } }, ok),
      el("button", { type: "button", class: "btn", onclick: () => { close(); resolve(false); } }, "Отмена"),
    ], { onDismiss: () => resolve(false) });
  });
}

function toast(text, kind = "ok") {
  const node = el("div", { class: "toast " + kind, role: "status" }, text);
  document.body.append(node);
  requestAnimationFrame(() => node.classList.add("show"));
  setTimeout(() => { node.classList.remove("show"); setTimeout(() => node.remove(), 300); }, 2600);
}

function show(screen) {
  for (const id of ["setup", "login", "main", "detail"]) $(id).classList.toggle("hidden", id !== screen);
  window.scrollTo(0, 0);
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
  const demo = Boolean(config && config.demo);
  $("demo-banner").classList.toggle("hidden", !demo);
  document.body.classList.toggle("demo", demo);
  $("enroll-person-row").classList.toggle("hidden", demo);
  $("enroll-person").required = !demo;
}

$("setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("setup-msg");
  out.replaceChildren();
  await busy(event.submitter || $("setup-form").querySelector("button"), async () => {
    try {
      panelUrl = L.normalizePanelUrl($("panel-url").value);
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
});

// ---- 2. login ----------------------------------------------------------------------
async function showLogin(reason) {
  token = null; me = null;
  show("login");
  renderChrome();
  $("enroll-msg").replaceChildren();
  $("login-msg").replaceChildren(reason ? msg("warn", reason) : "");
  $("login-panel").textContent = panelUrl.replace(/^https:\/\//, "") + (config ? ` · ${config.org_id}` : "");
  let keys = [];
  try {
    const status = await Vault.status();
    biometry = status.biometry || "none";
    keys = (await Vault.list()).filter((k) => k.panel === panelUrl && (!config || k.org_id === config.org_id));
  } catch (error) {
    $("login-msg").replaceChildren(msg("err", L.vaultMessage(error)));
  }
  fill($("login-keys"), keys.length ? [
    sectionTitle(keys.length > 1 ? "Ключи на этом телефоне" : "Ключ на этом телефоне"),
    keys.map((k) => {
      const enter = el("button", { class: "btn primary", type: "button" }, `Войти с ${biometryName()}`);
      enter.addEventListener("click", () => busy(enter, () => login(k)));
      return el("div", { class: "keycard" },
        cell({ lead: leadIcon("key"), title: k.person_id, sub: `ключ ${L.keyShort(k.key_id)}`,
               extra: el("button", { type: "button", class: "icon-btn", "aria-label": "Действия с ключом", onclick: () => keyActions(k) }, "⋯") }),
        enter);
    }),
  ] : []);
  fill($("enroll-entry"), keys.length
    ? el("button", { type: "button", class: "btn plain", onclick: openEnroll }, "Зарегистрировать другой ключ")
    : el("button", { type: "button", class: "enroll-card", onclick: openEnroll },
        leadIcon("phone"),
        el("div", { class: "body" }, el("div", { class: "title" }, "Зарегистрировать этот телефон"),
          el("div", { class: "sub" }, "Ключ создаётся здесь и защищается биометрией. Нужен один раз."))));
}

async function login(keyRecord) {
  const out = $("login-msg");
  out.replaceChildren();
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
    out.replaceChildren(msg(L.isCancel(error) ? "warn" : "err", errorText(error)));
  }
}

function keyActions(keyRecord) {
  sheet((close) => [
    el("h2", {}, keyRecord.person_id),
    el("p", { class: "sheet-text" }, `Идентификатор ключа: ${keyRecord.key_id}`),
    el("button", { type: "button", class: "btn tinted-danger", onclick: () => { close(); forget(keyRecord); } }, "Удалить ключ с телефона"),
    el("button", { type: "button", class: "btn", onclick: close }, "Отмена"),
  ]);
}

async function forget(keyRecord) {
  const sure = await ask({
    title: "Удалить ключ?", danger: true, ok: "Удалить",
    text: "Войти можно будет только после новой регистрации. Если телефон больше не ваш, попросите отозвать ключ в справочнике.",
  });
  if (!sure) return;
  try {
    await Vault.remove(keyRecord.key_id);
    await showLogin();
    toast("Ключ удалён с телефона");
  } catch (error) {
    $("login-msg").replaceChildren(msg("err", L.vaultMessage(error)));
  }
}

// The enrolment form lives in #parked and moves into a sheet while it is open.
const enrollForm = $("enroll-form");
let closeEnroll = null;
function openEnroll() {
  $("enroll-err").replaceChildren();
  closeEnroll = sheet(() => enrollForm, { onGone: () => { closeEnroll = null; $("parked").append(enrollForm); } });
  if (!(config && config.demo)) setTimeout(() => $("enroll-person").focus(), 300);
}

// Copy a public value; where the WebView refuses the clipboard, the text is
// selectable all at once anyway (.mono).
function copyButton(text) {
  const button = el("button", { type: "button", class: "btn small" }, "Скопировать");
  button.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(text); toast("Скопировано"); }
    catch (_) { toast("Выделите текст и скопируйте", "warn"); }
  });
  return button;
}

enrollForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("enroll-err");
  const demo = Boolean(config && config.demo);
  let personId = $("enroll-person").value.trim();
  if (!demo && !L.PERSON_ID.test(personId)) { out.replaceChildren(msg("err", "Идентификатор: латиница, цифры и дефис, например p-010.")); return; }
  await busy(enrollForm.querySelector("button[type=submit]"), async () => {
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
      if (closeEnroll) closeEnroll();
      await showLogin();
      if (demo) {
        toast(`Телефон зарегистрирован как «${personId}»`);
        return;
      }
      fill($("enroll-msg"),
        msg("ok", el("b", {}, "Ключ создан и защищён биометрией."), " Передайте регистрирующему лично публичный ключ и сверьте идентификатор после внесения в справочник."),
        group(
          el("div", { class: "cell kv" }, el("div", { class: "body" }, el("div", { class: "label" }, "Публичный ключ"),
            el("div", { class: "val mono" }, keyRecord.public_key)), copyButton(keyRecord.public_key)),
          el("div", { class: "cell kv" }, el("div", { class: "body" }, el("div", { class: "label" }, "Идентификатор ключа"),
            el("div", { class: "val mono" }, keyRecord.key_id)), copyButton(keyRecord.key_id))),
        el("p", { class: "footnote" }, "Если на телефоне поменять набор отпечатков или лиц, ключ станет недоступен — это защита, а не сбой: понадобится новая регистрация."));
    } catch (error) {
      out.replaceChildren(msg("err", errorText(error)));
    }
  });
});

$("change-panel").addEventListener("click", () => showSetup());

async function logout() {
  await api("/api/logout", { method: "POST" }).catch(() => {});
  await showLogin();
  toast("Вы вышли");
}

// ---- 3. lists ----------------------------------------------------------------------
const TAB_TITLES = { sign: "На подпись", events: "Действуют", orders: "История", new: "Создать" };

async function start() {
  meta = await api("/api/meta");
  $("account").textContent = L.initials(me.name, me.person_id);
  fillForm();
  showTab("sign");
  show("main");
  await refresh();
}

function showTab(name) {
  for (const button of document.querySelectorAll(".tabbar button")) button.classList.toggle("active", button.dataset.tab === name);
  for (const tab of ["sign", "events", "orders", "new"]) $(`tab-${tab}`).classList.toggle("hidden", tab !== name);
  $("tab-title").textContent = TAB_TITLES[name];
  window.scrollTo(0, 0);
}
for (const button of document.querySelectorAll(".tabbar button")) button.addEventListener("click", () => showTab(button.dataset.tab));

const modeLead = (drill) => leadIcon(drill ? "history" : "alert", drill ? "" : "real");

async function refresh() {
  const [proposals, orders, events] = await Promise.all([
    api("/api/proposals"), api("/api/orders"), api("/api/events/active")]);
  now = proposals.now;
  const open = L.openProposals(proposals.proposals);
  $("sign-count").textContent = String(open.length);
  $("sign-count").classList.toggle("hidden", !open.length);
  fill($("proposals"), open.length ? group(open.map((p) => cell({
    lead: leadIcon("sign", p.drill ? "" : "real"),
    title: [modeTag(p.drill), p.cancels ? "Отбой: " : "", describeScenario(p.scenario)],
    sub: `${p.signed_by.length} ${L.plural(p.signed_by.length, "подпись", "подписи", "подписей")} · ${L.left(p.not_valid_after, now)}`,
    onclick: () => openProposal(p.order_id),
  }))) : empty("sign", "Нечего подписывать", "Новые предложения появятся здесь."));
  fill($("events"), events.events.length ? group(events.events.map((e) => cell({
    lead: modeLead(e.drill),
    title: [modeTag(e.drill), describeScenario(e.scenario)],
    sub: `с ${L.time(e.dispatched_at)} · ` + (e.until_cancelled ? "до отбоя" : `до ${L.time(e.not_valid_after)}`),
    onclick: () => openOrder(e.order_id),
  }))) : empty("calm", "Всё спокойно", "Действующих оповещений нет."));
  fill($("orders"), orders.orders.length ? group(orders.orders.map((o) => cell({
    lead: modeLead(o.drill),
    title: [modeTag(o.drill), o.cancels ? "Отбой: " : "", describeScenario(o.scenario)],
    sub: [L.time(o.dispatched_at), o.cancelled_by ? el("span", { class: "tag ok" }, "отменено") : null],
    onclick: () => openOrder(o.order_id),
  }))) : empty("history", "Пока пусто", "Разосланные оповещения появятся здесь."));
  renderRenewal();
}

// ---- keeping the session -----------------------------------------------------------
// The delegation lasts 12 h and only the device key can sign the next one -- which
// here means biometrics. So the app never renews on its own: it shows a button.
function renderRenewal() {
  const note = $("renew-note");
  if (!L.needsRenewal(me, Math.floor(Date.now() / 1000))) { note.replaceChildren(); return; }
  const button = el("button", { type: "button", class: "btn small primary" }, "Продлить");
  button.addEventListener("click", () => busy(button, renew));
  fill(note, el("div", { class: "renew" },
    el("div", { class: "body" }, `Сеанс истекает в ${L.time(me.delegation_until)}`), button));
}

async function renew() {
  try {
    const begun = await api("/api/device/renew/begin", { method: "POST" });
    DeviceKey.checkDelegation(begun.delegation, record, Math.floor(Date.now() / 1000));
    const signature = await withKey(record, "Продлить сеанс «Оповещение ЛПР»",
      (key) => DeviceKey.sign(key, "delegation", begun.delegation));
    me = await api("/api/device/renew/finish", { method: "POST", body: { signature } });
    renderRenewal();
    toast(`Сеанс продлён до ${L.time(me.delegation_until)}`);
  } catch (error) {
    if (error.message !== "401") toast(errorText(error), "warn");
  }
}

$("account").addEventListener("click", () => {
  sheet((close) => {
    const renewBtn = el("button", { type: "button", class: "btn" }, `Продлить сеанс (${biometryName()})`);
    renewBtn.addEventListener("click", () => busy(renewBtn, async () => { await renew(); close(); }));
    return [
      el("div", { class: "who-card" }, el("div", { class: "avatar" }, L.initials(me.name, me.person_id)),
        el("div", { class: "name" }, me.name || me.person_id),
        el("div", { class: "sub" }, `${me.person_id} · ключ ${L.keyShort(me.key_id || record.key_id)}`)),
      group(
        cell({ title: "Панель", value: panelUrl.replace(/^https:\/\//, "") }),
        cell({ title: "Организация", value: config ? config.org_id : "—" }),
        me.delegation_until ? cell({ title: "Сеанс до", value: L.time(me.delegation_until) }) : null),
      me.delegation_until ? renewBtn : null,
      privacyUrl() ? el("a", { class: "btn", href: privacyUrl(), target: "_blank", rel: "noopener" }, "Политика конфиденциальности") : null,
      el("button", { type: "button", class: "btn tinted-danger", onclick: () => { close(); logout(); } }, "Выйти"),
    ];
  });
});

// ---- 4. review and sign ------------------------------------------------------------
function openDetail(kind, id, title) {
  current = { kind, id };
  show("detail");
  $("detail-title").textContent = title;
}

async function openProposal(id) {
  openDetail("proposal", id, "Проверка приказа");
  const body = $("detail-body");
  body.replaceChildren(el("div", { class: "empty" }, el("div", { class: "sub" }, "Загружаю приказ…")));
  let view;
  try { view = await api(`/api/proposals/${encodeURIComponent(id)}`); }
  catch (error) { body.replaceChildren(msg("err", error.message)); return; }
  if (view.status === "dispatched") { openOrder(id); return; }
  now = view.now;
  const f = DeviceKey.describe(view.payload);
  const problems = await DeviceKey.reviewProblems(view.payload, view.digest, record.org_id);
  const audience = L.audienceSummary(f.audience, f.drill);
  const rows = [
    kv("Режим", f.drill ? "Учение" : "БОЕВОЕ", f.drill ? "strong" : "real"),
    kv("Действие", L.ACTION[f.action] || f.action),
    rssOnly()
      ? kv("Куда", "RSS-лента" + (f.drill ? " (с пометкой «УЧЕНИЕ»)" : ""))
      : kv("Кому", audience.text, audience.everyone ? "" : "alert"),
    kv("Пояснение", f.text || "—"),
    // Two different times: how long the event lasts, and how long this proposal
    // waits for its signatures. They used to share one line, "Действует до 21:44".
    f.cancels ? null : kv("Действует", untilCancelled(f.scenario) ? "до отбоя" : `до ${L.time(f.not_valid_after)}`),
    kv("Ждёт подписей", `до ${L.time(f.not_valid_after)} (${L.left(f.not_valid_after, now)})`),
    f.cancels ? kv("Отменяет приказ", f.cancels) : null,
    kv("Сценарий", f.scenario),
  ];
  const technical = [
    kv("Подтверждение", f.requires_ack ? `требуется, срок ${f.ack_deadline_s} с` : "не требуется"),
    kv("Поток / номер", f.stream), kv("Организация / политика", `${f.org_id} / ${f.policy_id}`),
  ];

  const blocked = f.unexpected_fields.length > 0 || view.signed_by_me || !view.can_sign || problems.length > 0;
  const check = el("input", { type: "checkbox", class: "switch", "aria-label": "Я проверил все поля приказа" });
  const signBtn = el("button", { class: "btn " + (f.drill ? "primary" : "danger"), type: "button", disabled: "" },
    f.drill ? "Подписать учение" : "Подписать БОЕВОЙ приказ");
  const out = el("div");
  if (blocked) check.disabled = true;
  check.addEventListener("change", () => { signBtn.disabled = !check.checked || blocked; });
  signBtn.addEventListener("click", async () => {
    signBtn.disabled = true;
    signBtn.classList.add("busy");
    try {
      const reason = `${f.cancels ? "ОТБОЙ · " : ""}${f.drill ? "УЧЕНИЕ" : "БОЕВОЕ"}: ${describeScenario(f.scenario)}`;
      const sig = await withKey(record, `Подписать — ${reason}`, (key) => DeviceKey.sign(key, "order", view.payload));
      const result = await api(`/api/proposals/${encodeURIComponent(id)}/sign`, { method: "POST", body: { digest: view.digest, sig } });
      signBtn.classList.remove("busy");
      if (result.dispatched) {
        toast(rssOnly() ? "Подписано — опубликовано в RSS-ленте"
          : `Разослано: ${result.recipients} ${L.plural(result.recipients, "получатель", "получателя", "получателей")}`);
        fill(out, result.warnings.map((w) => msg("warn", w)));
        setTimeout(() => openOrder(id), 1200);
      } else {
        fill(out, msg("ok", el("b", {}, "Подпись принята."), rssOnly() ? " Ещё не опубликовано:" : " Ещё не разослано:",
          el("ul", {}, result.blocking.map((b) => el("li", {}, L.blockingText(b))))));
        check.checked = false; check.disabled = true;
        out.scrollIntoView({ behavior: "smooth", block: "center" });
      }
      refresh().catch(() => {});
    } catch (error) {
      signBtn.classList.remove("busy");
      out.replaceChildren(msg(L.isCancel(error) ? "warn" : "err", errorText(error)));
      signBtn.disabled = !check.checked || blocked;
    }
  });

  const signable = view.can_sign && !view.signed_by_me;
  const required = view.required ?? "?";
  const dots = Number.isInteger(view.required) && view.required <= 6
    ? el("div", { class: "dots" }, Array.from({ length: view.required }, (_, i) => el("i", { class: i < view.signed_by.length ? "on" : "" })))
    : null;
  fill(body,
    el("div", { class: "hero-card " + (f.drill ? "drill" : "real") },
      el("div", { class: "mode" }, (f.cancels ? "ОТБОЙ · " : "") + (f.drill ? "УЧЕНИЕ" : "БОЕВОЕ — РЕАЛЬНОЕ ОПОВЕЩЕНИЕ")),
      el("div", { class: "what" }, describeScenario(f.scenario)),
      el("div", { class: "meta" }, view.can_sign ? "Проверьте и подпишите" : "Ждёт подписи ЛПР")),
    audience.everyone || rssOnly() ? null : msg("err", el("b", {}, "Необычные получатели: "), audience.text, ". Проверьте, прежде чем подписывать."),
    f.unexpected_fields.length ? msg("err", el("b", {}, "В приказе есть поля, которые экран не показывает: "), f.unexpected_fields.join(", "), ". Не подписывайте.") : null,
    problems.length ? msg("err", el("b", {}, "Подписать нельзя: "), problems.join("; "), ".") : null,
    sectionTitle("Приказ"),
    group(rows),
    sectionTitle("Подписи"),
    group(
      cell({ title: `${view.signed_by.length} из ${required}`, sub: Number(required) > 1 ? "от разных людей" : null, extra: dots }),
      view.signed_by.map((s) => cell({ title: s, lead: leadIcon("calm", "ok") }))),
    view.signed_by_me ? msg("warn", "Вы уже подписали. Нужна подпись другого человека.") : null,
    el("details", { class: "cell-details" }, el("summary", {}, "Технические поля"), technical),
    out,
    signable ? el("div", { class: "actionbar" },
      el("label", { class: "confirm" }, el("span", {}, "Я проверил все поля приказа"), check),
      signBtn,
      el("div", { class: "hint" }, `Подпись ставит ключ этого телефона после ${biometryName()} — над показанными полями.`)) : null,
  );
}

async function openOrder(id) {
  openDetail("order", id, "Оповещение");
  let s;
  try { s = await api(`/api/orders/${encodeURIComponent(id)}`); }
  catch (error) { $("detail-body").replaceChildren(msg("err", error.message)); return; }
  now = s.now;
  const total = s.people.length;
  const progress = el("progress", { max: String(Math.max(total, 1)), value: String(s.acknowledged) });
  const canCancel = me.can_issue && !s.cancels && !s.cancelled_by;
  const signers = s.signed_by || [];
  fill($("detail-body"),
    el("div", { class: "hero-card " + (s.drill ? "drill" : "real") },
      el("div", { class: "mode" }, `${s.cancels ? "ОТБОЙ · " : ""}${s.drill ? "УЧЕНИЕ" : "БОЕВОЕ"} · ${L.time(s.dispatched_at)}`),
      el("div", { class: "what" }, describeScenario(s.scenario)),
      // RSS only: nobody is sent anything, so there is nothing to confirm -- "0 из 0
      // подтвердили" answered a question this installation does not ask.
      s.rss_only
        ? el("div", { class: "meta" }, "Опубликовано в RSS-ленте")
        : el("div", { class: "big-count" }, `${s.acknowledged} `, el("small", {}, `из ${total} подтвердили`)),
      s.rss_only ? null : el("div", { class: "progress-line" }, progress)),
    s.reached_nobody ? msg("err", "Приказ не дошёл ни до кого: в аудитории нет активных контактов.") : null,
    s.rss_only ? null : s.outstanding.length ? msg("warn", `Нет подтверждения: ${s.outstanding.length} чел. — идёт эскалация по каналам.`) : (total ? msg("ok", "Все подтвердили.") : null),
    s.cancelled_by ? msg("ok", "Событие отменено отбоем.") : null,
    group(
      !s.cancels && !s.cancelled_by ? cell({ title: "Действует", value: s.until_cancelled ? "до отбоя" : `до ${L.time(s.not_valid_after)}` }) : null,
      s.cancels ? cell({ title: "Открыть отменённое событие", onclick: () => openOrder(s.cancels) }) : null),
    sectionTitle(`Подписали · ${signers.length}`),
    signers.length ? group(signers.map((name) => cell({ title: name, lead: leadIcon("calm", "ok") })))
      : el("p", { class: "footnote" }, "Подписи не найдены."),
    s.rss_only ? null : sectionTitle(`Кто ответил · ${total}`),
    s.rss_only ? null : total ? group(s.people.map((p) => cell({
      title: p.name || p.person_id,
      value: p.ack_valid === false ? "ПОДДЕЛЬНАЯ РАСПИСКА" : p.ack_status ? (L.ACK[p.ack_status] || p.ack_status) : "нет ответа",
      valueClass: L.ackTone(p),
    }))) : el("p", { class: "footnote" }, "Получателей нет."),
    canCancel ? el("div", { class: "list-gap" }, el("button", { type: "button", class: "btn tinted-danger", onclick: () => askCancel(s) }, "Отбой…")) : null,
  );
}

// Stand down: a reason, then a proposal that needs signing like any other.
function askCancel(s) {
  sheet((close) => {
    const reason = el("textarea", { rows: "3", maxlength: "1000", placeholder: "Причина отбоя" });
    const out = el("div");
    const go = el("button", { type: "button", class: "btn danger" }, "Создать отбой");
    go.addEventListener("click", () => busy(go, async () => {
      try {
        const created = await api(`/api/orders/${encodeURIComponent(s.order_id)}/cancel`, { method: "POST", body: { text: reason.value.trim() } });
        close();
        openProposal(created.order_id);
      } catch (error) { out.replaceChildren(msg("err", error.message)); }
    }));
    return [
      el("h2", {}, "Отбой"),
      el("p", { class: "sheet-text" }, `«${describeScenario(s.scenario)}». Отбой — тоже приказ: его нужно будет подписать.`),
      group(reason),
      out, go,
      el("button", { type: "button", class: "btn", onclick: close }, "Отмена"),
    ];
  });
}

$("back").addEventListener("click", () => { current = null; show("main"); refresh().catch(() => {}); });

// ---- new proposal ------------------------------------------------------------------
const chosenScenario = () => {
  const picked = document.querySelector("input[name=scenario]:checked");
  return picked ? meta.scenarios.find((x) => x.code === picked.value) : null;
};
// The installation publishes to the RSS feed only (ALERTING_DELIVERY=rss): nothing is
// sent to anyone, so the screens speak of the feed, not of recipients.
const rssOnly = () => Boolean(meta && meta.delivery === "rss");
const untilCancelled = (code) => {
  const s = meta && meta.scenarios.find((x) => x.code === code);
  return Boolean(s && s.until_cancelled);
};
const chosenTtl = () => Number((document.querySelector("input[name=ttl]:checked") || { value: 900 }).value);

const pickRow = (name, value, title, sub, onchange) => el("label", { class: "cell pick" },
  el("input", { type: "radio", name, value, onchange }),
  el("div", { class: "body" }, el("div", { class: "title" }, title), sub ? el("div", { class: "sub" }, sub) : null));

function fillForm() {
  fill($("scenarios"), meta.scenarios.map((s) => pickRow("scenario", s.code, s.description || s.code, s.code, fillScenario)));
  for (const radio of document.querySelectorAll("input[name=drill]")) radio.onchange = updateSummary;
  fillScenario();
}

// There is no level to choose: an event is a drill or real, the scenario fixes the
// rest (the panel takes the scenario's own level).
function fillScenario() {
  const s = chosenScenario();
  const parts = [];
  if (s && s.until_cancelled) parts.push("Действует до отбоя.");
  if (s && s.card) parts.push(`Люди увидят: «${s.card}»`);
  $("scenario-hint").textContent = parts.join(" ");
  $("scenario-hint").classList.toggle("hidden", !parts.length);
  updateSummary();
}

function updateSummary() {
  const s = chosenScenario();
  const mode = document.querySelector("input[name=drill]:checked");
  const rule = s && meta.severities[s.severity];
  const row = (k, v) => el("div", { class: "row" }, el("span", {}, k), el("span", {}, v));
  if (!s) { fill($("summary"), el("div", { class: "hint" }, "Выберите, что случилось.")); return; }
  fill($("summary"),
    rssOnly()
      ? row("Куда", "RSS-лента" + (mode && mode.value === "true" ? " (с пометкой «УЧЕНИЕ»)" : "") + ", рассылки нет")
      : row("Получат", `все (${meta.recipients} чел.)` + (mode && mode.value === "false" ? " и RSS-лента" : "")),
    row("Нужно подписей ЛПР", `${rule ? rule.launch : "?"}` + (rule && rule.launch > 1 ? " — от разных людей" : "")),
    mode ? null : row("Режим", "не выбран"));
}

$("new-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("new-msg");
  const s = chosenScenario();
  const mode = document.querySelector("input[name=drill]:checked");
  if (!s) { out.replaceChildren(msg("err", "Выберите, что случилось.")); return; }
  if (!mode) { out.replaceChildren(msg("err", "Выберите: учение или боевое.")); return; }
  await busy(event.submitter || $("new-form").querySelector("button[type=submit]"), async () => {
    try {
      const created = await api("/api/proposals", { method: "POST", body: {
        scenario: s.code, drill: mode.value === "true",
        text: $("text").value.trim(), ttl_s: chosenTtl(),
      }});
      out.replaceChildren();
      $("text").value = "";
      mode.checked = false;
      updateSummary();
      openProposal(created.order_id);
    } catch (error) {
      out.replaceChildren(msg("err", error.message));
    }
  });
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
