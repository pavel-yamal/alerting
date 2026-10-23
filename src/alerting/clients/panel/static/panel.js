"use strict";

const SEVERITY = { info: "информация", warning: "предупреждение", critical: "критическая", catastrophic: "катастрофическая" };
const ORDER = ["info", "warning", "critical", "catastrophic"];
const ACK = { received: "получено устройством", acknowledged: "подтвердил", en_route: "выдвинулся",
              completed: "выполнил", cannot_comply: "не может выполнить" };
const ACTION = { START: "начать", STOP: "прекратить (отбой)", HOLD: "приостановить" };

let meta = null;
let me = null;
let current = null;           // { kind: "proposal" | "order", id }
// The unlocked device key: a non-extractable CryptoKey, in this page's memory only.
// A reload drops it, and with it the ability to sign -- the person logs in again.
let deviceKey = null;
let deviceRecord = null;
let now = Math.floor(Date.now() / 1000);

// ---- helpers ---------------------------------------------------------------
// Everything from the server goes in through textContent. Nothing is ever parsed
// as HTML: order text is free text typed by a person.
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
// replaceChildren() turns null into the text "null"; optional blocks are passed as
// `condition ? node : null`, so they are filtered out here.
const fill = (node, ...kids) => node.replaceChildren(...kids.flat().filter((k) => k != null && k !== false));
const time = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString("ru-RU") : "—";
const left = (until) => {
  const s = until - now;
  if (s <= 0) return "истёк";
  return s >= 60 ? `ещё ${Math.floor(s / 60)} мин` : `ещё ${s} с`;
};
const modeTag = (drill) => el("span", { class: "tag " + (drill ? "drill" : "real") }, drill ? "УЧЕНИЕ" : "БОЕВОЕ");
const msg = (kind, text) => el("div", { class: "msg " + kind }, text);

async function api(path, options = {}) {
  const init = { method: options.method || "GET", headers: {}, credentials: "same-origin" };
  // Background polling must not count as activity, or an unattended tab would keep
  // the session -- and the unlocked key -- alive forever.
  if (!options.poll) init.headers["X-Alerting-Activity"] = "1";
  if (init.method !== "GET") {
    init.headers["X-Alerting-Panel"] = "1";
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body || {});
  }
  const response = await fetch(path, init);
  let data = null;
  try { data = await response.json(); } catch (_) { /* empty body */ }
  if (response.status === 401 && !path.startsWith("/api/login") && !path.startsWith("/api/device/")) {
    showLogin(data && data.detail); throw new Error("401");
  }
  if (!response.ok) {
    const detail = data && data.detail;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail || response.status));
  }
  return data;
}

// ---- login -----------------------------------------------------------------
let config = { device_login: false, server_keys: false, org_id: null };

function showLogin(reason) {
  deviceKey = null;
  $("app").classList.add("hidden");
  $("login").classList.remove("hidden");
  $("login-msg").replaceChildren(reason ? msg("warn", reason) : "");
  renderLogin().catch((error) => $("login-msg").replaceChildren(msg("err", error.message)));
}

async function renderLogin() {
  config = await api("/api/config");
  $("login-form").classList.toggle("hidden", !config.server_keys);
  const problem = config.device_login ? await DeviceKey.supported() : null;
  const usable = config.device_login && !problem;
  $("login-support").replaceChildren(problem ? msg("err", problem) : "");
  $("enroll-row").classList.toggle("hidden", !usable);
  const keys = usable ? DeviceKey.list().filter((k) => !config.org_id || k.org_id === config.org_id) : [];
  $("device-form").classList.toggle("hidden", !keys.length);
  $("device-key").replaceChildren(...keys.map((k) =>
    el("option", { value: k.key_id }, `${k.person_id} · ${k.key_id.slice(8, 16)}…`)));
  if (config.device_login && !problem && !keys.length) {
    $("login-support").replaceChildren(msg("warn",
      "На этом устройстве ещё нет ключа. Зарегистрируйте устройство — лично, у регистрирующего."));
  }
}

$("device-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const keyId = $("device-key").value;
  const record = DeviceKey.list().find((k) => k.key_id === keyId);
  $("login-msg").replaceChildren(msg("warn", "Открываю ключ и проверяю справочник…"));
  try {
    const key = await DeviceKey.unlock(keyId, $("device-pass").value);
    const begun = await api("/api/device/begin", { method: "POST", body: { person_id: record.person_id, key_id: keyId } });
    // Signed only after checking it is a delegation for this very key, bounded in time.
    DeviceKey.checkDelegation(begun.delegation, record, Math.floor(Date.now() / 1000));
    const signature = await DeviceKey.sign(key, "delegation", begun.delegation);
    await api("/api/device/finish", { method: "POST", body: { challenge: begun.challenge, signature } });
    $("device-pass").value = "";
    deviceKey = key;
    deviceRecord = record;
    await start();
  } catch (error) {
    $("login-msg").replaceChildren(msg("err", error.message));
  }
});

$("forget-key").addEventListener("click", () => {
  const keyId = $("device-key").value;
  if (!keyId || !confirm("Удалить ключ с этого устройства? Войти с него можно будет только после новой регистрации.")) return;
  DeviceKey.forget(keyId);
  showLogin("Ключ удалён с устройства. Попросите отозвать его в справочнике, если устройство больше не ваше.");
});

$("enroll-open").addEventListener("click", () => $("enroll-form").classList.toggle("hidden"));

$("enroll-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("enroll-result");
  const personId = $("enroll-person").value.trim();
  const pass = $("enroll-pass").value;
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(personId)) { out.replaceChildren(msg("err", "Идентификатор: латиница, цифры и дефис, например p-010.")); return; }
  if (pass.length < 10) { out.replaceChildren(msg("err", "Пароль — не короче 10 символов.")); return; }
  if (pass !== $("enroll-pass2").value) { out.replaceChildren(msg("err", "Пароли не совпадают.")); return; }
  try {
    const record = await DeviceKey.create(personId, pass, config.org_id);
    $("enroll-pass").value = ""; $("enroll-pass2").value = "";
    out.replaceChildren(
      msg("ok", "Ключ создан на этом устройстве. Передайте регистрирующему лично:"),
      el("div", { class: "hint" }, "Публичный ключ"), el("div", { class: "keybox" }, record.public_key),
      el("div", { class: "hint" }, "Идентификатор ключа — сверьте его в справочнике после внесения"),
      el("div", { class: "keybox" }, record.key_id),
      el("div", { class: "hint" }, "Войти получится, когда ключ внесут в справочник. На iPhone и iPad добавьте панель на экран «Домой» (Поделиться → На экран «Домой»): иначе Safari может стереть ключ, если панель долго не открывать."),
    );
    await renderLogin();
  } catch (error) {
    out.replaceChildren(msg("err", error.message));
  }
});

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("login-msg").replaceChildren(msg("warn", "Расшифровываю ключ и проверяю справочник…"));
  try {
    await api("/api/login", { method: "POST", body: { person_id: $("person").value, passphrase: $("pass").value } });
    $("pass").value = "";
    await start();
  } catch (error) {
    $("login-msg").replaceChildren(msg("err", error.message));
  }
});

$("logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" }).catch(() => {});
  showLogin("Вы вышли.");
});

// ---- new proposal form -----------------------------------------------------
function fillForm() {
  const scenario = $("scenario");
  scenario.replaceChildren(...meta.scenarios.map((s) =>
    el("option", { value: s.code }, s.description ? `${s.code} — ${s.description}` : s.code)));
  $("groups").replaceChildren(
    el("div", { class: "hint" }, "Группы:"),
    ...meta.groups.map((g) => el("label", { class: "inline" }, el("input", { type: "checkbox", name: "group", value: g }), g)));
  $("sites").replaceChildren(
    el("div", { class: "hint" }, "Площадки:"),
    ...meta.sites.map((s) => el("label", { class: "inline" }, el("input", { type: "checkbox", name: "site", value: s }), s)));
  scenario.onchange = fillSeverity;
  $("severity").onchange = quorumHint;
  fillSeverity();
}

function fillSeverity() {
  const s = meta.scenarios.find((x) => x.code === $("scenario").value);
  const lo = s && s.min_severity ? ORDER.indexOf(s.min_severity) : 0;
  const hi = s && s.max_severity ? ORDER.indexOf(s.max_severity) : ORDER.length - 1;
  const allowed = ORDER.filter((level, i) => i >= lo && i <= hi && meta.severities[level]);
  $("severity").replaceChildren(...allowed.map((level) => el("option", { value: level }, SEVERITY[level])));
  const parts = [];
  if (s && (s.min_severity || s.max_severity)) parts.push(`Уровни: ${allowed.map((l) => SEVERITY[l]).join(", ")}.`);
  if (s && s.until_cancelled) parts.push("Действует до отбоя: эскалация не останавливается по сроку.");
  if (s && s.card) parts.push(`Исполнитель увидит: «${s.card}»`);
  $("scenario-hint").textContent = parts.join(" ");
  quorumHint();
}

function quorumHint() {
  const rule = meta.severities[$("severity").value];
  if (!rule) { $("quorum-hint").textContent = ""; return; }
  let text = `Нужно подписей: ${rule.launch}`;
  if (rule.launch > 1 && rule.distinct_persons) text += " от разных людей";
  const roles = Object.entries(rule.min_from_role || {}).map(([r, n]) => `${r} ×${n}`);
  if (roles.length) text += `, в том числе ${roles.join(", ")}`;
  if (rule.spread_s) text += `, все — в пределах ${Math.round(rule.spread_s / 60)} мин`;
  $("quorum-hint").textContent = text + ".";
}

$("new-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("new-msg");
  const mode = document.querySelector("input[name=drill]:checked");
  if (!mode) { out.replaceChildren(msg("err", "Выберите режим: УЧЕНИЕ или БОЕВОЕ.")); return; }
  const groups = [...document.querySelectorAll("input[name=group]:checked")].map((x) => x.value);
  const sites = [...document.querySelectorAll("input[name=site]:checked")].map((x) => x.value);
  if (!groups.length && !sites.length) { out.replaceChildren(msg("err", "Выберите, кого оповещать.")); return; }
  try {
    const created = await api("/api/proposals", { method: "POST", body: {
      scenario: $("scenario").value, severity: $("severity").value, drill: mode.value === "true",
      groups, sites, text: $("text").value.trim(), ttl_s: Number($("ttl").value),
    }});
    out.replaceChildren(msg("ok", "Создано. Проверьте и подпишите."));
    $("text").value = "";
    mode.checked = false;
    await refreshLists();
    openProposal(created.order_id);
  } catch (error) {
    out.replaceChildren(msg("err", error.message));
  }
});

// ---- lists -----------------------------------------------------------------
async function refreshLists(poll = false) {
  const [proposals, orders, events] = await Promise.all([
    api("/api/proposals", { poll }), api("/api/orders", { poll }), api("/api/events/active", { poll })]);
  now = proposals.now;
  $("events").replaceChildren(...(events.events.length ? events.events.map((e) =>
    el("div", { class: "item" + (current && current.id === e.order_id ? " active" : ""), onclick: () => openOrder(e.order_id) },
      el("div", { class: "top" }, modeTag(e.drill), e.scenario),
      el("div", { class: "sub" }, `${SEVERITY[e.severity]} · с ${time(e.dispatched_at)} · `
        + (e.until_cancelled ? "до отбоя" : `до ${time(e.not_valid_after)}`))))
    : [el("div", { class: "empty" }, "Действующих событий нет.")]));
  const open = proposals.proposals.filter((p) => p.status === "open");
  $("proposals").replaceChildren(...(open.length ? open.map((p) =>
    el("div", { class: "item" + (current && current.id === p.order_id ? " active" : ""), onclick: () => openProposal(p.order_id) },
      el("div", { class: "top" }, modeTag(p.drill), p.cancels ? "ОТБОЙ " : "", p.scenario),
      el("div", { class: "sub" }, `${SEVERITY[p.severity]} · подписали: ${p.signed_by.length ? p.signed_by.join(", ") : "никто"} · ${left(p.not_valid_after)}`)))
    : [el("div", { class: "empty" }, "Нет приказов, ожидающих подписи.")]));
  $("orders").replaceChildren(...(orders.orders.length ? orders.orders.map((o) =>
    el("div", { class: "item" + (current && current.id === o.order_id ? " active" : ""), onclick: () => openOrder(o.order_id) },
      el("div", { class: "top" }, modeTag(o.drill), o.cancels ? "ОТБОЙ " : "", o.scenario,
        o.cancelled_by ? el("span", { class: "tag ok" }, "отменён") : null),
      el("div", { class: "sub" }, `${SEVERITY[o.severity]} · разослан ${time(o.dispatched_at)}`)))
    : [el("div", { class: "empty" }, "Ещё ничего не разослано.")]));
}

$("open-btn").addEventListener("click", () => {
  const id = $("open-id").value.trim();
  if (id) openProposal(id);
});

// ---- review and sign -------------------------------------------------------
async function openProposal(id) {
  current = { kind: "proposal", id };
  const detail = $("detail");
  let view;
  try { view = await api(`/api/proposals/${encodeURIComponent(id)}`); }
  catch (error) { detail.replaceChildren(msg("err", error.message)); return; }
  if (view.status === "dispatched") { openOrder(id); return; }
  now = view.now;
  // With the key in this browser, the review is rendered from the payload itself --
  // the same object that will be signed -- not from the panel's description of it.
  const local = me.device_key;
  const f = local ? describeLocal(view.payload) : view.fields;
  const problems = [];
  if (local) {
    if (await DeviceKey.digestHex("order", view.payload) !== view.digest) problems.push("панель и страница видят разные приказы");
    if (deviceRecord && deviceRecord.org_id && view.payload.org_id !== deviceRecord.org_id) problems.push("приказ другой организации");
  }
  const audience = [
    f.audience.groups.length ? `группы: ${f.audience.groups.join(", ")}` : null,
    f.audience.sites.length ? `площадки: ${f.audience.sites.join(", ")}` : null,
    f.audience.persons.length ? `лично: ${f.audience.persons.join(", ")}` : null,
  ].filter(Boolean).join("; ") || "ПУСТО — приказ не дойдёт ни до кого";

  const rows = [
    ["Сценарий", f.scenario], ["Важность", SEVERITY[f.severity] || f.severity],
    ["Действие", ACTION[f.action] || f.action], ["Кому", audience],
    ["Пояснение", f.text || "—"],
    ["Действует", `до ${time(f.not_valid_after)} (${left(f.not_valid_after)})`],
    ["Подтверждение", f.requires_ack ? `требуется, срок ${f.ack_deadline_s} с` : "не требуется"],
    f.cancels ? ["ОТМЕНЯЕТ приказ", f.cancels] : null,
    ["Поток / номер", f.stream], ["Организация / политика", `${f.org_id} / ${f.policy_id}`],
  ].filter(Boolean);

  const check = el("input", { type: "checkbox", id: "reviewed" });
  const signBtn = el("button", { class: f.drill ? "primary" : "danger", type: "button", disabled: "" }, "Подписать");
  const out = el("div");
  const blocked = f.unexpected_fields.length > 0 || view.signed_by_me || !view.can_sign || problems.length > 0;
  check.addEventListener("change", () => { signBtn.disabled = !check.checked || blocked; });
  signBtn.addEventListener("click", async () => {
    signBtn.disabled = true;
    try {
      const body = { digest: view.digest };
      if (local) body.sig = await DeviceKey.sign(deviceKey, "order", view.payload);
      const result = await api(`/api/proposals/${encodeURIComponent(id)}/sign`, { method: "POST", body });
      if (result.dispatched) {
        out.replaceChildren(msg("ok", `Кворум набран — разослано ${result.recipients} получателям.`),
          ...result.warnings.map((w) => msg("warn", w)));
        await refreshLists();
        setTimeout(() => openOrder(id), 1200);
      } else {
        out.replaceChildren(msg("warn", "Подпись принята. Ещё не разослано:"),
          el("ul", {}, result.blocking.map((b) => el("li", {}, b))));
        await refreshLists();
        setTimeout(() => openProposal(id), 1500);
      }
    } catch (error) {
      out.replaceChildren(msg("err", error.message));
      signBtn.disabled = false;
    }
  });

  fill(detail,
    el("div", { class: "banner " + (f.drill ? "drill" : "real") },
      (f.cancels ? "ОТБОЙ · " : "") + (f.drill ? "УЧЕНИЕ" : "БОЕВОЕ — реальное оповещение")),
    el("h2", {}, "Вы подписываете"),
    el("table", {}, rows.map(([k, v]) => el("tr", {}, el("th", {}, k), el("td", {}, v)))),
    f.unexpected_fields.length ? msg("err", `В приказе есть поля, которые панель не показывает: ${f.unexpected_fields.join(", ")}. Не подписывайте.`) : null,
    problems.length ? msg("err", `Подписать нельзя: ${problems.join("; ")}.`) : null,
    local ? el("div", { class: "hint" }, "Подпись ставится ключом этого устройства, здесь, над показанными полями.") : null,
    el("h3", {}, `Подписи: ${view.signed_by.length} из ${view.required ?? "?"}`),
    view.signed_by.length ? el("ul", {}, view.signed_by.map((s) => el("li", {}, s))) : el("div", { class: "empty" }, "Пока никто не подписал."),
    view.signed_by_me ? msg("warn", "Вы уже подписали этот приказ. Нужна подпись другого человека.") : null,
    !view.can_sign ? msg("warn", "По политике ваша подпись не засчитывается в кворум. Подписать должны ЛПР.") : null,
    el("div", { class: "row" }, el("label", { class: "inline" }, check, "Я проверил все поля приказа")),
    el("div", { class: "row" }, signBtn, el("button", { type: "button", onclick: () => openProposal(id) }, "Обновить")),
    el("div", { class: "hint" }, "ID: ", el("code", {}, id)),
    out,
  );
  highlight();
}

// Every field the signature covers, from the payload itself. Mirrors
// describe_payload in app.py, which the demo login still uses.
function describeLocal(p) {
  const a = p.audience || {};
  return {
    drill: p.drill, scenario: p.scenario, severity: p.severity, action: p.action,
    audience: { sites: a.sites || [], groups: a.groups || [], persons: a.persons || [] },
    text: p.text || "", issued_at: p.issued_at, not_valid_after: p.not_valid_after,
    stream: `${p.stream_id}#${p.seq}`, requires_ack: Boolean(p.requires_ack),
    ack_deadline_s: p.ack_deadline_s, cancels: p.cancels, org_id: p.org_id, policy_id: p.policy_id,
    unexpected_fields: DeviceKey.unexpectedFields(p),
  };
}

// ---- order status ----------------------------------------------------------
async function openOrder(id) {
  current = { kind: "order", id };
  let status;
  try { status = await api(`/api/orders/${encodeURIComponent(id)}`); }
  catch (error) { $("detail").replaceChildren(msg("err", error.message)); return; }
  renderOrder(status);
  highlight();
}

function renderOrder(s) {
  now = s.now;
  const total = s.people.length;
  const ackText = (p) => p.ack_status ? (ACK[p.ack_status] || p.ack_status) : "нет ответа";
  const ackTag = (p) => p.ack_valid === false ? el("span", { class: "tag real" }, "ПОДДЕЛЬНАЯ РАСПИСКА")
    : p.ack_status && p.ack_status !== "received" ? el("span", { class: "tag ok" }, ackText(p))
    : p.ack_status ? el("span", { class: "tag warn" }, ackText(p))
    : el("span", { class: "tag real" }, ackText(p));
  const cancelText = el("input", { type: "text", placeholder: "Причина отбоя, например: ложное срабатывание" });
  const out = el("div");
  const cancelBtn = el("button", { class: "danger", type: "button", onclick: async () => {
    if (!confirm("Создать приказ об отбое? Его тоже нужно будет подписать.")) return;
    try {
      const created = await api(`/api/orders/${encodeURIComponent(s.order_id)}/cancel`, { method: "POST", body: { text: cancelText.value.trim() } });
      await refreshLists();
      openProposal(created.order_id);
    } catch (error) { out.replaceChildren(msg("err", error.message)); }
  }}, "Отбой");

  fill($("detail"),
    el("div", { class: "banner " + (s.drill ? "drill" : "real") }, `${s.drill ? "УЧЕНИЕ" : "БОЕВОЕ"} · ${s.scenario} · разослан ${time(s.dispatched_at)}`),
    el("div", { class: "big" }, `Подтвердили: ${s.acknowledged} из ${total}`),
    el("div", { class: "hint" }, "«Получено устройством» — приложение приняло и проверило приказ. Подтверждение — когда человек нажал «принял»."),
    s.reached_nobody ? msg("err", "Приказ не дошёл ни до кого: в аудитории нет активных контактов.") : null,
    s.outstanding.length ? msg("warn", `Нет подтверждения от человека: ${s.people.filter((p) => s.outstanding.includes(p.person_id)).map((p) => p.name || p.person_id).join(", ")} — пока не подтвердят, идёт эскалация по каналам.`) : (total ? msg("ok", "Все подтвердили.") : null),
    s.stub_attempts ? msg("warn", `Попыток через каналы-заглушки: ${s.stub_attempts}. Они ничего не отправляют — до этих людей дошло только приложение.`) : null,
    el("table", {},
      el("tr", {}, el("th", {}, "Кто"), el("th", {}, "Ответ"), el("th", {}, "Каналы")),
      s.people.map((p) => el("tr", {},
        el("td", {}, p.name ? `${p.name} ` : "", el("code", {}, p.person_id)),
        el("td", {}, ackTag(p), p.ack_at ? el("div", { class: "hint" }, time(p.ack_at)) : null),
        el("td", {}, el("code", {}, p.channels_attempted.join(", ")))))),
    // The event and its stand-down are linked both ways.
    s.cancels ? el("div", { class: "row" }, "Это отбой события ",
      el("button", { type: "button", onclick: () => openOrder(s.cancels) }, "открыть событие")) : null,
    s.cancelled_by ? msg("ok", "Событие отменено отбоем.") : null,
    s.cancelled_by ? el("div", { class: "row" },
      el("button", { type: "button", onclick: () => openOrder(s.cancelled_by) }, "открыть отбой")) : null,
    !s.cancels && !s.cancelled_by ? el("h3", {}, s.until_cancelled ? "Действует до отбоя" : `Действует до ${time(s.not_valid_after)}`) : null,
    !s.cancels && !s.cancelled_by ? el("div", { class: "row" }, cancelText, cancelBtn) : null,
    el("div", { class: "hint" }, "ID: ", el("code", {}, s.order_id)),
    out,
  );
}

function highlight() {
  for (const node of document.querySelectorAll(".item")) node.classList.remove("active");
  refreshLists().catch(() => {});
}

// ---- polling ---------------------------------------------------------------
// The lists and an open status view refresh every 3 s. A review screen does not:
// it must not change under the person reading it. If the proposal changes on the
// server, signing is refused and they review again.
setInterval(async () => {
  if ($("app").classList.contains("hidden")) return;
  try {
    await refreshLists(true);
    if (current && current.kind === "order") renderOrder(await api(`/api/orders/${encodeURIComponent(current.id)}`, { poll: true }));
  } catch (_) { /* shown on the next action */ }
}, 3000);

// ---- directory, custodians' requests, revocation key --------------------------------
// The panel never holds the root key. Changes to who may sign are collected here into
// a request file for the custodians' offline laptop; their signed answer is uploaded
// back and published. Only revocation is immediate: the duty shift's revocation key,
// kept in this browser, signs the next revocation list.
const ROLE = { executor: "исполнитель", duty_officer: "дежурный", deputy: "заместитель",
               director: "директор", auditor: "аудитор" };
let dir = null;
let codebookDirty = false;
let pending = [];
try { pending = JSON.parse(sessionStorage.getItem("alerting.pending") || "[]"); } catch (_) { pending = []; }
function savePending() {
  try { sessionStorage.setItem("alerting.pending", JSON.stringify(pending)); } catch (_) { /* private mode */ }
  renderPending();
}

function showTab(name) {
  $("alerts-view").classList.toggle("hidden", name !== "alerts");
  $("directory-view").classList.toggle("hidden", name !== "directory");
  $("tab-alerts").classList.toggle("active", name === "alerts");
  $("tab-directory").classList.toggle("active", name === "directory");
  if (name === "directory") loadDirectory();
}
$("tab-alerts").addEventListener("click", () => showTab("alerts"));
$("tab-directory").addEventListener("click", () => showTab("directory"));

function download(name, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const link = el("a", { href: URL.createObjectURL(blob), download: name });
  document.body.append(link);
  link.click();
  link.remove();
}
const stamp = () => new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");

async function loadDirectory() {
  try { dir = await api("/api/directory"); }
  catch (error) { $("dir-msg").replaceChildren(msg("err", error.message)); return; }
  renderDirectory();
}

function keyName(keyId) {
  const p = dir && dir.people.find((x) => x.key_id === keyId);
  return p ? `${p.person_id} ${p.name}` : keyId;
}

function describeChange(c) {
  switch (c.op) {
    case "add_key": return `Добавить ${c.person_id} «${c.name}», ${ROLE[c.role] || c.role}`;
    case "retire": return `Вывести ключ ${keyName(c.key_id)} (прежние подписи в силе)`;
    case "revoke": return `Отозвать ключ ${keyName(c.key_id)}: ${c.reason}`;
    case "add_revoker": return `Внести ключ отзыва «${c.label}»`;
    case "remove_revoker": return `Убрать ключ отзыва ${c.key_id} — ${c.fate === "absorb" ? "отзывы перенести" : "отзывы отбросить (украден)"}`;
    case "absorb_revocations": return "Перенести быстрые отзывы в справочник";
    case "policy": return `Новая кодовая книга, срок ${c.renew_days} дн.`;
    default: return c.op;
  }
}

function queue(change, note) {
  pending.push(change);
  savePending();
  $("dir-msg").replaceChildren(msg("ok", `В заявку: ${describeChange(change)}.${note ? " " + note : ""}`));
}

function renderDirectory() {
  $("dir-versions").textContent = `справочник v${dir.directory_version} · политика v${dir.policy_version} · быстрые отзывы v${dir.revocations_version}`;
  const state = (p) => p.state === "live" ? el("span", { class: "tag ok" }, "действует")
    : p.state === "retired" ? el("span", { class: "tag warn" }, "выведен")
    : el("span", { class: "tag real" }, `отозван${p.reason ? ": " + p.reason : ""}`);
  $("people").replaceChildren(
    el("tr", {}, el("th", {}, "Кто"), el("th", {}, "Роль"), el("th", {}, "Ключ"), el("th", {}, "Состояние"), el("th", {}, "")),
    ...dir.people.map((p) => el("tr", {},
      el("td", {}, `${p.name} `, el("code", {}, p.person_id)),
      el("td", {}, ROLE[p.role] || p.role),
      el("td", {}, el("code", {}, p.key_id)),
      el("td", {}, state(p)),
      el("td", {}, p.state !== "live" ? null : [
        el("button", { type: "button", class: "danger", onclick: () => fastRevoke(p) }, "Отозвать сейчас"), " ",
        el("button", { type: "button", onclick: () => queue({ op: "retire", key_id: p.key_id }) }, "В заявку: вывести"), " ",
        el("button", { type: "button", onclick: () => {
          const reason = prompt(`Причина отзыва ключа ${p.person_id} ${p.name}:`);
          if (reason) queue({ op: "revoke", key_id: p.key_id, reason });
        } }, "В заявку: отозвать"),
      ])))
  );
  if (!codebookDirty) $("codebook").value = dir.scenarios_yaml;
  $("policy-expiry").textContent = `Текущая политика действует до ${new Date(dir.policy_not_valid_after * 1000).toLocaleDateString("ru-RU")}. Продлить — та же кнопка «В заявку» без правок.`;
  renderRevoker();
  renderPending();
}

function renderRevoker() {
  const mine = DeviceKey.list("revoker").filter((k) => !k.org_id || k.org_id === dir.org_id);
  const named = new Map(dir.revokers.map((r) => [r.key_id, r]));
  const rows = [];
  for (const k of mine) {
    rows.push(el("div", { class: "item" },
      el("div", { class: "top" }, `«${k.person_id}» `, el("code", {}, k.key_id)),
      named.has(k.key_id) ? el("div", { class: "sub" }, "На этом устройстве, внесён в справочник — «Отозвать сейчас» работает.")
        : el("div", { class: "sub" }, "На этом устройстве, ещё не внесён в справочник. ",
          el("button", { type: "button", onclick: () => queue({ op: "add_revoker", public_key: k.public_key, label: k.person_id }) }, "В заявку: внести"))));
  }
  for (const r of dir.revokers) {
    if (mine.some((k) => k.key_id === r.key_id)) continue;
    rows.push(el("div", { class: "item" },
      el("div", { class: "top" }, `«${r.label}» `, el("code", {}, r.key_id)),
      el("div", { class: "sub" }, "В справочнике, но не на этом устройстве. ",
        el("button", { type: "button", onclick: () => queue({ op: "remove_revoker", key_id: r.key_id, fate: "absorb" }) }, "В заявку: убрать"), " ",
        el("button", { type: "button", onclick: () => queue({ op: "remove_revoker", key_id: r.key_id, fate: "discard" }, "Отзывы, сделанные им, перестанут действовать — повторите настоящие.") }, "Украден: убрать и отбросить отзывы"))));
  }
  if (!rows.length) rows.push(el("div", { class: "empty" }, "Ключа отзыва нет — отзыв идёт только через хранителей."));
  $("revoker-box").replaceChildren(...rows);
  $("revoker-form").classList.toggle("hidden", mine.length > 0);
}

async function fastRevoke(person) {
  const keys = DeviceKey.list("revoker").filter((k) => dir.revokers.some((r) => r.key_id === k.key_id));
  if (!keys.length) {
    $("dir-msg").replaceChildren(msg("err", "На этом устройстве нет ключа отзыва, внесённого в справочник. Отзовите через заявку хранителям или с устройства дежурной смены."));
    return;
  }
  const reason = el("input", { type: "text", placeholder: "Причина: например, утерян телефон" });
  const pass = el("input", { type: "password", autocomplete: "off", placeholder: "Пароль ключа отзыва" });
  const out = el("div");
  const go = el("button", { type: "button", class: "danger" }, "Отозвать");
  go.addEventListener("click", async () => {
    if (!reason.value.trim()) { out.replaceChildren(msg("err", "Укажите причину.")); return; }
    go.disabled = true;
    try {
      const record = keys[0];
      const key = await DeviceKey.unlock(record.key_id, pass.value);
      const prepared = await api("/api/revocations/prepare", { method: "POST", body: {
        signer: record.key_id, reason: reason.value.trim(), key_id: person.key_id } });
      const list = prepared.payload;
      // The baseline -- what was already revoked -- is taken only from a list this
      // browser can verify itself: one signed by its own revocation key. Anything the
      // panel merely claims was revoked before counts as new, and is shown.
      let baseline = [];
      const latest = prepared.latest;
      if (latest && latest.payload) {
        if (latest.payload.signer === record.key_id
            && await DeviceKey.verify(record.public_key, "revocations", latest.payload, latest.signature)) {
          baseline = latest.payload.entries.map((e) => e.key_id);
        }
        if (list.version !== latest.payload.version + 1) throw new Error("панель прислала неверную версию списка отзыва — не подписано");
      }
      const ids = new Set(list.entries.map((e) => e.key_id));
      if (list.type !== "revocations" || list.signer !== record.key_id || list.org_id !== dir.org_id
          || baseline.some((k) => !ids.has(k)) || !ids.has(person.key_id)) {
        throw new Error("панель прислала неверный список отзыва — не подписано");
      }
      const fresh = list.entries.filter((e) => !baseline.includes(e.key_id) && e.key_id !== person.key_id);
      if (fresh.length) {
        // Earlier revocations made with another device's key cannot be checked here.
        // The person sees every one of them and decides.
        const lines = fresh.map((e) => `• ${keyName(e.key_id)} (${e.key_id}) — ${e.reason || "без причины"}`);
        if (!confirm(`Вместе с ${person.person_id} список отзыва содержит ещё ${fresh.length} ключ(а), отозванных раньше другим ключом отзыва — проверить это на этом устройстве нельзя:\n\n${lines.join("\n")}\n\nЕсли кого-то из них вы не знаете как отозванного — нажмите «Отмена». Подписать весь список?`)) {
          throw new Error("отменено: список не подписан");
        }
      }
      const signature = await DeviceKey.sign(key, "revocations", list);
      const result = await api("/api/revocations/publish", { method: "POST", body: { payload: list, signature } });
      fill(out, msg("ok", `Отозван ${person.person_id} ${person.name}. Сервер отказывает этому ключу; открытые соединения закроются в течение 15 с.`),
        result.invalidated && result.invalidated.length ? msg("warn", `Действующие события, подписанные этим ключом, больше не проверяются: ${result.invalidated.join("; ")}. Переиздайте их.`) : null);
      await loadDirectory();
      $("dir-msg").replaceChildren(...out.childNodes);
    } catch (error) {
      out.replaceChildren(msg("err", error.message));
      go.disabled = false;
    }
  });
  $("dir-msg").replaceChildren(el("div", { class: "msg warn" },
    el("strong", {}, `Отозвать ключ ${person.person_id} ${person.name} (${person.key_id})? `),
    "Все его подписи перестанут действовать, включая прошлые.",
    el("div", { class: "row" }, reason, pass, go), out));
}

$("revoker-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const label = $("revoker-label").value.trim();
  if ($("revoker-pass").value.length < 10 || $("revoker-pass").value !== $("revoker-pass2").value) {
    $("dir-msg").replaceChildren(msg("err", "Пароль ключа отзыва — не короче 10 символов, оба раза одинаково."));
    return;
  }
  try {
    const record = await DeviceKey.create(label, $("revoker-pass").value, dir.org_id, "revoker");
    $("revoker-pass").value = ""; $("revoker-pass2").value = "";
    queue({ op: "add_revoker", public_key: record.public_key, label }, "Ключ отзыва создан на этом устройстве.");
    renderRevoker();
  } catch (error) {
    $("dir-msg").replaceChildren(msg("err", error.message));
  }
});

$("add-key").addEventListener("input", async () => {
  const text = $("add-key").value.trim();
  try {
    const raw = DeviceKey.fromB64u(text);
    $("add-kid").textContent = raw.length === 32 ? `Идентификатор ключа: ${await DeviceKey.keyId(raw)} — сверьте с экраном устройства.` : "Ключ должен быть 43 символа.";
  } catch (_) { $("add-kid").textContent = "Ключ не читается."; }
});

$("add-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const person = $("add-person").value.trim();
  const change = { op: "add_key", person_id: person, name: $("add-name").value.trim(),
                   role: $("add-role").value, public_key: $("add-key").value.trim() };
  const groups = $("add-groups").value.split(",").map((g) => g.trim()).filter(Boolean);
  try {
    if ($("add-phone").value.trim() || $("add-site").value.trim() || groups.length) {
      await api("/api/contacts", { method: "POST", body: { person_id: person, name: change.name,
        phone: $("add-phone").value.trim(), site: $("add-site").value.trim(), groups, role: change.role } });
    }
    queue(change, groups.length ? "Контакт сохранён на сервере." : "");
    for (const id of ["add-person", "add-name", "add-key", "add-phone", "add-site", "add-groups"]) $(id).value = "";
    $("add-kid").textContent = "";
  } catch (error) {
    $("dir-msg").replaceChildren(msg("err", error.message));
  }
});

$("codebook").addEventListener("input", () => { codebookDirty = true; });
$("codebook-add").addEventListener("click", () => {
  queue({ op: "policy", scenarios_yaml: $("codebook").value, renew_days: Number($("renew-days").value) || 365 });
});

function renderPending() {
  $("pending").replaceChildren(...(pending.length ? pending.map((c, i) => el("li", {},
    describeChange(c), " ", el("button", { type: "button", onclick: () => { pending.splice(i, 1); savePending(); } }, "убрать")))
    : [el("div", { class: "empty" }, "Изменений нет.")]));
  $("request-download").disabled = !pending.length;
}

$("request-clear").addEventListener("click", () => { pending = []; codebookDirty = false; savePending(); });

$("request-download").addEventListener("click", async () => {
  try {
    const request = await api("/api/custody/request", { method: "POST", body: { changes: pending } });
    download(`заявка-${request.org_id}-${stamp()}.json`, request);
    $("dir-msg").replaceChildren(msg("ok", "Файл заявки сохранён. Отнесите его хранителям; ответ загрузите ниже."));
    pending = []; codebookDirty = false; savePending();
  } catch (error) {
    $("dir-msg").replaceChildren(msg("err", error.message));
  }
});

$("answer-file").addEventListener("change", async () => {
  const out = $("answer-msg");
  try {
    const file = $("answer-file").files[0];
    if (!file) return;
    let answer;
    try { answer = JSON.parse(await file.text()); } catch (_) { throw new Error("файл не читается как JSON"); }
    const result = await api("/api/custody/answer", { method: "POST", body: { answer } });
    const invalidated = result.published.flatMap((r) => r.invalidated || []);
    fill(out,
      msg("ok", "Опубликовано: " + result.published.map((r) => `${r.kind} v${r.version}`).join(", ")),
      el("ul", {}, result.summary.map((line) => el("li", {}, line))),
      invalidated.length ? msg("warn", `Больше не проверяются: ${invalidated.join("; ")}`) : null);
    $("answer-file").value = "";
    await loadDirectory();
  } catch (error) {
    out.replaceChildren(msg("err", error.message));
  }
});

async function start() {
  me = await api("/api/me");
  if (me.device_key && !deviceKey) {
    // The session outlived the page (a reload): the key is no longer unlocked here.
    await api("/api/logout", { method: "POST" }).catch(() => {});
    showLogin("Страница перезагружена — ключ устройства закрыт. Войдите снова.");
    return;
  }
  meta = await api("/api/meta");
  $("who").textContent = `${me.name} · ${me.role} · ${me.person_id}` + (me.device_key ? " · ключ устройства" : " · демо-ключ на сервере");
  $("org").textContent = `организация ${meta.org_id}`;
  fillForm();
  $("login").classList.add("hidden");
  $("app").classList.remove("hidden");
  await refreshLists();
}

start().catch(() => showLogin());
