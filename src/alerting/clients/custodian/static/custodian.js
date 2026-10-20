"use strict";

// Everything that came from a file goes in through textContent: a request is data
// someone else wrote, and nothing in it is ever parsed as HTML.
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
const msg = (kind, text) => el("div", { class: "msg " + kind }, text);
// replaceChildren() turns null into the text "null"; optional blocks are dropped here.
const fill = (node, ...kids) => node.replaceChildren(...kids.flat().filter((k) => k != null && k !== false));
const date = (ts) => ts ? new Date(ts * 1000).toLocaleString("ru-RU") : "—";

async function api(path, body) {
  const init = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Alerting-Custodian": "1" },
    body: JSON.stringify(body),
  };
  const response = await fetch(path, init);
  let data = null;
  try { data = await response.json(); } catch (_) { /* empty */ }
  if (!response.ok) {
    const detail = data && data.detail;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail || response.status));
  }
  return data;
}

async function readJson(input) {
  const file = input.files[0];
  if (!file) return null;
  try { return JSON.parse(await file.text()); }
  catch (_) { throw new Error("файл не читается как JSON"); }
}

function download(name, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const link = el("a", { href: URL.createObjectURL(blob), download: name });
  document.body.append(link);
  link.click();
  link.remove();
}

// ---- status ----------------------------------------------------------------------
let status = null;

async function refresh() {
  status = await api("/api/status");
  const v = status.vault;
  $("setup").classList.toggle("hidden", Boolean(v));
  $("vault").classList.toggle("hidden", !v);
  $("request").classList.toggle("hidden", !v);
  $("who").textContent = v ? `организация ${v.org_id} · ${v.custodians.join(" и ")}` : status.path;
  if (v) {
    $("card").replaceChildren(
      el("div", { class: "hint" }, "Карточка корневого ключа организации"),
      el("h2", {}, v.org_id),
      el("div", { class: "hint" }, "Отпечаток (идентификатор ключа)"),
      el("div", { class: "fp" }, v.fingerprint),
      el("div", { class: "hint" }, "Открытый ключ — ALERTING_ROOT_PUBKEY"),
      el("div", { class: "mono" }, v.public_key),
      el("div", { class: "hint" }, `Хранители: ${v.custodians.join(", ")} · создан ${date(v.created_at)}`),
    );
  }
}

$("print-card").addEventListener("click", () => window.print());

// ---- creating the vault ----------------------------------------------------------
$("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const out = $("setup-msg");
  if ($("p1").value !== $("p1b").value || $("p2").value !== $("p2b").value) {
    out.replaceChildren(msg("err", "Пароли одного из хранителей не совпадают.")); return;
  }
  try {
    await api("/api/vault/create", {
      org_id: $("org").value.trim(),
      names: [$("n1").value.trim(), $("n2").value.trim()],
      passphrases: [$("p1").value, $("p2").value],
    });
    for (const id of ["p1", "p1b", "p2", "p2b"]) $(id).value = "";
    await refresh();
    $("global-msg").replaceChildren(msg("ok",
      "Корневой ключ создан. Напечатайте карточку и скачайте резервную копию на второй носитель."));
  } catch (error) {
    out.replaceChildren(msg("err", error.message));
  }
});

$("restore-file").addEventListener("change", async () => {
  try {
    const vault = await readJson($("restore-file"));
    if (!vault) return;
    await api("/api/vault/restore", { vault });
    await refresh();
    $("global-msg").replaceChildren(msg("ok", "Корневой ключ восстановлен из резервной копии."));
  } catch (error) {
    $("setup-msg").replaceChildren(msg("err", error.message));
  }
});

// ---- a request -------------------------------------------------------------------
$("request-file").addEventListener("change", async () => {
  const out = $("review");
  out.replaceChildren();
  let request;
  try {
    request = await readJson($("request-file"));
    if (!request) return;
    renderReview(request, await api("/api/review", { request }));
  } catch (error) {
    out.replaceChildren(msg("err", error.message));
  }
});

function renderReview(request, r) {
  const p1 = el("input", { type: "password", autocomplete: "off" });
  const p2 = el("input", { type: "password", autocomplete: "off" });
  const checked = el("input", { type: "checkbox" });
  const migrate = el("input", { type: "checkbox" });
  const signBtn = el("button", { class: r.migrating ? "danger" : "primary", type: "button", disabled: "" }, "Подписать");
  const out = el("div");
  const ready = () => { signBtn.disabled = !checked.checked || (r.migrating && !migrate.checked); };
  checked.addEventListener("change", ready);
  migrate.addEventListener("change", ready);

  signBtn.addEventListener("click", async () => {
    signBtn.disabled = true;
    out.replaceChildren(msg("warn", "Открываю ключ и подписываю…"));
    try {
      const answer = await api("/api/sign", {
        request, passphrases: [p1.value, p2.value], confirm_migration: migrate.checked,
      });
      p1.value = ""; p2.value = "";
      const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "");
      download(`ответ-${answer.org_id}-${stamp}.json`, answer);
      fill(out,
        msg("ok", "Подписано. Файл ответа сохранён — перенесите его дежурному на том же носителе."),
        el("ul", {}, answer.summary.map((line) => el("li", {}, line))),
        answer.migration ? msg("warn", "Это перенос на новый корневой ключ: на сервере его применяют командой ./docker/rotate-root.sh <файл ответа>, сверив отпечаток с карточкой.") : null,
      );
    } catch (error) {
      out.replaceChildren(msg("err", error.message));
      ready();
    }
  });

  fill($("review"),
    r.migrating ? el("div", { class: "banner" },
      "ПЕРЕНОС ОРГАНИЗАЦИИ НА ЭТОТ КОРНЕВОЙ КЛЮЧ. Справочник подписан другим ключом с отпечатком ",
      el("span", { class: "mono" }, r.previous_fingerprint),
      ". Подписывайте, только если перенос решён и прежний отпечаток — ваш прежний ключ.") : null,
    el("h3", {}, `Заявка от ${r.created_by || "?"}, ${date(r.created_at)} · справочник v${r.directory_version}, политика v${r.policy_version}`),
    el("h2", {}, "Что будет подписано"),
    el("ol", { class: "changes" }, r.changes.map((c) => el("li", {}, c))),
    el("div", { class: "hint" }, "Идентификатор каждого добавляемого ключа сверьте с тем, что показало устройство человека."),
    el("details", {},
      el("summary", {}, `Справочник сейчас: ${r.people.length} ключей`),
      el("table", {},
        el("tr", {}, el("th", {}, "Кто"), el("th", {}, "Роль"), el("th", {}, "Ключ"), el("th", {}, "")),
        r.people.map((p) => el("tr", {}, el("td", {}, `${p.person_id} ${p.name}`), el("td", {}, p.role),
          el("td", { class: "mono" }, p.key_id), el("td", {}, p.state))))),
    el("div", { class: "two" },
      el("div", {}, el("label", {}, "Пароль хранителя 1"), p1),
      el("div", {}, el("label", {}, "Пароль хранителя 2"), p2)),
    el("div", { class: "row" }, el("label", { class: "inline" }, checked, "Мы вдвоём проверили каждое изменение")),
    r.migrating ? el("div", { class: "row" }, el("label", { class: "inline" }, migrate, "Подтверждаем перенос организации на этот ключ")) : null,
    el("div", { class: "row" }, signBtn),
    out,
  );
}

refresh().catch((error) => $("global-msg").replaceChildren(msg("err", error.message)));
