// Pure rules of the decision-makers' app: no DOM, no network, no vault. app.js
// draws what these decide; test/logic.test.mjs holds them. docs/adr/0016.
"use strict";

(function (root) {
  const SEVERITY = { info: "информация", warning: "предупреждение", critical: "критическая", catastrophic: "катастрофическая" };
  const SEVERITY_ORDER = ["info", "warning", "critical", "catastrophic"];
  const ACTION = { START: "начать", STOP: "прекратить (отбой)", HOLD: "приостановить" };
  const ACK = { received: "получено устройством", acknowledged: "подтвердил", en_route: "выдвинулся",
                completed: "выполнил", cannot_comply: "не может выполнить" };

  // Same rule as the panel (PERSON_ID in panel/app.py): the id names a key home.
  const PERSON_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;

  // The delegation lasts 12 h (MAX_DELEGATION_S); the app renews it with the
  // biometric key once fewer than this many seconds are left -- the same margin as
  // the panel page (RENEW_WHEN_LEFT_S in panel.js).
  const RENEW_WHEN_LEFT_S = 6 * 3600;

  // The panel's address. https only: the WebView refuses mixed content, and a
  // signing session over plain http is exactly what the app is here to avoid.
  // localhost is let through for a developer's own machine.
  function normalizePanelUrl(text) {
    let value = String(text || "").trim();
    if (!value) throw new Error("Укажите адрес панели.");
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = "https://" + value;
    let url;
    try { url = new URL(value); } catch (_) { throw new Error("Это не адрес: " + text); }
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
      throw new Error("Только https:// — подписывать по открытому каналу нельзя.");
    }
    if (url.username || url.password) throw new Error("Логин и пароль в адресе не нужны.");
    url.hash = ""; url.search = "";
    return url.origin + url.pathname.replace(/\/+$/, "");
  }

  // What every request carries. The app's session token goes in Authorization: the
  // page lives at capacitor://localhost, and the panel's cookie never gets here.
  function requestHeaders(method, token) {
    const headers = { "X-Alerting-Panel": "1", "X-Alerting-Client": "app" };
    if (method !== "GET") headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = `Bearer ${token}`;
    return headers;
  }

  function needsRenewal(me, now) {
    return Boolean(me && me.delegation_until) && me.delegation_until - now <= RENEW_WHEN_LEFT_S;
  }

  // The usual audience is everyone; anything else is said out loud, field by field.
  function audienceSummary(audience, drill) {
    const a = audience || {};
    const groups = a.groups || [], sites = a.sites || [], persons = a.persons || [];
    const everyone = groups.length === 1 && groups[0] === "all" && !sites.length && !persons.length;
    if (everyone) return { everyone: true, text: drill ? "все" : "все и публичная RSS-лента" };
    const parts = [
      groups.length ? `группы: ${groups.join(", ")}` : null,
      sites.length ? `площадки: ${sites.join(", ")}` : null,
      persons.length ? `лично: ${persons.join(", ")}` : null,
    ].filter(Boolean);
    return { everyone: false, text: parts.join("; ") || "ПУСТО — приказ не дойдёт ни до кого" };
  }

  // The severities a scenario allows, as the panel's form offers them.
  function allowedSeverities(scenario, severities) {
    const lo = scenario && scenario.min_severity ? SEVERITY_ORDER.indexOf(scenario.min_severity) : 0;
    const hi = scenario && scenario.max_severity ? SEVERITY_ORDER.indexOf(scenario.max_severity) : SEVERITY_ORDER.length - 1;
    return SEVERITY_ORDER.filter((level, i) => i >= lo && i <= hi && severities && severities[level]);
  }

  // The vault's refusals in words the person can act on. The codes come from the
  // native plugin (plugins/device-vault).
  // Shown at launch when the WebView cannot sign with Ed25519 (docs/16, docs/15).
const UNSUPPORTED_PHONE =
  "Этот телефон не умеет подписи Ed25519. Нужен iOS 17 и новее либо Android 11 и новее " +
  "со свежим Android System WebView — обновите его в Google Play и откройте приложение снова.";

const VAULT_ERRORS = {
    cancelled: "Подтверждение отменено — ничего не подписано.",
    failed: "Биометрия не подтверждена.",
    locked: "Биометрия заблокирована после неудачных попыток. Разблокируйте телефон код-паролем и попробуйте снова.",
    invalidated: "Набор отпечатков или лиц на телефоне изменился, и ключ стал недоступен — так и задумано. Удалите ключ, создайте новый и зарегистрируйте его заново у регистрирующего.",
    not_found: "Ключа на этом телефоне нет.",
    not_enrolled: "На телефоне не настроены Face ID или отпечаток. Настройте их — без биометрии приложение не подписывает.",
    unavailable: "Биометрия на этом устройстве недоступна.",
  };
  function vaultMessage(error) {
    const code = error && (error.code || error.errorCode);
    return VAULT_ERRORS[code] || (error && error.message) || String(error);
  }
  const isCancel = (error) => Boolean(error) && (error.code === "cancelled" || error.errorCode === "cancelled");

  // Why a signed proposal is not sent yet: the quorum's codes (core/errors.py:
  // Reason) in words. An unknown code is shown as it is rather than hidden.
  const BLOCKING = {
    quorum_not_met: "нужна подпись ещё одного ЛПР",
    not_distinct_persons: "подписи должны быть от разных людей",
    role_requirement_unmet: "не хватает подписи с нужной ролью",
    unauthorized_signer_role: "подпись человека без права издавать приказы",
    duplicate_signer: "этот ключ уже подписал",
    signature_spread_exceeded: "подписи собраны слишком далеко друг от друга по времени — нужна новая",
  };
  const blockingText = (code) => BLOCKING[code] || code;

  // Proposals still waiting for signatures; the panel lists the rest too.
  const openProposals = (proposals) => (proposals || []).filter((p) => p.status === "open");

  function time(ts) {
    return ts ? new Date(ts * 1000).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }) : "—";
  }
  function left(until, now) {
    const s = until - now;
    if (s <= 0) return "истёк";
    return s >= 60 ? `ещё ${Math.floor(s / 60)} мин` : `ещё ${s} с`;
  }

  const api = {
    SEVERITY, SEVERITY_ORDER, ACTION, ACK, PERSON_ID, RENEW_WHEN_LEFT_S, VAULT_ERRORS, UNSUPPORTED_PHONE,
    normalizePanelUrl, requestHeaders, needsRenewal, audienceSummary, allowedSeverities,
    vaultMessage, isCancel, openProposals, blockingText, time, left,
  };
  root.ApproverLogic = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
