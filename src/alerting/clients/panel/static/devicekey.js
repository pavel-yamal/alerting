// The person's device key, kept in this browser. docs/adr/0012.
//
// The private key is created here and never leaves: it is stored only wrapped
// (AES-GCM under a key derived from the person's password), and unwrapped at login
// into a non-extractable CryptoKey that lives in this page's memory until the tab
// closes. The panel process receives signatures, never the key.
//
// Everything signed here is built the way the Python core builds it -- domain bytes,
// then RFC 8785 canonical JSON -- so a signature made in the browser verifies on the
// server and on every executor's device. tests/unit/test_devicekey_js.py holds the
// two implementations to the same bytes.
"use strict";

(function (root) {
  const STORE = "alerting.devicekeys.v1";
  const PBKDF2_ITERATIONS = 600000;
  const MAX_SAFE = Number.MAX_SAFE_INTEGER;
  const DOMAIN = {
    order: "alerting.order.v1\u0000",
    delegation: "alerting.session-delegation.v1\u0000",
  };
  // Every field an order may carry. Anything else is a field the review screen did
  // not show, and the page refuses to sign it -- the same rule as the CLI.
  const KNOWN_ORDER_FIELDS = new Set([
    "v", "type", "order_id", "org_id", "stream_id", "seq", "nonce", "issued_at",
    "not_valid_after", "severity", "drill", "scenario", "action", "audience", "text",
    "requires_ack", "ack_deadline_s", "policy_id", "cancels",
  ]);
  const MAX_DELEGATION_S = 12 * 3600;

  // ---- canonical JSON (RFC 8785, narrowed like alerting.core.canonical) ----------
  function canonicalize(value, path = "$") {
    if (value === null || value === undefined) {
      throw new Error(`null at ${path}: absent means absent`);
    }
    if (typeof value === "boolean") return value ? "true" : "false";
    if (typeof value === "number") {
      if (!Number.isInteger(value)) throw new Error(`float at ${path}`);
      if (Math.abs(value) > MAX_SAFE) throw new Error(`unsafe integer at ${path}`);
      return String(value);
    }
    if (typeof value === "string") return JSON.stringify(value.normalize("NFC"));
    if (Array.isArray(value)) {
      return "[" + value.map((item, i) => canonicalize(item, `${path}[${i}]`)).join(",") + "]";
    }
    if (typeof value === "object") {
      const normalized = new Map();
      for (const [rawKey, item] of Object.entries(value)) {
        const key = rawKey.normalize("NFC");
        if (normalized.has(key)) throw new Error(`keys collide at ${path} after NFC`);
        normalized.set(key, item);
      }
      // Array.prototype.sort compares UTF-16 code units, which is exactly RFC 8785.
      const keys = [...normalized.keys()].sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(normalized.get(k), `${path}.${k}`)).join(",") + "}";
    }
    throw new Error(`unsupported ${typeof value} at ${path}`);
  }

  // ---- bytes ----------------------------------------------------------------------
  const utf8 = (text) => new TextEncoder().encode(text);
  function b64u(bytes) {
    let binary = "";
    for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function fromB64u(text) {
    const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  }
  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }
  const signingInput = (domain, payload) => concat(utf8(DOMAIN[domain]), utf8(canonicalize(payload)));

  async function keyId(rawPublic) {
    const digest = await crypto.subtle.digest("SHA-256", rawPublic);
    return "ed25519:" + b64u(digest).slice(0, 22);
  }

  async function digestHex(domain, payload) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", signingInput(domain, payload)));
    return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function sign(privateKey, domain, payload) {
    return b64u(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, signingInput(domain, payload)));
  }

  // ---- availability ---------------------------------------------------------------
  // WebCrypto exists only in a secure context: https://, or localhost.
  async function supported() {
    if (!root.isSecureContext || !root.crypto || !crypto.subtle) {
      return "Ключ устройства работает только по https:// (или на localhost). Откройте панель по защищённому адресу.";
    }
    try {
      await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    } catch (_) {
      return "Этот браузер не умеет подписи Ed25519. Обновите его: Safari 17+, Chrome, Firefox, Edge.";
    }
    return null;
  }

  // ---- storage --------------------------------------------------------------------
  function load() {
    try { return JSON.parse(root.localStorage.getItem(STORE) || "[]"); }
    catch (_) { return []; }
  }
  function save(records) {
    root.localStorage.setItem(STORE, JSON.stringify(records));
  }
  const list = () => load().map(({ person_id, key_id, org_id, public_key, created }) =>
    ({ person_id, key_id, org_id, public_key, created }));
  function forget(keyIdToDrop) {
    save(load().filter((r) => r.key_id !== keyIdToDrop));
  }

  async function wrappingKey(password, salt) {
    const material = await crypto.subtle.importKey("raw", utf8(password.normalize("NFC")), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
      material, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
  }

  // Create, wrap and store a key for this person in this browser. The private key is
  // extractable only for the moment it takes to wrap it.
  async function create(personId, password, orgId) {
    const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const rawPublic = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = await crypto.subtle.wrapKey("pkcs8", pair.privateKey, await wrappingKey(password, salt), { name: "AES-GCM", iv });
    const record = {
      person_id: personId, org_id: orgId, key_id: await keyId(rawPublic), public_key: b64u(rawPublic),
      salt: b64u(salt), iv: b64u(iv), wrapped: b64u(wrapped), iterations: PBKDF2_ITERATIONS,
      created: Math.floor(Date.now() / 1000),
    };
    save([...load().filter((r) => r.person_id !== personId), record]);
    // Ask the browser not to evict this site's storage. Safari honours it for a page
    // added to the home screen; elsewhere it is a hint.
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
    return record;
  }

  // Unwrap into a key that can sign and can never be exported again.
  async function unlock(keyIdToOpen, password) {
    const record = load().find((r) => r.key_id === keyIdToOpen);
    if (!record) throw new Error("ключа на этом устройстве нет");
    const unwrapping = await crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt: fromB64u(record.salt), iterations: record.iterations },
      await crypto.subtle.importKey("raw", utf8(password.normalize("NFC")), "PBKDF2", false, ["deriveKey"]),
      { name: "AES-GCM", length: 256 }, false, ["unwrapKey"]);
    try {
      return await crypto.subtle.unwrapKey("pkcs8", fromB64u(record.wrapped), unwrapping,
        { name: "AES-GCM", iv: fromB64u(record.iv) }, { name: "Ed25519" }, false, ["sign"]);
    } catch (_) {
      throw new Error("неверный пароль");
    }
  }

  // ---- what may be signed ---------------------------------------------------------
  // The page checks a delegation before signing it: for this key, this person, this
  // organisation, and no longer than the server will accept anyway.
  function checkDelegation(delegation, record, now) {
    const problems = [];
    if (delegation.type !== "session-delegation" || delegation.v !== 1) problems.push("не доверенность на сеанс");
    if (delegation.key_id !== record.key_id) problems.push("чужой ключ");
    if (delegation.person_id !== record.person_id) problems.push("чужой идентификатор");
    if (record.org_id && delegation.org_id !== record.org_id) problems.push("чужая организация");
    if (delegation.not_after - delegation.not_before > MAX_DELEGATION_S) problems.push("слишком долгий срок");
    if (Math.abs(delegation.not_before - now) > 300) problems.push("неверное время");
    if (problems.length) throw new Error("панель прислала неверную доверенность: " + problems.join(", "));
  }

  function unexpectedFields(payload) {
    return Object.keys(payload).filter((k) => !KNOWN_ORDER_FIELDS.has(k)).sort();
  }

  root.DeviceKey = {
    canonicalize, b64u, fromB64u, keyId, digestHex, sign, supported,
    list, forget, create, unlock, checkDelegation, unexpectedFields, signingInput,
  };
})(typeof window !== "undefined" ? window : globalThis);
