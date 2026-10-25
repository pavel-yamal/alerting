// The device key's home on the phone: the native DeviceVault plugin
// (plugins/device-vault). docs/adr/0016.
//
// The private key is kept by the operating system behind biometrics -- on iOS a
// Keychain item with .biometryCurrentSet, on Android an AES key in the Keystore that
// needs a strong biometric for every use. The OS releases it only after Face ID or a
// fingerprint, for one operation; this page imports it into a non-extractable
// CryptoKey, signs, and lets it go. Nothing here keeps it between operations.
//
// There is no fallback for a desktop browser on purpose: a vault that does not ask
// for biometrics would be one that signs without the person.
"use strict";

(function (root) {
  function plugin() {
    const cap = root.Capacitor;
    if (!cap || !cap.isNativePlatform || !cap.isNativePlatform()) return null;
    if (cap.Plugins && cap.Plugins.DeviceVault) return cap.Plugins.DeviceVault;
    return cap.registerPlugin ? cap.registerPlugin("DeviceVault") : null;
  }

  // The plugin rejects with { code, message }; keep the code for vaultMessage.
  async function call(method, args) {
    const p = plugin();
    if (!p) {
      const error = new Error("Приложение запущено не на телефоне: хранилища ключа нет.");
      error.code = "unavailable";
      throw error;
    }
    try {
      return await p[method](args || {});
    } catch (raw) {
      const error = new Error(raw && raw.message ? raw.message : String(raw));
      error.code = raw && (raw.code || (raw.data && raw.data.code));
      throw error;
    }
  }

  async function status() {
    if (!plugin()) return { available: false, biometry: "none", reason: "not_native" };
    return call("status");
  }

  // Public facts about each key on this phone: person, organisation, key id, public
  // key. Kept by the plugin beside the secret, unprotected -- nothing in it signs.
  async function list() {
    const { items } = await call("list");
    return (items || []).map((item) => {
      try { return JSON.parse(item.meta); } catch (_) { return null; }
    }).filter(Boolean);
  }

  async function store(record, pkcs8, reason) {
    const meta = JSON.stringify({
      person_id: record.person_id, org_id: record.org_id, key_id: record.key_id,
      public_key: record.public_key, panel: record.panel, created: record.created,
    });
    await call("store", { alias: record.key_id, secret: pkcs8, meta, reason });
  }

  // Asks for biometrics. Returns PKCS#8 for one operation; the caller drops it.
  async function load(keyId, reason) {
    const { secret } = await call("load", { alias: keyId, reason });
    return secret;
  }

  async function remove(keyId) {
    await call("remove", { alias: keyId });
  }

  root.Vault = { status, list, store, load, remove };
})(typeof window !== "undefined" ? window : globalThis);
