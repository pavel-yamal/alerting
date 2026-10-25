// What the app ships with, and what it must never ship with. docs/adr/0016.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const app = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (...parts) => readFileSync(join(app, ...parts), "utf8");
const config = JSON.parse(read("capacitor.config.json"));
const pkg = JSON.parse(read("package.json"));

test("the page comes from the bundle, never from a server", () => {
  // server.url would load the page from the network: whoever controls that server
  // would decide what the key is asked to sign -- the hole the app exists to close.
  assert.equal(config.server.url, undefined);
  assert.equal(config.webDir, "www");
});

test("no live update: changing the page means a new build through the store", () => {
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  for (const name of Object.keys(deps)) {
    assert.doesNotMatch(name, /updater|live-?update|appflow|codepush/i, name);
  }
  assert.equal((config.plugins || {}).CapacitorUpdater, undefined);
});

test("the WebView is not debuggable in a release", () => {
  assert.equal(config.android.webContentsDebuggingEnabled, false);
  assert.equal(config.ios.webContentsDebuggingEnabled, false);
  assert.equal(config.android.allowMixedContent, false);
});

test("the page allows only its own scripts", () => {
  const html = read("src", "index.html");
  const csp = html.match(/Content-Security-Policy"\s+content="([^"]+)"/)[1];
  assert.match(csp, /script-src 'self'(;|$)/);
  assert.doesNotMatch(csp, /unsafe-eval|unsafe-inline/);
  assert.doesNotMatch(html, /<script>(?!<\/script>)/, "no inline script");
  for (const src of html.matchAll(/<script src="([^"]+)"/g)) assert.doesNotMatch(src[1], /^https?:/);
});

test("the session token is never written anywhere", () => {
  const code = read("src", "app.js");
  assert.doesNotMatch(code, /localStorage\.setItem\([^)]*token/i);
  assert.doesNotMatch(code, /sessionStorage/);
  // The only thing remembered between launches is the panel's address.
  const writes = [...code.matchAll(/localStorage\.setItem\(([^,]+),/g)].map((m) => m[1].trim());
  assert.deepEqual(writes, ["PANEL_KEY"]);
});

test("the key reaches signing only through the vault, which asks for biometrics", () => {
  const code = read("src", "app.js");
  // Every DeviceKey.sign with a key goes through withKey(...): fetched for one
  // operation, behind the system prompt.
  const signs = [...code.matchAll(/DeviceKey\.sign\(key,/g)].length;
  const viaVault = [...code.matchAll(/withKey\(/g)].length - 1; // minus the definition
  assert.equal(signs, viaVault);
  assert.ok(signs >= 3, "login, renewal, order");
  assert.doesNotMatch(code, /DeviceKey\.(create|unlock)\(/, "no password-wrapped browser key in the app");
});
