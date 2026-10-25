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

test("the app id is frozen: me.yamal.alert, the publisher's shared yamal.me identifier", () => {
  // Changing it after the store release makes a different app: no update over the
  // installed one, and APNs topics of the old installs stop matching.
  assert.equal(config.appId, "me.yamal.alert");
});

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

// ---- the iOS project, as App Store review sees it (docs/15-ios-review.md) ----

const plist = read("ios", "App", "App", "Info.plist");
const pbxproj = read("ios", "App", "App.xcodeproj", "project.pbxproj");
const plistValue = (key) => {
  const m = plist.match(new RegExp(`<key>${key}</key>\\s*<(string>([^<]*)</string|true|false)/?>`));
  return m ? (m[2] ?? m[1]) : undefined;
};

test("ios: Face ID has its purpose string, or iOS refuses biometrics to the app", () => {
  assert.ok((plistValue("NSFaceIDUsageDescription") || "").length > 10);
});

test("ios: export compliance is answered in the build (signatures only, exempt)", () => {
  assert.equal(plistValue("ITSAppUsesNonExemptEncryption"), "false");
});

test("ios: the privacy manifest is there and is bundled as a resource", () => {
  const manifest = read("ios", "App", "App", "PrivacyInfo.xcprivacy");
  assert.match(manifest, /<key>NSPrivacyTracking<\/key>\s*<false\/>/);
  assert.match(manifest, /NSPrivacyAccessedAPICategoryUserDefaults/, "the vault uses UserDefaults");
  assert.match(pbxproj, /PrivacyInfo\.xcprivacy in Resources/);
});

test("ios: bundle id matches the app id; iPhone and iPad; iOS 17 for Ed25519 in WebCrypto", () => {
  assert.match(pbxproj, /PRODUCT_BUNDLE_IDENTIFIER = me\.yamal\.alert;/);
  assert.doesNotMatch(pbxproj, /PRODUCT_BUNDLE_IDENTIFIER = (?!me\.yamal\.alert;)/);
  assert.match(pbxproj, /TARGETED_DEVICE_FAMILY = "1,2";/);
  const targets = [...pbxproj.matchAll(/IPHONEOS_DEPLOYMENT_TARGET = ([\d.]+);/g)].map((m) => m[1]);
  assert.ok(targets.length > 0 && targets.every((t) => t === "17.0"), targets.join(","));
});

test("ios: the store icon is 1024x1024 without an alpha channel", () => {
  const png = readFileSync(join(app, "ios", "App", "App", "Assets.xcassets", "AppIcon.appiconset", "AppIcon-512@2x.png"));
  assert.equal(png.readUInt32BE(16), 1024);
  assert.equal(png.readUInt32BE(20), 1024);
  assert.equal(png[25], 2, "PNG colour type 2 = RGB, no alpha (Apple rejects transparency)");
});
