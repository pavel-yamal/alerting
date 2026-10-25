// Assembles www/ -- the page the app ships with. docs/adr/0016.
//
// No bundler and no dependencies: the page is four plain scripts. devicekey.js is
// taken from the panel as is, so the app and the panel page canonicalise, digest and
// sign with one implementation (tests/unit/test_devicekey_js.py holds it to the
// Python core).
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, "..");
const out = join(app, "www");
const devicekey = join(app, "..", "..", "src", "alerting", "clients", "panel", "static", "devicekey.js");

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
cpSync(join(app, "src"), out, { recursive: true });
cpSync(devicekey, join(out, "devicekey.js"));

// Nothing in the page may load code from the network: the guarantee of the app is
// that what asks the key to sign is what was reviewed and shipped.
for (const name of ["index.html", "app.js", "logic.js", "vault.js", "push.js", "devicekey.js"]) {
  const text = readFileSync(join(out, name), "utf8");
  if (/<script[^>]+src=["']https?:/i.test(text) || /\bimport\(\s*["']https?:/.test(text) || /\beval\(/.test(text)) {
    throw new Error(`${name}: code from the network or eval in the shipped page`);
  }
}
writeFileSync(join(out, "build.json"), JSON.stringify({ built: new Date().toISOString() }) + "\n");
console.log(`www/ ready (${out})`);
