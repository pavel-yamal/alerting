// src/push.js against a fake Capacitor: what reaches the panel, and when.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "src", "push.js"), "utf8");

function fakePlugin({ permission = "prompt", grant = "granted", token = "apns-token", error = null } = {}) {
  const listeners = {};
  const plugin = {
    calls: [],
    permission,
    async checkPermissions() { return { receive: plugin.permission }; },
    async requestPermissions() { plugin.calls.push("request"); plugin.permission = grant; return { receive: grant }; },
    async createChannel(channel) { plugin.calls.push(`channel:${channel.id}:${channel.importance}`); },
    addListener(name, fn) {
      (listeners[name] ||= []).push(fn);
      return Promise.resolve({ remove() { listeners[name] = listeners[name].filter((f) => f !== fn); } });
    },
    async register() {
      plugin.calls.push("register");
      setTimeout(() => {
        if (error) for (const fn of listeners.registrationError || []) fn({ error });
        else for (const fn of listeners.registration || []) fn({ value: token });
      }, 0);
    },
    tap(data) { for (const fn of listeners.pushNotificationActionPerformed || []) fn({ notification: { data } }); },
    listening: (name) => (listeners[name] || []).length,
  };
  return plugin;
}

function load(plugin, { native = true, platform = "ios" } = {}) {
  const root = {
    setTimeout, clearTimeout, Promise,
    Capacitor: { isNativePlatform: () => native, getPlatform: () => platform, Plugins: { PushNotifications: plugin } },
  };
  vm.runInNewContext(source, { window: root, globalThis: root, setTimeout, clearTimeout, Promise });
  return root.AppPush;
}

let sent;
const register = async (device) => { sent.push({ ...device }); return { configured: true }; };
beforeEach(() => { sent = []; });

test("enable asks once, registers the token with its platform, and remembers it in memory", async () => {
  const plugin = fakePlugin();
  const push = load(plugin, { platform: "android" });
  assert.equal(push.enabled(), false);
  assert.deepEqual(await push.enable(register), { configured: true });
  assert.deepEqual(sent, [{ token: "apns-token", platform: "android" }]);
  assert.equal(push.enabled(), true);
  assert.deepEqual(plugin.calls, ["request", "channel:lpr:4", "register"]);
  assert.equal(plugin.listening("registration"), 0, "listeners are removed after the token arrives");
});

test("ios creates no channel; a refusal says where to allow it", async () => {
  const ios = fakePlugin();
  await load(ios).enable(register);
  assert.ok(!ios.calls.some((c) => c.startsWith("channel")));

  const refused = load(fakePlugin({ grant: "denied" }));
  await assert.rejects(refused.enable(register), /настройках телефона/);
  assert.deepEqual(sent, [{ token: "apns-token", platform: "ios" }]);
});

test("sync is silent: nothing without permission, never a prompt", async () => {
  const plugin = fakePlugin({ permission: "prompt" });
  const push = load(plugin);
  assert.equal(await push.sync(register), null);
  assert.deepEqual(sent, []);
  assert.ok(!plugin.calls.includes("request"));

  const granted = fakePlugin({ permission: "granted", token: "new-token" });
  const again = load(granted);
  assert.equal(await again.sync(register), "new-token");
  assert.deepEqual(sent, [{ token: "new-token", platform: "ios" }]);
  assert.ok(!granted.calls.includes("request"));
});

test("a registration error fails enable and leaves sync quiet", async () => {
  const push = load(fakePlugin({ permission: "granted", error: "no APNs" }));
  await assert.rejects(push.enable(register), /no APNs/);
  assert.equal(await push.sync(register), null);
  assert.equal(push.enabled(), false);
});

test("release unregisters this launch's token once", async () => {
  const push = load(fakePlugin());
  await push.enable(register);
  const gone = [];
  await push.release(async (token) => gone.push(token));
  await push.release(async (token) => gone.push(token));
  assert.deepEqual(gone, ["apns-token"]);
  assert.equal(push.enabled(), false);
});

test("a tap hands over the order and what to open; without an id nothing happens", () => {
  const plugin = fakePlugin();
  const push = load(plugin);
  const opened = [];
  push.onTap((target) => opened.push({ ...target }));
  plugin.tap({ order_id: "o-1", open: "order" });
  plugin.tap({ order_id: "o-2" });
  plugin.tap({ title: "no id" });
  assert.deepEqual(opened, [{ order_id: "o-1", open: "order" }, { order_id: "o-2", open: "proposal" }]);
});

test("in a browser there is no push at all", async () => {
  const push = load(fakePlugin(), { native: false });
  assert.equal(push.supported(), false);
  assert.equal(await push.sync(register), null);
  await assert.rejects(push.enable(register), /только в приложении/);
});

test("a logout during a registration still under way unregisters what it registered", async () => {
  const push = load(fakePlugin({ permission: "granted", token: "late-token" }));
  let answer;
  const slowRegister = (device) => new Promise((resolve) => { answer = () => { sent.push({ ...device }); resolve({}); }; });
  const syncing = push.sync(slowRegister);
  await new Promise((r) => setTimeout(r, 5)); // the token arrived; the panel has not answered
  const gone = [];
  const releasing = push.release(async (token) => gone.push(token));
  assert.deepEqual(gone, [], "it waits for the registration, rather than skip it");
  answer();
  await syncing;
  await releasing;
  assert.deepEqual(sent, [{ token: "late-token", platform: "ios" }]);
  assert.deepEqual(gone, ["late-token"]);
  assert.equal(push.enabled(), false);
});
