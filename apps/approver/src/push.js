// Push to this phone: "a proposal waits for your signature", "the order went out".
//
// The token goes to the panel, which registers it on the server for the person
// signed in (alerting/server/api/push.py). It is a secret -- whoever holds it writes
// into this phone's notification shade -- so it lives in memory only, never in
// storage: the system hands it out again on every launch.
//
// iOS registers straight with APNs, Android with FCM: the same split as the
// organisation's helpdesk app, and for the same reasons (docs/14-approver-app.md).
//
// requestPermissions() only from a tap: outside a gesture iOS silently refuses.
(function (root) {
  "use strict";

  // Same id as ANDROID_CHANNEL_ID on the server and the manifest's default channel.
  const CHANNEL_ID = "lpr";
  const TOKEN_TIMEOUT_MS = 20000;

  function plugin() {
    const cap = root.Capacitor;
    if (!cap || !cap.isNativePlatform || !cap.isNativePlatform()) return null;
    if (cap.Plugins && cap.Plugins.PushNotifications) return cap.Plugins.PushNotifications;
    return cap.registerPlugin ? cap.registerPlugin("PushNotifications") : null;
  }

  const platform = () => root.Capacitor.getPlatform();

  // Android 8+: without a channel of its own FCM uses Firebase's fallback channel,
  // importance DEFAULT -- the notification lands in the shade without popping up,
  // which reads as "no notifications". HIGH (4) pops up with sound. Android
  // remembers a channel's importance at creation: changing it means a new id.
  async function ensureChannel(p) {
    if (platform() !== "android") return;
    try {
      await p.createChannel({
        id: CHANNEL_ID,
        name: "Подписи и приказы",
        description: "Предложения, ждущие вашей подписи, и вышедшие приказы",
        importance: 4,
        visibility: 1,
        vibration: true,
      });
    } catch (_) { /* an old Android: the fallback channel still delivers */ }
  }

  // register() returns nothing: the token arrives as an event, or an error does.
  // Without a timeout a silent system would read as a spinner forever.
  function awaitToken(p) {
    return new Promise((resolve, reject) => {
      let done = false;
      const handles = [];
      const finish = (fn, value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        for (const h of handles) Promise.resolve(h).then((x) => x.remove()).catch(() => {});
        fn(value);
      };
      const timer = setTimeout(() => finish(reject, new Error("Телефон не выдал адрес для уведомлений — попробуйте ещё раз")), TOKEN_TIMEOUT_MS);
      handles.push(p.addListener("registration", (t) => finish(resolve, (t && t.value) || "")));
      handles.push(p.addListener("registrationError", (e) => finish(reject, new Error((e && e.error) || "Не удалось включить уведомления"))));
      p.register().catch((e) => finish(reject, e));
    });
  }

  let current = null; // the token registered in this launch
  let pending = null; // a registration under way

  // A registration still running when the person logs out would land after the
  // release and leave this phone on the logged-out person's notifications. So
  // release waits for it, and only then forgets the token it produced.
  function registering(work) {
    const run = work();
    pending = run;
    const clear = () => { if (pending === run) pending = null; };
    run.then(clear, clear);
    return run;
  }

  const api = {
    supported: () => Boolean(plugin()),

    // "granted" | "denied" | "prompt" | null
    async permission() {
      const p = plugin();
      if (!p) return null;
      try { return (await p.checkPermissions()).receive || null; } catch (_) { return null; }
    },

    enabled: () => Boolean(current),

    // From a tap only. `register({token, platform})` sends it to the panel.
    async enable(register) {
      const p = plugin();
      if (!p) throw new Error("Уведомления работают только в приложении");
      const { receive } = await p.requestPermissions();
      if (receive !== "granted") throw new Error("Уведомления запрещены. Разрешить их можно в настройках телефона.");
      return registering(async () => {
        await ensureChannel(p);
        const token = await awaitToken(p);
        if (!token) throw new Error("Телефон выдал пустой адрес для уведомлений");
        const answer = await register({ token, platform: platform() });
        current = token;
        return answer;
      });
    },

    // On every launch, silently: tokens change by themselves (reinstall, restore,
    // OS update), and a registration must follow whoever is signed in now.
    async sync(register) {
      const p = plugin();
      if (!p) return null;
      try {
        if ((await api.permission()) !== "granted") return null;
        return await registering(async () => {
          await ensureChannel(p);
          const token = await awaitToken(p);
          if (!token) return null;
          await register({ token, platform: platform() });
          current = token;
          return token;
        });
      } catch (_) {
        return null;
      }
    },

    // On logout, and from the account menu: the server forgets this phone, so the
    // next person signed in here does not get the previous one's notifications.
    async release(unregister) {
      if (pending) await pending.catch(() => {});
      const token = current;
      current = null;
      if (token) await unregister(token);
    },

    // A tap on a notification: `handler({order_id, open})`.
    onTap(handler) {
      const p = plugin();
      if (!p) return;
      p.addListener("pushNotificationActionPerformed", (action) => {
        const data = (action && action.notification && action.notification.data) || {};
        if (data.order_id) handler({ order_id: String(data.order_id), open: String(data.open || "proposal") });
      });
    },
  };

  root.AppPush = api;
})(typeof window !== "undefined" ? window : globalThis);
