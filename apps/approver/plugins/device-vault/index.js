// The app reaches the plugin through window.Capacitor (src/vault.js) and needs no
// bundler; this entry exists for anything that imports the package instead.
// API: status(), list(), store({alias, secret, meta, reason}), load({alias, reason}),
// remove({alias}). Rejections carry `code`: cancelled | failed | locked |
// invalidated | not_found | not_enrolled | unavailable.
const { registerPlugin } = require("@capacitor/core");
module.exports = { DeviceVault: registerPlugin("DeviceVault") };
