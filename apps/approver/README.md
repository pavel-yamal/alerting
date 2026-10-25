# alerting-approver — приложение ЛПР

Подпись приказов ключом телефона под Face ID / отпечатком. Решение —
[docs/adr/0016](../../docs/adr/0016-native-approver-app.md), сборка и работа —
[docs/14-approver-app.md](../../docs/14-approver-app.md), выпуск в App Store и ревью —
[docs/15-ios-review.md](../../docs/15-ios-review.md).

```
src/                  страница: index.html, app.js (экраны), logic.js (чистые правила), vault.js (мост к плагину)
scripts/build.mjs     собирает www/ и берёт devicekey.js из панели как есть
scripts/native-setup.mjs  Info.plist (Face ID) и FLAG_SECURE после `cap add`
plugins/device-vault/ нативный плагин: iOS Keychain (.biometryCurrentSet), Android Keystore + BiometricPrompt
test/                 node --test: правила и что приложение не должно содержать
```
