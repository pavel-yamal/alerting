# Выпуск приложения ЛПР в App Store и ревью Apple

Как отдать `apps/approver` (docs/14, ADR 0016) на ревью Apple и пройти его. Приложение
служебное: войти может только человек, чей ключ внесён в справочник организации.
Ревьюеру Apple вносить ключ некому, поэтому для ревью поднимается **отдельный
демо-стенд**, который регистрирует телефон сам.

## Что уже сделано в проекте

| Требование Apple | Где | Проверяет |
|---|---|---|
| Строка назначения Face ID (`NSFaceIDUsageDescription`) | `ios/App/App/Info.plist` | `test/shipping.test.mjs` |
| Ответ про шифрование в сборке (`ITSAppUsesNonExemptEncryption = NO`) | там же | там же |
| Манифест приватности `PrivacyInfo.xcprivacy`: без отслеживания, UserID/Name/контент — для работы приложения; UserDefaults, причина `CA92.1` | `ios/App/App/PrivacyInfo.xcprivacy`, в ресурсах цели | там же |
| Иконка 1024×1024 без прозрачности, своя заставка | `scripts/icons.py` → `Assets.xcassets`, `store/icon-1024.png` | там же |
| iPhone и iPad (`TARGETED_DEVICE_FAMILY = "1,2"`) | `project.pbxproj` | там же |
| iOS 17+ (Ed25519 в WebCrypto) | `IPHONEOS_DEPLOYMENT_TARGET = 17.0` | там же |
| Bundle ID `me.yamal.alert` | `capacitor.config.json`, `project.pbxproj` | там же |
| Политика конфиденциальности по ссылке и в приложении | панель: `GET /privacy`; ссылка на экранах подключения и входа | `tests/integration/test_panel_app_client.py` |
| Вход ревьюера без настоящего справочника | демо-стенд (`demo_enroll.py`, `docker/review.yml`) | `tests/integration/test_panel_demo_enroll.py` |

> ⚠️ **Шифрование: ответ «не использует нешифруемое исключение» верен, и вот почему.**
> Ed25519 в приложении только подписывает (аутентификация и целостность), а HTTPS
> даёт система. Это освобождённые категории (Category 5 Part 2, note 3); документов
> на экспорт не нужно. Если когда-нибудь появится шифрование содержимого своими
> средствами — ответ меняется, и вместе с ним ключ в `Info.plist`.

> ⚠️ **Иконку и заставку не править руками** — `python3 apps/approver/scripts/icons.py`
> (нужен Pillow). Иконка с альфа-каналом отбивается при загрузке сборки, а стандартная
> иконка Capacitor — на ревью (4.1, «шаблонное приложение»).

## Демо-стенд для ревьюера

Отдельная установка (не боевая!) с демо-организацией из `org-init`, доступная из
интернета по https. Панель получает корневой ключ **демо**-организации и вносит в
справочник ключ любого телефона как «Демо-ЛПР N», роль `lpr`, на 30 дней, не больше
200 регистраций. Приложение видит `demo: true` в `/api/config` и показывает полосу
«Демо-стенд» на каждом экране.

```bash
# на отдельном сервере, docs/12-docker.md до шага «запустить»
docker compose --env-file docker/.env --profile init run --rm org-init
docker compose --env-file docker/.env -f docker-compose.yml -f docker/review.yml up -d
```

Затем опубликовать панель по https (например, `https://alert-review.<ваш домен>` —
TLS снимает обратный прокси) и открыть `/privacy` и `/api/config` с телефона: оба
должны отвечать, `demo` — `true`.

> ⚠️ **Каналы демо-стенда не должны вести к живым людям.** Ревьюер разошлёт учебное
> оповещение; в демо-организации получатели вымышленные — проверьте, что SMS/почта
> стенда не настроены на настоящие номера и адреса.

> ⚠️ **На боевой панели `--demo-enroll-root-key` не включается** и включиться не может:
> корневого ключа на сервере нет (ADR 0013), а панель с ключом, не совпадающим с
> закреплённым корнем, не стартует.

## App Store Connect

- **Название:** «Оповещение ЛПР», подзаголовок «Подпись приказов об оповещении».
  Имя под иконкой — «Оповещение».
- **Категория:** Business. **Цена:** бесплатно. **Возраст:** 4+.
- **Распространение:** рекомендуется *Unlisted* (по ссылке) — приложение не для
  частных лиц; либо обычная публикация с пометкой в описании, что нужна учётная
  запись организации.
- **URL политики конфиденциальности:** `https://alert-review.<ваш домен>/privacy` — страница демо-стенда; в самом приложении ссылка ведёт на `/privacy` той панели, к которой оно подключено.
- **URL поддержки:** страница организации или та же `/privacy` (там есть контакт).
- **Приватность приложения (App Privacy):** отслеживания нет. Собирается и связано с
  пользователем, только «Функциональность приложения»: *Идентификаторы → User ID*,
  *Контактные данные → Имя*, *Пользовательский контент → Другой контент* (приказы).
  Биометрию приложение **не собирает** — её проверяет система. Ответы обязаны
  совпадать с `PrivacyInfo.xcprivacy` и с `/privacy`.
- **Скриншоты:** iPhone 6,9″ (1320×2868) и iPad 13″ (2064×2752) — экраны входа,
  «На подпись», карточка учебного приказа, «Новый». Делать на демо-стенде: полоса
  «Демо-стенд» на снимке допустима и честна.

### Review notes (вставить как есть)

```
This is an internal app for decision-makers of an organisation: they review and
sign alert orders (e.g. building evacuation). Normally a key is enrolled only after
an in-person check by the organisation. For review we run a demonstration stand
that enrols any device automatically.

1. Launch the app and enter the panel address: https://alert-review.<domain>
   then tap "Подключиться" (Connect).
2. Open "Зарегистрировать этот телефон" (Register this phone) and tap
   "Создать ключ" (Create key). The stand enrols the phone as "Демо-ЛПР N".
3. Tap "Войти" (Sign in) and confirm with Face ID.
4. Tab "Новый" (New): choose "Технический тест канала" (TEST.PING), mode
   "Учение" (Drill), tap "Создать предложение", then open it, tick the check box
   and tap "Подписать учение" (Sign drill), confirm with Face ID. A drill of this
   level needs one signature and is dispatched to fictional recipients.
   Critical scenarios need two different decision-makers and stay in
   "На подпись" (Awaiting signature) — this is intended.

Face ID is required: the signing key is stored in the Keychain with
biometryCurrentSet access control. There is no account, password or payment.
Privacy policy: https://alert-review.<domain>/privacy
The banner "Демо-стенд" at the top marks the demonstration stand.
```

## Сборка для загрузки

```bash
cd apps/approver
npm ci && npm test
npm run sync            # build + cap sync + native-setup
npx cap open ios        # Xcode
```

В Xcode: команда разработчика в *Signing & Capabilities*, `MARKETING_VERSION`
(1.0) и `CURRENT_PROJECT_VERSION` (+1 на каждую загрузку), схема *Release*,
*Product → Archive → Distribute App → App Store Connect*.

> ⚠️ **Перед загрузкой — на живом iPhone и iPad**, а не в симуляторе: Face ID без
> кнопки «Ввести пароль», вход и подпись на демо-стенде, сообщение после добавления
> нового лица (ключ недействителен — нужна новая регистрация). Нативный код плагина
> `device-vault` в этой среде не собирался — первая сборка в Xcode проверит его.

## Частые отказы и что отвечать

| Правило | Повод | Ответ |
|---|---|---|
| 2.1 Information Needed | ревьюер не смог войти | демо-стенд доступен из интернета, адрес и шаги в Review notes |
| 3.2 / 4.2 «нет пользы для публики» | приложение для сотрудников | *Unlisted*-распространение либо пояснение: служебный инструмент организации |
| 4.2 «это сайт в обёртке» | Capacitor | страница вшита в сборку, ключ под Face ID в Keychain, подпись на устройстве — сайт этого не может |
| 5.1.1 Privacy | нет политики / расхождение с App Privacy | `/privacy` открыта без входа, ответы совпадают с манифестом |
| 5.1.1(v) удаление учётной записи | — | учётных записей нет; ключ удаляется кнопкой «Удалить ключ», запись в справочнике отзывает организация (сказано в политике) |
| 2.5.1 / guideline про шифрование | экспорт | `ITSAppUsesNonExemptEncryption = NO`, см. выше |
