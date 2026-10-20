# Развёртывание в Docker

Один узел приложения и PostgreSQL на одной машине, через `docker compose`. Это
быстрый путь для стенда и показа. Контур из пяти машин с резервом базы —
[11-installation.md](11-installation.md), через systemd.

Проверено 20 октября 2026: сборка, `org-init`, запуск, учебный приказ от
предложения до проверки исполнителем и `alerting-auditor verify` — `chain intact`.

## 0. Что нужно на сервере

- Docker 24+ с плагином `compose`;
- **синхронизированные часы** (chrony на хосте): контейнер берёт время хоста, а
  при расхождении больше ±120 с узел начинает отвергать валидные приказы и при этом
  выглядит здоровым;
- nginx на хосте с TLS — порт 8080 слушает только `127.0.0.1`
  (`deploy/nginx/alerting.conf`).

## 1. Сборка

```bash
git clone https://github.com/pavel-yamal/alerting.git && cd alerting
cp docker/.env.example docker/.env
docker compose --env-file docker/.env build
```

За корпоративным TLS-прокси pip не доверяет его сертификату. Тогда:

```bash
docker build --secret id=ca,src=/path/corp-ca.crt -t alerting:local .
```

CA передаётся секретом сборки и в образ не попадает.

## 2. Организация (демо)

```bash
docker compose --env-file docker/.env --profile init run --rm org-init
```

Поднимает базу, генерирует пароли, создаёт демо-организацию и кладёт ключ подписи
голов аудита туда, где его ждёт сервер. В выводе — `ORG ROOT PUBLIC KEY`. Впишите
его в `docker/.env`:

```
ALERTING_ROOT_PUBKEY=<ключ из вывода>
```

**`org-init` стирает схему базы.** Повторный запуск — это новая организация с
новым корневым ключом, а старые клиенты перестают ей доверять. И он пишет корневой
**закрытый** ключ в том `alerting_demo-keys`: на боевом сервере его не запускают
вовсе (см. §5).

## 3. Запуск

```bash
docker compose --env-file docker/.env up -d --wait
curl -s http://127.0.0.1:8080/v1/readyz        # {"ready":true, ...}
docker compose --env-file docker/.env logs server | head
```

В первой строке журнала должно быть `audit heads : signed`, а не `UNSIGNED`.

Порядок обеспечивает compose: `secrets-init` → `db` → `migrate` (ролью владельца,
одноразово) → `server` (ролью приложения). Сервер не стартует, если миграции не
прошли.

## 4. Проверка учебным приказом

```bash
R="docker compose --env-file docker/.env --profile cli run --rm cli"
S="--server http://server:8080 --passphrase demo"
H=/var/lib/alerting/clients

$R alerting-approver propose TEST.PING --drill --severity info \
    --groups fire-wardens --text "проверка" --person p-001 --home $H/p-001 $S
$R alerting-approver sign <id> --yes --person p-001 --home $H/p-001 $S
$R alerting-approver status <id> --person p-001 --home $H/p-001 $S

$R alerting-executor sync          --person x-102 --home $H/x-102 $S
$R alerting-executor verify <id>   --person x-102 --home $H/x-102 $S   # ПОДЛИННЫЙ приказ

$R alerting-auditor verify --person a-001 --home $H/a-001 $S           # chain intact
```

У демо-людей ключи уже выданы. **Не запускайте `alerting-executor enroll`** для
них: он создаст новый ключ устройства, которого нет в справочнике, и человек получит
`403`.

## 5. Секреты

Через окружение не передаётся ни один. `secrets-init` генерирует пароли один раз и
раскладывает по трём томам, каждый файл `0400` и принадлежит тому, кто его читает:

| Том | Что | Кто читает |
|---|---|---|
| `alerting_db-secrets` | пароли ролей | postgres, при инициализации |
| `alerting_owner-secrets` | DSN владельца | только `migrate` и `org-init` |
| `alerting_app-secrets` | DSN приложения, ключ подписи голов | только `server` |

Сервер не видит DSN владельца, поэтому не может переписать журнал аудита.

**Боевой узел:** бандлы организации готовятся на машине без сети. На сервер
кладётся только ключ подписи голов:

```bash
docker run --rm -v alerting_app-secrets:/s -v "$PWD/server-key:/k:ro" busybox:1.36 \
    sh -c 'cp /k /s/server-key && chown 10001:10001 /s/server-key && chmod 0400 /s/server-key'
docker volume rm alerting_demo-keys     # если на этой машине когда-то был org-init
```

## 6. Эксплуатация

```bash
docker compose --env-file docker/.env ps
docker compose --env-file docker/.env logs -f server

# обновление: миграции применятся сами перед стартом сервера
git pull && docker compose --env-file docker/.env up -d --build --wait

# резервная копия базы
docker compose --env-file docker/.env exec -T db \
    pg_dump -U postgres -Fc alerting > alerting-$(date +%F).dump
```

Головы аудита лежат в томе `alerting_heads`. Их смысл в том, чтобы быть **вне**
базы: копируйте их на хост аудитора, иначе подделку журнала нечем обнаружить.

## 7. Чего здесь нет

- **Резерва базы.** Один PostgreSQL. Отказ машины — простой до восстановления
  из копии. Резерв и измеренное переключение есть только в systemd-контуре
  ([10-failover.md](10-failover.md)).
- **Реальных каналов.** push, SMS, голос, сирена — заглушки; поэтому в
  `.env.example` стоит `ALERTING_ALLOW_STUB_CHANNELS=1`. Доставляет только приложение
  (WebSocket).
- **TLS.** Его даёт nginx на хосте.
