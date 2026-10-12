---
id: mobile-firebase
title: "Firebase-мисконфиги: открытые БД, Storage и утечки"
category: mobile
parent: mobile-api-testing
difficulty: medium
order: 2
tags: [firebase, firestore, realtime-database, storage, misconfig, android, ios]
prerequisites: [mobile-api-testing, mobile-hardcoded-secrets]
useful_for:
  - "CTF Mobile (чтение данных из открытой Firebase)"
  - "Bug bounty (открытые Firestore/Storage)"
  - "Пентест мобильных приложений"
estimated_minutes: 14
summary: "Как находить Firebase-конфиг в APK/IPA и проверять, открыты ли Firestore, Realtime Database и Storage без аутентификации; типовые мисконфиги правил безопасности."
---

## Вопрос, с которого всё начинается

Многие мобильные приложения не имеют своего сервера — их бэкендом служит **Firebase**, платформа Google. Она даёт готовые базы данных (Realtime Database, Cloud Firestore), файловое хранилище (Cloud Storage) и аутентификацию. Доступ к данным регулируют **правила безопасности** (security rules). Если разработчик оставил их открытыми (`read: true`), любой, кто знает конфиг Firebase, читает данные напрямую — минуя приложение.

И вот ключевой факт: **этот конфиг зашит в само приложение**. Значит, вопрос урока звучит так: как достать конфиг из APK и проверить, не открыт ли доступ?

## Наш пример: shopdemo.apk

Возьмём APK `shopdemo.apk` — учебное приложение магазина. Первым делом смотрим, нет ли внутри файла конфигурации `google-services.json` (именно он генерируется Google и кладётся в APK):

```
$ unzip -l shopdemo.apk | grep -i google-services
      500  2026-10-12 15:55   assets/google-services.json
```

Файл найден в `assets/`. **APK — это обычный ZIP**, поэтому его содержимое достаётся командой `unzip`. Извлекаем конфиг и разбираем JSON:

```
$ unzip -o -q shopdemo.apk 'assets/google-services.json' -d fb_x
$ python3 - <<'EOF'
import json
d = json.load(open('fb_x/assets/google-services.json'))
pi = d['project_info']
print("project_id     =", pi['project_id'])
print("project_number =", pi['project_number'])
print("firebase_url   =", pi['firebase_url'])
print("storage_bucket =", pi['storage_bucket'])
print("api_key        =", d['client'][0]['api_key'][0]['current_key'])
EOF
project_id     = shopdemo-9f1a2
project_number = 918273645012
firebase_url   = https://shopdemo-9f1a2.firebaseio.com
storage_bucket = shopdemo-9f1a2.appspot.com
api_key        = AIzaSyD-DEMO-EXAMPLE-KEY-1234567890
```

Вот и всё, что нужно: имя проекта, адрес базы (`firebase_url`), бакет хранилища и `api_key`.

## Шаг 1: `api_key` — это не секрет

Важно понять сразу: **`api_key` Firebase — публичный по дизайну**. Он не «ключ доступа», а идентификатор проекта; его безопасно вшивать в клиент. Секретность доступа обеспечивают именно **правила безопасности**, а не этот ключ. Поэтому вопрос «утек ли `api_key`» бессмысленен — важнее «открыты ли rules».

Если `google-services.json` в APK нет, конфиг ищут в других местах:

```
$ unzip -l app.apk | grep -iE 'google-services|firebase'
$ strings app.apk | grep -iE 'firebaseio\.com|appspot\.com|firebaseapp\.com'
```

## Шаг 2: проверяем Realtime Database

**Realtime Database** — это JSON-дерево. К любому узлу обращаются по URL, добавив `.json`. Наш `firebase_url` указывает на локальный демо-сервер, поэтому запрашиваем корень:

```
$ curl -s "http://127.0.0.1:18081/.json"
{"users": {"1001": {"email": "alice@example.com"}, "1002": {"email": "bob@example.com"}}, "config": {"support_email": "help@example.com"}, "flags": {"admin_panel": "FLAG{r34lt1m3_db_1s_0p3n}"}}
```

Данные отдались **без токена** — правила открыты. Часто корень большой, поэтому берут только имена узлов первого уровня через параметр `shallow=true`:

```
$ curl -s "http://127.0.0.1:18081/.json?shallow=true"
{"users": true, "config": true, "flags": true}
```

Теперь видно структуру, и можно идти в конкретный узел:

```
$ curl -s "http://127.0.0.1:18081/users.json"
{"1001": {"email": "alice@example.com"}, "1002": {"email": "bob@example.com"}}
```

## Шаг 3: не всё открыто — и это тоже сигнал

Правила могут быть выставлены по-разному. Узел `flags` у нас закрыт:

```
$ curl -s -i "http://127.0.0.1:18081/flags.json"
HTTP/1.0 401 Unauthorized
{"error": "Permission denied"}
```

Это важное различие: `null` или пустой ответ означает «узел пуст или не существует», а `Permission denied` / `Missing or insufficient permissions` — «правило есть, но оно не пускает». Не путайте закрытую базу с пустой. Иногда правило требует лишь **анонимной аутентификации** — тогда достаточно войти анонимно (Firebase Auth) и повторить запрос.

## Шаг 4: Firestore и Cloud Storage

Realtime Database — не единственный продукт. **Cloud Firestore** (более новая база) проверяется через REST с `api_key`:

```
$ curl -s "https://firestore.googleapis.com/v1/projects/<project_id>/databases/(default)/documents/users?key=<api_key>"
```

**Cloud Storage** отдаёт файлы; если листинг открыт, виден список объектов:

```
$ curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>/o"
$ curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>/o/<path>?alt=media"
```

Открытый Storage часто хранит бэкапы, конфиги и те самые флаги. Для Firestore и Storage `api_key` уже нужен — он передаётся в URL.

## Шаг 5: что ещё проверять в Firebase

Помимо данных, у Firebase есть ещё несколько поверхностей, которые стоит перебрать:

- **Remote Config** — набор параметров, который приложение тянет при старте. Иногда там лежат фича-флаги и ссылки на внутренние сервисы.
- **Cloud Functions** — публичные HTTP-триггеры (`https://<region>-<project>.cloudfunctions.net/<name>`). Неаутентифицированная функция может выполнять действия от имени проекта.
- **Authentication** — если открыта анонимная регистрация, то правила «auth-only» обходятся одним запросом на вход.
- **FCM** — ключ для отправки push (разберём в следующем уроке).

Порядок такой: сначала данные (Realtime DB → Firestore → Storage), потом функции и конфиг. Автоматизировать перебор помогает `FirebaseEnum` (перебор путей) и `firepwn` (проверка правил). Для ручной работы достаточно `curl` и словаря путей вроде `users`, `config`, `flags`, `secret`, `messages`.

## Справочная таблица: что и куда

| Ресурс | Как обратиться |
|--------|----------------|
| Конфиг | `assets/google-services.json` внутри APK |
| Realtime DB | `https://<project>.firebaseio.com/<path>.json` |
| Firestore | `firestore.googleapis.com/v1/projects/<p>/databases/(default)/documents/<c>?key=<k>` |
| Storage | `firebasestorage.googleapis.com/v0/b/<bucket>/o` |
| Регион RTDB | `https://<project>-default-rtdb.<region>.firebasedatabase.app/.json` |

## Типовые ошибки новичка

- Считать `api_key` секретом — он публичен, смотрите правила.
- Проверять только корень `.json` — данные часто лежат на конкретных путях.
- Забыть про Firestore и Storage — это отдельные продукты со своими правилами.
- Не проверять запись — открытая запись опаснее чтения.
- Путать `project_id` и имя базы — иногда они различаются, а база живёт в региональном домене.
- Не заметить правила «auth-only» — иногда достаточно анонимного входа.

## Полный прогон от начала до конца

1. **`unzip -l`** — находим `assets/google-services.json` в APK.
2. **`python3 json`** — извлекаем `project_id`, `firebase_url`, `storage_bucket`, `api_key`.
3. **`curl .../.json`** — корень базы без токена отдаёт данные → правила открыты.
4. **`?shallow=true`** — получаем список узлов, не выкачивая всё дерево.
5. **`/users.json`, `/config.json`** — читаем конкретные узлы.
6. **Firestore/Storage** — проверяем остальные продукты по тем же ключам.
7. **Запись** (осторожно) — минимальный неразрушающий `PUT` во временный ключ подтверждает `write: true`.

## Если не сработало

`null` на корне — база пуста или адрес неверен. База может жить в **региональном** домене `<project>-default-rtdb.<region>.firebasedatabase.app` — проверьте и его. `Permission denied` — попробуйте анонимную аутентификацию. Нет `google-services.json` — ищите строки `firebaseio.com` / `appspot.com` в коде и ресурсах. Пусто в Storage — пробуйте прямые пути файлов, а не листинг. И помните про запись: открытая запись опаснее чтения — она позволяет подменить данные других пользователей.

## Что мы теперь знаем

1. Firebase-конфиг лежит в APK (`google-services.json`) или в строках кода.
2. `api_key` публичен — доступ регулируют security rules.
3. Realtime Database читается через `.json`; `?shallow=true` даёт только имена узлов.
4. Firestore и Storage проверяются по REST с `api_key`.
5. `null` ≠ `Permission denied`: первое — пусто, второе — правило не пускает.
6. Проверять надо и чтение, и запись; региональные домены — тоже.

## Квиз

Проверь себя.

```quiz
- question: "Что в Firebase-конфиге НЕ является секретом по дизайну?"
  options:
    - "api_key / API_KEY"
    - "Серверный FCM-ключ"
    - "Пароль от БД"
    - "Приватный ключ подписи"
  answer: 0
  explanation: "apiKey публичен; доступ ограничивают Security Rules, а не секретность ключа."
- question: "Какая команда быстро покажет ключи верхнего уровня Realtime Database?"
  options:
    - "curl https://<project>.firebaseio.com/.json?shallow=true"
    - "curl https://<project>.firebaseio.com/?keys=all"
    - "curl -X LIST https://<project>.firebaseio.com"
    - "curl https://<project>.firebaseio.com/?dump=1"
  answer: 0
  explanation: "Параметр shallow=true отдаёт только ключи первого уровня."
- question: "Ответ `Permission denied` на узел означает, что…"
  options:
    - "Правило существует, но не пропускает этот запрос"
    - "Узел пустой"
    - "APK повреждён"
    - "Нужно переустановить приложение"
  answer: 0
  explanation: "Это отличается от `null` (пусто/нет узла) — правило есть, но не пускает."
- question: "Как безопасно подтвердить открытую запись в Realtime DB?"
  options:
    - "PUT во временный ключ, не трогая реальные данные"
    - "Удалить корневой узел"
    - "Перезаписать /users"
    - "Отправить DELETE /*"
  answer: 0
  explanation: "Минимальный неразрушающий PUT доказывает доступ и не вредит данным."
- question: "Где искать Firebase-конфиг в APK?"
  options:
    - "В assets (google-services.json) и в строковых константах DEX"
    - "В списке permissions манифеста"
    - "В подписи APK"
    - "В libc.so"
  answer: 0
  explanation: "Конфиг и ключи утекают в ресурсах и строковых константах кода."
```

## Куда дальше

Мы научились читать открытые Firebase-базы. В следующем уроке `mobile-push-security` разберём другой продукт Firebase — FCM: как устроены push-уведомления, где хранится токен устройства и почему подмена payload может привести к фишингу или утечке. А пока запомни главное: конфиг — в APK, а доступ определяют правила, а не ключ.

## Где пригодится

- **CTF Mobile:** конфиг в APK + открытая база = быстрый путь к флагу.
- **Bug bounty:** открытые Firestore/Realtime DB/Storage — частый critical за утечку PII.
- **Пентест:** проверка клиент-серверных мисконфигов, когда бэкенд managed (Firebase).
- **Работа:** аудит правил безопасности перед релизом мобильного приложения.
