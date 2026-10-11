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
## Что такое Firebase-мисконфиги

Firebase — платформа Google для бэкенда мобильных приложений: Realtime Database, Cloud Firestore, Cloud Storage, Authentication. Многие приложения используют её и оставляют правила безопасности (security rules) открытыми — «read/write: true». Тогда любой, у кого есть конфиг Firebase (а он зашит в приложение), может читать и писать данные напрямую, минуя приложение. Это частая находка в баг-баунти и CTF. Цель модуля — научиться находить Firebase-конфиги в приложении и проверять их на мисконфиги.

## Где искать Firebase-конфиг

- `google-services.json` (Android) — содержит `project_id`, `api_key`, `database_url`, `storage_bucket`.
- `GoogleService-Info.plist` (iOS).
- В `strings.xml` и в коде — `firebaseio.com`, `firebasestorage.googleapis.com`.
- В `assets/`.

```bash
unzip -l app.apk | grep -iE 'google-services|firebase'
grep -rhoE '[a-z0-9-]+\.firebaseio\.com' app_java app_smali/assets | sort -u
grep -rhoE '[a-z0-9-]+\.appspot\.com' app_java | sort -u
```

`api_key` Firebase — публичный по дизайну, но без правил безопасности он открывает доступ к данным.

## Проверка Realtime Database

Формат URL: `https://<project>.firebaseio.com/.json`. Попробуйте прочитать корень:

```bash
curl -s "https://<project>.firebaseio.com/.json"
curl -s "https://<project>-default-rtdb.firebaseio.com/.json"
```

Если возвращается JSON с данными — правила открыты. Перебирайте пути: `/users`, `/flags`, `/config`, `/secret`.

```bash
curl -s "https://<project>.firebaseio.com/users.json"
```

Проверьте и запись (осторожно): `curl -X PUT "https://<project>.firebaseio.com/test.json" -d '"x"'`.

## Проверка Firestore

```bash
curl -s "https://firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents/<collection>?key=<api_key>"
```

Если правило `allow read: if true`, данные отдаются без аутентификации. Перебирайте коллекции.

## Проверка Cloud Storage

```bash
curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>.appspot.com/o"
```

Открытый листинг бакета выдаёт список файлов. Скачивайте подозрительные:

```bash
curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>.appspot.com/o/<path>?alt=media"
```

## Автоматизация

- **`FirebaseEnum`**, **`firebase-tools`** — перечисление.
- **`firepwn`**, **`Firesploit`** — эксплуатация открытых правил.
- Ручной перебор путей через `curl` + словарь.

## Типичные ошибки и подводные камни

- **Считать `api_key` секретом** — он публичен; важны rules.
- **Проверять только корень** — данные могут быть на путях.
- **Забыть про Firestore/Storage** — не только Realtime DB.
- **Не проверить запись** — открытая запись опаснее чтения.
- **Путать project_id и database_url** — иногда различаются.
- **Игнорировать регион** — URL может быть `<project>-default-rtdb.<region>.firebasedatabase.app`.
- **Не заметить правила «auth-only»** — иногда достаточно анонимной аутентификации.

## Справочная таблица

| Ресурс | URL |
|--------|-----|
| Realtime DB | `https://<p>.firebaseio.com/.json` |
| Firestore | `.../projects/<p>/databases/(default)/documents/<c>` |
| Storage | `firebasestorage.googleapis.com/v0/b/<b>/o` |
| Конфиг | `google-services.json` |

## Что дальше / решение

План: найдите Firebase-конфиг в APK (`google-services.json`, строки), извлеките `project_id`, `api_key`, `database_url`, `storage_bucket`. Затем проверьте каждый ресурс: Realtime DB (`.json`), Firestore, Storage. Перебирайте пути и коллекции. Если правила открыты — вы получите данные напрямую. Firebase-мисконфиги — частая и легко эксплуатируемая уязвимость, часто ведущая прямо к флагу.

## Практический пример: открытая Realtime Database

Разберём сквозной сценарий. В APK находим `google-services.json` с полями `project_id: example-app` и `api_key: AIza...`. Шаг 1: формируем URL базы: `https://example-app.firebaseio.com/.json`. Шаг 2: `curl -s "https://example-app.firebaseio.com/.json"` — если возвращается JSON с данными, правила открыты. Шаг 3: перебираем пути: `/users.json`, `/flags.json`, `/config.json`, `/secret.json`. Шаг 4: если корень закрыт, но какая-то коллекция открыта — найдём её перебором. Шаг 5: проверяем запись: `curl -X PUT ".../test.json" -d '"x"'` — если прошло, правила `write: true`.

Это типичный путь к флагу в задачах категории Mobile: конфиг в APK → открытая база → данные. Иногда база не в `firebaseio.com`, а в региональном домене `<project>-default-rtdb.<region>.firebasedatabase.app` — проверяйте оба.

## Firestore и Storage

Firestore проверяется через REST API с `api_key`. Storage — через листинг бакета. Открытый листинг Storage часто содержит бэкапы, конфиги и флаги. Скачивайте подозрительные файлы через `?alt=media`.

## Частые вопросы

«Корень закрыт — тупик?» — нет, перебирайте пути. «Не знаю project_id?» — `google-services.json` или строки в APK. «База в другом регионе?» — проверьте региональный домен. «api_key не работает?» — возможно, нужно ограничение по приложению; проверяйте rules. «Как автоматизировать?» — `FirebaseEnum`, `firepwn`.

## Что дальше / решение

Итог: извлеките Firebase-конфиг из APK, проверьте Realtime DB, Firestore и Storage на открытые правила, перебирайте пути и коллекции. Firebase-мисконфиги — частая и легко эксплуатируемая уязвимость, часто ведущая прямо к флагу. Держите под рукой `curl` и инструменты перечисления.

## Расширенный чек-лист по Firebase

Действуйте методично. Первое: извлеките конфиг — `unzip -l app.apk | grep -i google-services`, затем читайте `google-services.json` или `GoogleService-Info.plist`; если их нет, ищите строки `firebaseio.com`, `appspot.com` в коде и ресурсах. Второе: соберите все значения — `project_id`, `api_key`, `database_url`, `storage_bucket`, `mobilesdk_app_id`. Третье: для Realtime DB попробуйте `.json` на корне и на типовых путях (`users`, `config`, `flags`, `secret`, `messages`). Четвёртое: для Firestore сформируйте REST-запрос с `api_key` и перебирайте коллекции. Пятое: для Storage запросите листинг бакета (`/o`) и скачивайте подозрительные файлы через `?alt=media`. Шестое: проверьте правила записи (`PUT`/`POST`). Седьмое: проверьте Authentication — иногда открыта анонимная регистрация, дающая доступ к «auth-only» правилам.

## Проекты и регионы

Firebase-база может быть в региональном домене: `<project>-default-rtdb.<region>.firebasedatabase.app` или `<project>.<region>.firebasedatabase.app`. Проверяйте оба варианта и разные регионы (`us-central1`, `europe-west1`, `asia-southeast1`). Иногда `project_id` из конфига отличается от имени базы — пробуйте комбинации.

## Инструменты перечисления

`FirebaseEnum` автоматизирует перебор путей; `firepwn` и `Firesploit` проверяют правила; `firebase-tools` (`firebase`) — официальный CLI. Для ручной работы достаточно `curl` и словаря путей. Всегда фиксируйте найденные рабочие URL — они пригодятся для дальнейшего анализа.

## Частые вопросы

«Корень `.json` отдаёт `null`?» — база пуста или путь неверен. «403/401?» — правила требуют аутентификации; попробуйте анонимный вход. «Нет `google-services.json`?» — ищите строки в коде. «Storage не листится?» — пробуйте прямые пути файлов. «Как понять, что правила открыты?» — успешное чтение без токена.

## Что дальше / решение

Итог: извлеките Firebase-конфиг, проверьте Realtime DB, Firestore и Storage, перебирайте пути и коллекции, проверяйте запись и аутентификацию. Firebase-мисконфиги — одна из самых частых находок в мобильном пентесте и часто кратчайший путь к данным и флагу. Держите под рукой `curl` и `FirebaseEnum`.

## Примеры команд для проверки Firebase

Ниже — набор команд, который покрывает большинство проверок. Держите его под рукой.

```bash
# извлечь конфиг
unzip -o app.apk google-services.json -d /tmp/fb
python3 -c "import json;d=json.load(open('/tmp/fb/google-services.json'))['project_info'];print(d)"

# Realtime DB
curl -s "https://<project>.firebaseio.com/.json"
curl -s "https://<project>.firebaseio.com/users.json"
curl -s "https://<project>-default-rtdb.<region>.firebasedatabase.app/.json"

# Firestore
curl -s "https://firestore.googleapis.com/v1/projects/<project>/databases/(default)/documents/users?key=<api_key>"

# Storage
curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>.appspot.com/o"
curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>.appspot.com/o/<path>?alt=media"
```

Заменяйте `<project>`, `<region>`, `<api_key>`, `<bucket>` на значения из конфига. Если запрос возвращает данные без токена — правила открыты.

## Анализ ответов

`null` означает, что путь пуст или закрыт. JSON с данными — открытое чтение. `Permission denied` — правила требуют аутентификации. `Missing or insufficient permissions` — правило есть, но не пропускает анонимного пользователя. Учитывайте эти различия, чтобы не принять закрытую базу за пустую.

## Что ещё проверить

Помимо данных, проверьте: правила записи (можно ли подменить данные), Firebase Authentication (открыта ли анонимная регистрация), Cloud Functions (есть ли публичные HTTP-триггеры), Remote Config (не утекают ли значения). Иногда флаг лежит не в базе, а в публичной Cloud Function или в Remote Config.

## Частые вопросы

«`null` на всех путях?» — возможно, нужен регион или другой домен. «`Permission denied`?» — попробуйте анонимную аутентификацию. «Storage пустой?» — пробуйте прямые пути. «Как найти bucket?» — `storage_bucket` в конфиге или строка `appspot.com` в коде.

## Что дальше / решение

Итог: извлеките конфиг, проверьте Realtime DB, Firestore, Storage и дополнительные сервисы (Functions, Remote Config). Перебирайте пути и регионы, проверяйте запись. Firebase-мисконфиги — частая и легко эксплуатируемая уязвимость; набор команд выше позволяет проверить всё за минуты.

## Итог по Firebase

Проверяйте Realtime DB, Firestore и Storage на открытые правила, перебирайте пути и регионы, проверяйте запись и аутентификацию. Firebase-мисконфиги — частая находка и кратчайший путь к данным и флагу. Держите набор `curl`-команд под рукой.

## Квиз

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
- question: "Правила Firestore и Realtime Database — это…"
  options:
    - "Разные наборы правил для разных продуктов"
    - "Один и тот же файл правил"
    - "Настройки только на клиенте"
    - "Только для iOS"
  answer: 0
  explanation: "Это отдельные продукты со своими Security Rules."
- question: "Как безопасно подтвердить открытую запись в Realtime DB?"
  options:
    - "PUT во временный ключ, не трогая реальные данные"
    - "Удалить корневой узел"
    - "Перезаписать /users"
    - "Отправить DELETE /*"
  answer: 0
  explanation: "Минимальный неразрушающий PUT доказывает доступ и не вредит."
- question: "Где искать Firebase-конфиг в APK?"
  options:
    - "В строках DEX и ресурсах (google-services.json)"
    - "В AndroidManifest.xml permissions"
    - "В подписи APK"
    - "В libc.so"
  answer: 0
  explanation: "Конфиг и ключи утекают в строковых константах и ресурсах."
```

## Где пригодится

- **CTF Mobile:** задачи, где в APK спрятан конфиг открытой Firebase, а флаг — в узле БД.
- **Bug bounty:** открытые Firestore/Realtime DB/Storage — частый critical с выплатами за утечку PII.
- **Пентест:** проверка клиент-серверных мисконфигов, когда backend — managed (Firebase), а не свой.
- **Работа:** аудит правил безопасности перед релизом мобильного приложения.
