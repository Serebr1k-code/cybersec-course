---
id: forensics-app-artifacts
title: "Артефакты мобильных приложений: мессенджеры и базы"
category: forensics
parent: forensics-mobile-deep
difficulty: hard
order: 2
tags: [mobile, android, ios, whatsapp, telegram, signal, sqlite, app-forensics]
prerequisites: [forensics-mobile-deep]
useful_for:
  - "CTF Forensics категория"
  - "Mobile Forensics"
  - "Incident Response"
estimated_minutes: 50
summary: "Разбор артефактов мобильных приложений: базы SQLite мессенджеров (WhatsApp, Telegram, Signal), вложения, кэши, ключи и шифрование, а также восстановление удалённой переписки."
---

Большая часть улик на телефоне — в приложениях, прежде всего в мессенджерах. Каждое приложение хранит свои данные по-своему: SQLite-базы, файлы вложений, кэши, иногда зашифрованные. Понимание структуры позволяет восстановить переписку, контакты, геолокацию и удалённые сообщения.

## Где что лежит (Android)

| Приложение | Путь (пример) | Формат |
|------------|---------------|--------|
| WhatsApp | `/data/data/com.whatsapp/databases/msgstore.db` | SQLite (crypt12/14) |
| Telegram | `/data/data/org.telegram.messenger/files/cache4.db` | SQLite (зашифрован) |
| Signal | `/data/data/org.thoughtcrime.securesms/databases/signal.db` | SQLite + ключ |
| Общие вложения | `/sdcard/Android/media/<pkg>/` | файлы |

WhatsApp хранит историю в `msgstore.db` (открытый SQLite) или в `msgstore.db.crypt14` (зашифрован ключом из `key`). Telegram шифрует `cache4.db`; ключ выводится из настроек. Signal хранит `signal.db`, зашифрованную SQLCipher с ключом в `SharedPreferences`.

## Где что лежит (iOS)

iOS-бэкап (или ФС) хранит данные приложений в `AppDomain-<bundleID>`:

- `AppDomainGroup-group.net.whatsapp.WhatsApp.shared` — общие данные WhatsApp.
- `AppDomain-org.thoughtcrime.securesms` — Signal.
- `AppDomain-ph.telegra.ph` / `org.telegram` — Telegram.

Имена файлов в бэкапе хешированы; `Manifest.db` (SQLite) сопоставляет `fileID` → `relativePath`/`domain`.

```bash
sqlite3 Manifest.db "select fileID, domain, relativePath from Files where relativePath like '%msgstore%';"
```

## Разбор SQLite-баз

```bash
# Открыть и осмотреть схему
sqlite3 msgstore.db ".tables"
sqlite3 msgstore.db ".schema message"
# Последние сообщения
sqlite3 -header -column msgstore.db \
  "select key_id, remote_jid, from_me, timestamp, text from message order by timestamp desc limit 20;"
# Восстановить удалённые (WAL / freelist)
sqlite3 msgstore.db "PRAGMA wal_checkpoint;"
sqlite3 msgstore.db "select count(*) from message where text is null;"
```

Удалённые строки могут остаться в **WAL-файле** или в свободных страницах. Инструменты `undark`, `sqlite_undark`, `bring2lite` восстанавливают их.

## Ключи и шифрование

- **WhatsApp crypt14.** Ключ в файле `key` (плейн, если есть root) — расшифровывается `wa-crypt-tools`.
- **Signal.** SQLCipher; ключ в `SharedPreferences` (Android) или Keychain (iOS).
- **Telegram.** `cache4.db` шифруется; ключ в `tgnet.dat`/`userconf`.

```bash
# WhatsApp: расшифровать msgstore
python3 wa-crypt-tools.py decrypt14 key msgstore.db.crypt14 msgstore.db
sqlite3 msgstore.db ".tables"
```

## Разобранный пример

```bash
$ sqlite3 msgstore.db "select remote_jid, datetime(timestamp/1000,'unixepoch'), text from message order by timestamp desc limit 3;"
4915112345678@s.whatsapp.net|2024-03-01 22:15:00|встречаемся в 22:30
4915112345678@s.whatsapp.net|2024-03-01 22:16:10|пароль от архива: hunter2
$ ls Android/media/com.whatsapp/WhatsApp/Media/WhatsApp\ Documents/
report.pdf  archive.zip
$ file "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents/archive.zip"
... Zip archive data
```

Вывод: восстановлены сообщения с паролем и вложение — архив, который можно распаковать этим паролем.

## Вложения и медиа

Вложения обычно лежат вне баз, в каталогах `Media/` (WhatsApp), `files/` (Telegram), `attachments/` (Signal). Метаданные (кому отправлено, когда) — в базе. Для удалённых вложений помогает carving: `photorec` по `userdata`.

## Краевые случаи и подводные камни

- **Шифрование.** Многие базы зашифрованы; без ключа — только метаданные.
- **Исчезающие сообщения.** Signal/Telegram/WhatsApp удаляют по таймеру; но остатки могут быть в WAL.
- **Экспорт из облака.** Часть переписки — в облачном бэкапе, не на устройстве.
- **Несколько аккаунтов.** WhatsApp Business/Telegram multi-account — разные базы.
- **Кэш ≠ история.** Кэшированные медиа могут остаться даже после удаления сообщения.
- **Время.** WhatsApp хранит timestamp в миллисекундах; приводите аккуратно.
- **Версии схемы.** Названия таблиц меняются между версиями приложений.
- **Целостность.** Работайте с копией базы; открытие в SQLite может изменить файл.

## Android: разбор через ALEAPP

ALEAPP автоматически обрабатывает извлечённую ФС или бэкап и создаёт HTML-отчёт по артефактам:

```bash
python3 -m aleapp -t fs -i /evidence/android_fs -o /evidence/aleapp_out
# Открыть отчёт
ls /evidence/aleapp_out/index.html
```

Что извлекается: SMS/MMS, звонки, контакты, история браузеров, аккаунты, местоположения, установленные приложения, базы мессенджеров (частично), журналы подключений Wi-Fi/Bluetooth.

## iOS: разбор через iLEAPP

```bash
# Из iTunes-бэкапа
python3 -m ileapp -t itunes -i /evidence/ios_backup -o /evidence/ileapp_out
# Из файловой системы (jailbreak)
python3 -m ileapp -t fs -i /evidence/ios_fs -o /evidence/ileapp_out
```

Артефакты iOS: iMessage/SMS (`sms.db`), звонки (`CallHistory.storedata`), Safari (`History.db`), Health, локации (`cache.sqlite`), знания (`knowledgeC.db` — очень ценный источник активности).

## knowledgeC.db

`knowledgeC.db` (iOS) — база CoreDuet с записями активности: какие приложения использовались, когда, какие уведомления, зарядка, подключения. Это один из богатейших источников таймлайна.

```bash
sqlite3 knowledgeC.db ".tables"
sqlite3 knowledgeC.db "select ZOBJECT.ZVALUESTRING, datetime(ZOBJECT.ZSTARTDATE+978307200,'unixepoch') \
  from ZOBJECT join ZSTRUCTUREDMETADATA on ... limit 20;"
```

Дата iOS — Unix + 978307200 (эпоха 2001).

## Восстановление удалённых данных из SQLite

```bash
# Свободные страницы и WAL
sqlite3 app.db "PRAGMA page_count; PRAGMA freelist_count;"
# undark: восстановление удалённых строк
pip install undark
undark -i app.db -o app_recovered.db
# bring2lite — инструмент для SQLite recovery
```

Помимо WAL, данные могут быть в `-journal`, `-wal`, `-shm` файлах — не забудьте скопировать их вместе с базой.

## Геолокация

Мобильные артефакты часто содержат GPS:

- **iOS** — `cache.sqlite`, `routing.db`, `locationd` (кэш геолокации).
- **Android** — `com.google.android.gms` базы, `cache.cell`.
- **Фото** — EXIF GPS.

```bash
# Извлечь координаты из EXIF
exiftool -r -GPSLatitude -GPSLongitude -csv /evidence/media > gps.csv
```

Координаты можно нанести на карту (KML) и сопоставить со временем.

## Сводная таблица источников

| Платформа | Артефакт | Путь |
|-----------|----------|------|
| Android | SMS | `mmssms.db` |
| Android | Звонки | `contacts2.db` |
| Android | Аккаунты | `accounts.db` |
| iOS | SMS/iMessage | `sms.db` |
| iOS | Звонки | `CallHistory.storedata` |
| iOS | Активность | `knowledgeC.db` |
| iOS | Safari | `History.db` |

## Типичные ошибки

- **Игнорирование `-wal`/`-shm`.** Теряются последние записи.
- **Открытие базы на запись.** Меняет файл; работайте с копией.
- **Ошибки времени.** iOS-эпоха 2001, Android-время может быть локальным.
- **Пропуск knowledgeC.** Один из лучших источников таймлайна iOS.
- **Нет проверки на шпионское ПО.** MVT может выявить скрытую угрозу.
- **Единый отчёт.** Сверяйте ALEAPP/iLEAPP с ручным разбором.

## Сопоставление артефактов приложений

Данные одного приложения разбросаны по нескольким местам — их нужно связать:

- **База сообщений** (`msgstore.db`) — текст и метаданные.
- **Файл вложений** (`Media/`) — сам файл.
- **Кэш** — миниатюры и превью (могут остаться после удаления).
- **Логи/аналитика** — события приложения.

```bash
# Найти все файлы, связанные с WhatsApp
find /evidence/android_fs -iname '*whatsapp*' -o -iname '*msgstore*'
# Сопоставить сообщение с вложением по времени и имени
sqlite3 msgstore.db "select remote_jid, text from message where text like '%report%';"
ls "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents/"
```

## Восстановление удалённых сообщений

- **WAL-файл** — последние незакоммиченные изменения.
- **Freelist** — удалённые строки до `VACUUM`.
- **undark**/`sqlite_undark` — автоматическое восстановление.
- **Carving** по `userdata` — если база перезаписана.

```bash
undark -i msgstore.db -o recovered.db
sqlite3 recovered.db "select count(*) from message;"
```

## Шифрование: практика

```bash
# WhatsApp crypt14: нужен файл key
python3 wa-crypt-tools.py decrypt14 key msgstore.db.crypt14 msgstore.db
# Signal: SQLCipher, ключ из SharedPreferences
sqlcipher signal.db "PRAGMA key = '...'; select count(*) from sms;"
# Telegram: cache4.db, ключ из tgnet.dat
```

Без ключа остаётся анализ метаданных (размеры, время, участники) и кэшей.

## Чек-лист разбора мессенджера

1. Найти каталог приложения.
2. Определить, зашифрована ли база.
3. Извлечь ключ (root/бэкап).
4. Расшифровать и открыть копию.
5. Извлечь сообщения, контакты, вложения.
6. Проверить WAL/freelist на удалённое.
7. Сопоставить вложения с сообщениями.

## Особенности разных мессенджеров

| Мессенджер | База | Шифрование | Ключ |
|------------|------|------------|------|
| WhatsApp | `msgstore.db` | crypt14 (опц.) | файл `key` |
| Signal | `signal.db` | SQLCipher | Keychain/SharedPrefs |
| Telegram | `cache4.db` | да | `tgnet.dat` |
| Threema | `threema.db` | да | ключ в настройках |
| Viber | `viber.db` | да | ключ в БД/Keychain |

```bash
# Быстрый обзор найденных баз
find /evidence -iname '*.db' -o -iname '*.sqlite' | while read f; do
  echo "== $f"; sqlite3 "$f" '.tables' 2>/dev/null | head -1
done
```

## Восстановление и корреляция

Удалённые сообщения часто остаются в WAL; вложения — в `Media/`; метаданные (участники, время) — даже в зашифрованных базах. Коррелируйте базу, вложения и кэш по времени, чтобы восстановить полную переписку.

## Итог

Артефакты приложений — самый ценный источник на телефоне. Начинайте с каталогов приложений, определите шифрование, извлеките ключи и разберите базы; не забывайте про WAL, кэши и вложения.

## Ключевые выводы

- База сообщений + вложения + кэш = полная картина переписки.
- Шифрование не приговор: ключ часто доступен при root/бэкапе.
- WAL и freelist хранят удалённые сообщения до vacuum.
- Всегда открывайте копию базы, а не оригинал.
- iOS-эпоха — 2001; учитывайте при построении таймлайна.

## Мини-таблица приложений

| Приложение | Файл | Заметка |
|------------|------|---------|
| WhatsApp | msgstore.db | ключ в `key` |
| Signal | signal.db | SQLCipher |
| Telegram | cache4.db | ключ в tgnet |
| Viber | viber.db | ключ в БД |

Начните с определения, зашифрована ли база, и поиска ключа — от этого зависит весь дальнейший разбор.

## Что дальше / решение

1. Найти каталоги приложений (root/бэкап).
2. Определить, зашифрованы ли базы.
3. Извлечь ключи (key/tgnet/SharedPreferences).
4. Расшифровать и открыть SQLite.
5. Проверить WAL/freelist на удалённые записи.
6. Собрать вложения и сопоставить с сообщениями.

Дальше — `forensics-mobile-android`/`forensics-mobile-ios` для платформенных артефактов.

## Квиз

```quiz
- question: "В каком файле WhatsApp (Android) хранит историю сообщений?"
  options:
    - "msgstore.db (или .crypt14)"
    - "Manifest.db"
    - "cache4.db"
    - "signal.db"
  answer: 0
  explanation: "WhatsApp использует msgstore.db, иногда зашифрованный как .crypt14."
- question: "Зачем в iOS-бэкапе нужен Manifest.db?"
  options:
    - "Он хранит переписку"
    - "Он сопоставляет fileID с путями/доменами файлов бэкапа"
    - "Он расшифровывает бэкап"
    - "Он содержит пароли"
  answer: 1
  explanation: "Manifest.db — индекс бэкапа: fileID → relativePath/domain."
- question: "Где могут сохраниться удалённые сообщения в SQLite?"
  options:
    - "В WAL-файле и свободных страницах"
    - "В Manifest.db"
    - "В реестре"
    - "Их нигде не остаётся"
  answer: 0
  explanation: "WAL и freelist могут содержать удалённые строки до vacuum."
- question: "Почему базу надо открывать копию, а не оригинал?"
  options:
    - "Оригинал зашифрован"
    - "Открытие в SQLite может изменить файл (WAL/журнал)"
    - "Оригинал нельзя читать"
    - "Это быстрее"
  answer: 1
  explanation: "SQLite может писать в WAL при открытии — работайте с копией."
```

## Где пригодится

- **CTF:** задачи с базами мессенджеров.
- **Mobile Forensics:** восстановление переписки и вложений.
- **IR:** анализ коммуникации фигурантов.
- **Судебная экспертиза:** доказательство сообщений и передачи файлов.
