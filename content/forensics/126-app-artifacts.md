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

## Вопрос, с которого всё начинается

В прошлом уроке мы извлекли данные с телефона. Но «данные» — это тысячи файлов, и большинство из них бесполезны. Где искать саму переписку и, что важнее, можно ли восстановить **удалённые** сообщения? Ответ почти всегда — в базах приложений.

## Наш пример: база WhatsApp

У нас есть файловая система Android после извлечения. Смотрим каталог WhatsApp:

```bash
$ ls /data/data/com.whatsapp/databases/
msgstore.db  msgstore.db-wal  msgstore.db-shm
```

База `msgstore.db` — это **SQLite** (встраиваемая база данных в одном файле; её понимают все инструменты). Рядом лежат `-wal` и `-shm` — вспомогательные файлы журнала. Их **обязательно копировать вместе** с базой: в WAL могут лежать самые свежие (и удалённые) записи.

## Шаг 1: осматриваем базу

Работаем **с копией**, не с оригиналом: открытие SQLite может изменить файл. Смотрим таблицы и структуру:

```bash
$ sqlite3 msgstore.db ".tables"
$ sqlite3 msgstore.db ".schema message"
```

Достаём последние сообщения:

```bash
$ sqlite3 -header -column msgstore.db \
  "select remote_jid, datetime(timestamp/1000,'unixepoch'), text from message order by timestamp desc limit 3;"
4915112345678@s.whatsapp.net|2024-03-01 22:15:00|встречаемся в 22:30
4915112345678@s.whatsapp.net|2024-03-01 22:16:10|пароль от архива: hunter2
```

Обратите внимание на время: WhatsApp хранит `timestamp` в **миллисекундах**, поэтому делим на 1000 перед `unixepoch`. И вот важное: в переписке — **пароль от архива**.

## Шаг 2: находим вложение

Метаданные (кому, когда) — в базе, а сам файл — отдельно. Вложения WhatsApp лежат в `Media/`:

```bash
$ ls "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents/"
report.pdf  archive.zip
$ file "Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents/archive.zip"
... Zip archive data
```

Мы восстановили сообщение с паролем и вложение — архив, который этим паролем можно распаковать. База сообщений + вложения + кэш вместе дают полную картину переписки.

## Шаг 3: восстановление удалённых сообщений

Удалённые строки не всегда исчезают физически. Они могут остаться в:

- **WAL-файле** — последние незакоммиченные изменения.
- **Freelist** — свободные страницы до операции `VACUUM`.

Инструмент `undark` пытается восстановить их:

```bash
$ pip install undark
$ undark -i msgstore.db -o recovered.db
$ sqlite3 recovered.db "select count(*) from message;"
```

Проверить, есть ли что восстанавливать, можно так:

```bash
$ sqlite3 msgstore.db "PRAGMA page_count; PRAGMA freelist_count;"
```

## Шаг 4: шифрование и ключи

Многие базы зашифрованы, но это не приговор — ключ часто доступен при root или в бэкапе:

| Мессенджер | База | Шифрование | Ключ |
|------------|------|------------|------|
| WhatsApp | `msgstore.db` | crypt14 (опц.) | файл `key` |
| Signal | `signal.db` | SQLCipher | Keychain/SharedPreferences |
| Telegram | `cache4.db` | да | `tgnet.dat` |

```bash
# WhatsApp: расшифровать msgstore
$ python3 wa-crypt-tools.py decrypt14 key msgstore.db.crypt14 msgstore.db
```

Без ключа остаётся анализ метаданных (размеры, время, участники) и кэшей.

## Шаг 5: iOS и автоматизация

В iOS-бэкапе имена файлов **хешированы**, а связывает их с путями индекс `Manifest.db`:

```bash
$ sqlite3 Manifest.db "select fileID, domain, relativePath from Files where relativePath like '%msgstore%';"
```

Чтобы не разбирать сотни баз вручную, используют `ALEAPP` (Android) и `iLEAPP` (iOS) — они автоматически обрабатывают извлечённую ФС и создают HTML-отчёт:

```bash
$ python3 -m aleapp -t fs -i /evidence/android_fs -o /evidence/aleapp_out
```

Особо ценен на iOS `knowledgeC.db` — база активности CoreDuet: какие приложения использовались и когда. Даты iOS отсчитываются от **2001 года**: к значению прибавляют `978307200` для перевода в Unix-время.

## Полный разбор: от базы к переписке

Соберём разбор базы WhatsApp в один сценарий.

1. **Находим базу.** В песочнице приложения: `data/data/com.whatsapp/databases/msgstore.db` (или в бэкапе iOS).
2. **Смотрим схему.** Прежде чем писать запросы, узнаём таблицы:
   ```sql
   sqlite> .tables
   message  chat  jid  message_media  ...
   ```
3. **Выгружаем переписку.** Соединяем сообщения с чатами и отправителями:
   ```sql
   sqlite> SELECT chat.jid_row_id, message.from_me, message.text_data, message.timestamp
      ...> FROM message JOIN chat ON message.chat_row_id = chat._id
      ...> ORDER BY message.timestamp DESC LIMIT 5;
   ```
4. **Сопоставляем вложение.** Таблица `message_media` хранит путь к файлу, `file_path` в песочнице. Связываем `message_id` → файл.
5. **Восстанавливаем удалённое.** В `message` есть записи с `status`/флагом удаления; освобождённые страницы достаём из `msgstore.db` и из `-wal`/`-shm`.

Итог: из одного файла `msgstore.db` восстанавливается конкретная переписка с временем и вложениями.

## Шпаргалка по SQLite мессенджеров

| Приложение | Файл базы | Особенность |
|------------|-----------|-------------|
| WhatsApp | `msgstore.db` | WAL, часто без шифрования на Android |
| Telegram | `cache4.db` | своя схема, шифрование опционально |
| Signal | `signal.db` | SQLCipher (нужен ключ) |
| Viber | `viber.db` | открытая SQLite |

Полезные приёмы: `.schema message` (структура), `.mode line`, `PRAGMA wal_checkpoint` — чтобы увидеть свежие записи из WAL.

## Частые вопросы

**Почему база «пустая», хотя переписка есть?** Данные ещё в `-wal`-журнале; откройте базу вместе с ним или сделайте checkpoint.

**Чем отличаются базы Android и iOS?** На iOS те же SQLite лежат внутри iTunes-бэкапа (часто с ключом), на Android — в песочнице приложения (нужен root или backup).

**Как быть с шифрованием (Signal/SQLCipher)?** Ключ хранится отдельно (keychain, shared prefs). Без ключа база — набор шума.

**Восстановление удалённого — это надёжно?** Не всегда: освобождённые страницы могут быть перезаписаны. Фиксируйте, что нашли, и не обещайте больше, чем есть.

## Что мы теперь знаем

- База сообщений + вложения + кэш = полная картина переписки.
- Работайте **с копией** базы: открытие SQLite может изменить файл.
- Не забывайте `-wal`/`-shm` — там свежие и удалённые записи.
- Шифрование не приговор: ключ часто доступен при root/бэкапе.
- В iOS-бэкапе пути восстанавливает `Manifest.db`; iOS-эпоха — 2001 год.
- `ALEAPP`/`iLEAPP` автоматизируют разбор артефактов.

## На что смотреть дальше: геолокация и активность

Кроме переписки, в приложениях много других артефактов:

- **Геолокация.** iOS хранит её в `cache.sqlite`/`routing.db`, Android — в базах `com.google.android.gms`; фото — в EXIF. Координаты наносят на карту и сопоставляют со временем:

```bash
$ exiftool -r -GPSLatitude -GPSLongitude -csv /evidence/media > gps.csv
```

- **Активность iOS.** `knowledgeC.db` — база CoreDuet: какие приложения использовались и когда, уведомления, зарядка. Один из богатейших источников таймлайна.

Сводка по платформам:

| Платформа | Артефакт | Путь |
|-----------|----------|------|
| Android | SMS | `mmssms.db` |
| Android | Звонки/контакты | `contacts2.db` |
| iOS | SMS/iMessage | `sms.db` |
| iOS | Звонки | `CallHistory.storedata` |
| iOS | Активность | `knowledgeC.db` |

Не забывайте про несколько аккаунтов (multi-account мессенджеры хранят разные базы) и кэш: превью медиа может остаться даже после удаления сообщения.

## Квиз

Проверь себя.

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
- question: "От какой даты отсчитывается время в артефактах iOS?"
  options:
    - "1970-01-01"
    - "2001-01-01"
    - "1601-01-01"
    - "2000-01-01"
  answer: 1
  explanation: "iOS использует эпоху 2001 года; прибавляют 978307200 для Unix-времени."
```

## Куда дальше

Мы научились восстанавливать переписку из баз приложений. В следующем уроке (`forensics-memory-malware`) вернёмся к памяти и разберём охоту на **малварь без файла** — инжектированный код, который виден только в дампе RAM. А пока главное запомни: **база + вложения + WAL = переписка; работай с копией и ищи ключ шифрования**.

## Где пригодится

- **CTF:** задачи с базами мессенджеров.
- **Mobile Forensics:** восстановление переписки и вложений.
- **IR:** анализ коммуникации фигурантов.
- **Судебная экспертиза:** доказательство сообщений и передачи файлов.
