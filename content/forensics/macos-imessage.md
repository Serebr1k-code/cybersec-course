---
id: macos-imessage
title: 'iMessage-форензика: переписка, вложения и адресаты'
category: forensics
parent: forensics-macos-artifacts-deep
difficulty: hard
order: 6
tags: [macos, imessage, chat, sqlite, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 55
summary: 'Как читать chat.db iMessage: сообщения, вложения, время и участники переписки.'
lab:
  kind: shell
  title: "Практика: чат iMessage"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, imessage_chat.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "chat.db хранит сообщения в таблице message (text, handle, date)."
    - "Незнакомый номер с текстом-меткой — зацепка."
    - "`grep nto imessage_chat.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Расследуется инцидент, и ключевые указания пришли в переписке. iMessage хранит всё в
одной базе `chat.db`. Но её структура неочевидна, а время в особом формате. Разберём,
как достать сообщения.

## Наш пример: база chat.db

## Шаг 1: находим базу

```
$ ls ~/Library/Messages/chat.db
-rw-r--r-- 1 user staff 1048576 Jan 14 03:35 chat.db
```

## Шаг 2: таблицы

```
$ sqlite3 chat.db '.tables'
chat  handle  message  message_attachment_join  attachment  ...
```

- `handle` — участники (номера, email);
- `message` — сами сообщения;
- `attachment` — вложения;
- `chat` — диалоги.

## Шаг 3: читаем сообщения

```
$ sqlite3 chat.db 'SELECT datetime(date/1000000000+978307200,"unixepoch"), is_from_me, text FROM message ORDER BY date DESC LIMIT 5;'
2026-01-14 03:33:02|0|Переведи на счёт 203.0.113.5
2026-01-14 03:30:11|1|ok
```

Важно: время в `chat.db` — Apple epoch **в наносекундах**, поэтому делим на
`1000000000`. `is_from_me=1` — исходящее, `0` — входящее.

## Шаг 4: связываем с участниками

```
$ sqlite3 chat.db 'SELECT h.id, m.text FROM message m JOIN handle h ON h.ROWID=m.handle_id LIMIT 3;'
+15551234567|Переведи на счёт...
```

Так видно, кто отправил каждое сообщение.

## Шаг 5: вложения

```
$ sqlite3 chat.db 'SELECT a.filename, a.transfer_name FROM attachment a;'
~/Library/Messages/Attachments/.../photo.jpg|photo.jpg
```

Вложения лежат в `~/Library/Messages/Attachments/`. По `transfer_name` и пути
восстанавливаешь, что пересылали. Проверь и удалённые вложения — ссылки в базе могут
сохраниться.

## Что мы теперь знаем

- `chat.db` — единая база iMessage.
- Таблицы: handle (участники), message (сообщения), attachment (файлы).
- Время в наносекундах Apple epoch: `date/1e9 + 978307200`.
- `is_from_me` различает входящие и исходящие.
- Вложения — в `~/Library/Messages/Attachments/`.

## Если не сработало

- База защищена? На современных macOS нужен доступ с правами пользователя (Full Disk
  Access).
- Нужны удалённые сообщения? Смотри WAL (`chat.db-wal`) и бэкапы iPhone.
- Вложение удалено? Ищи по хешу в других местах.

## Разбор chat.db по шагам

Начинаем с инвентаризации схемы — так видно, какие таблицы и поля доступны:

```
$ sqlite3 chat.db '.schema message'
CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, text TEXT,
  handle_id INTEGER, date INTEGER, is_from_me INTEGER, ...);
```

Поле `date` хранит время в наносекундах Apple epoch (с 2001-01-01), `text` —
тело сообщения, `handle_id` — ссылку на участника, `is_from_me` — направление.
Дальше читаем сами сообщения:

```
$ sqlite3 chat.db 'SELECT datetime(date/1000000000+978307200,"unixepoch") t,
    is_from_me, text FROM message ORDER BY date DESC LIMIT 4;'
2026-01-14 03:33:02|0|Переведи на счёт 203.0.113.5
2026-01-14 03:30:11|1|ok
2026-01-14 03:28:40|0|реквизиты скину
2026-01-14 03:20:00|1|принял
```

Формула времени обязательна: без неё `date` выглядит как огромное число и
ничего не значит.

## Таблица: таблицы и поля chat.db

| Таблица | Ключевые поля | Что даёт |
|---|---|---|
| `handle` | id, service | участники (номер, email) |
| `message` | text, date, is_from_me, handle_id | сообщения |
| `chat` | chat_identifier, display_name | диалоги/группы |
| `chat_message_join` | chat_id, message_id | привязка к диалогу |
| `attachment` | filename, transfer_name | вложения |
| `message_attachment_join` | message_id, attachment_id | связь сообщение↔файл |

Связка `message` → `chat_message_join` → `chat` позволяет восстановить
**контекст**: в каком диалоге (личном или групповом) шло обсуждение.

## Работа с WAL и удалёнными сообщениями

SQLite пишет через WAL-журнал, и в нём могут лежать уже «удалённые» строки:

```
$ ls -la ~/Library/Messages/
chat.db      chat.db-wal      chat.db-shm
$ sqlite3 chat.db "PRAGMA wal_checkpoint;"
```

После checkpoint удалённые записи иногда остаются в свободных страницах. Для
восстановления используют `sqlite3_recover` или парсинг неразмеченных страниц
утилитами вроде `undark`. Также проверь резервные копии iPhone — там
сохранится история за месяцы.

## Пример: разбор переписки с вложением

Связываем сообщение и отправленный файл:

```
$ sqlite3 chat.db 'SELECT m.text, a.filename FROM message m
    JOIN message_attachment_join maj ON maj.message_id=m.ROWID
    JOIN attachment a ON a.ROWID=maj.attachment_id LIMIT 3;'
смотри файл|~/Library/Messages/Attachments/.../invoice.pdf
```

Файл лежит по пути из `filename`. Если он удалён из файловой системы, ссылка
в базе всё равно указывает на него — можно восстановить по хешу из бэкапа или
найти в других местах.

## Если сработало

Нашёл криминально значимую переписку — фиксируй доказательства:

1. Выгрузи выборку сообщений с временем и участниками в CSV.
2. Сохрани копию `chat.db` и её хеш (работай только с копией).
3. Проверь WAL и бэкапы на удалённые сообщения.
4. Восстанови вложения по путям и хешам.
5. Сопоставь участников (`handle.id`) с известными контактами.

Копию делай до любых запросов: даже чтение может запустить checkpoint и
изменить WAL, лишив тебя «удалённых» строк.

## Ограничения и подводные камни

- **Full Disk Access.** На современных macOS база защищена TCC; без прав
  доступа файл не прочитать.
- **Зашифрованный бэкап.** Бэкап iPhone/iCloud может быть зашифрован — нужен
  пароль.
- **Обрезанные вложения.** Файлы могли быть удалены или выгружены в iCloud
  (тогда локально только заглушка).
- **Часовой пояс.** `datetime` даёт UTC; для отчёта переводи в местное время.
- **Несколько устройств.** Одно сообщение синхронизируется на iPhone, iPad и
  Mac — базы могут различаться полнотой.

## Практика: SQL-запросы к chat.db

`chat.db` — это SQLite, и почти все вопросы решаются парой запросов. Ниже — рабочие
запросы, которые стоит держать под рукой.

Список последних сообщений с датой и адресатом:

```
$ sqlite3 chat.db \
 "SELECT datetime(message.date/1000000000 + 978307200,'unixepoch','localtime') AS t,
         handle.id, message.text
  FROM message JOIN handle ON message.handle_id = handle.ROWID
  WHERE message.is_from_me = 0 ORDER BY message.date DESC LIMIT 10;"
2024-11-03 22:14:02  +79990001122  скинь файл на почту
```

Дата в `message.date` — это **наносекунды от 2001-01-01** (эпоха Apple), поэтому и нужна
формула `date/1000000000 + 978307200`. Забыть про неё — типичная ошибка новичка: время
уезжает на десятилетия.

## Таблица: таблицы и поля chat.db

| Таблица | Ключевые поля | Что даёт |
|---|---|---|
| `message` | `date`, `text`, `is_from_me`, `handle_id` | сами сообщения |
| `handle` | `id`, `service` | адресаты (номер/Apple ID) |
| `chat` | `guid`, `display_name` | группы и их имена |
| `chat_message_join` | `chat_id`, `message_id` | связь сообщения с чатом |
| `attachment` | `filename`, `transfer_name`, `mime_type` | вложения |
| `message_attachment_join` | `message_id`, `attachment_id` | связь сообщения с файлом |

Через `chat_message_join` восстанавливается **групповая переписка**: одно сообщение может
относиться к нескольким чатам, и без связи «сообщение↔чат» картина неполна.

## Работа с WAL и удалёнными сообщениями

SQLite в режиме **WAL** (write-ahead log) пишет новые транзакции в отдельный файл
`chat.db-wal`, а `chat.db-shm` хранит индекс. Свежие сообщения могут лежать **только** в
WAL, ещё не перенесённые в основную базу. Поэтому:

```
$ ls -la chat.db*
-rw-r--r--  chat.db
-rw-r--r--  chat.db-wal
-rw-r--r--  chat.db-shm
$ sqlite3 chat.db "PRAGMA wal_checkpoint(FULL);"   # слить WAL в основную базу
```

Копируй **все три** файла вместе — иначе потеряешь последние сообщения. Удалённые сообщения
иногда остаются в свободных страницах (`freelist`) или в WAL; их достают карвингом:

```
$ strings -a chat.db-wal | grep -i 'nto{\|password\|пароль'
```

## Пример: разбор переписки с вложением

Соберём полную картину «сообщение → адресат → вложение»:

```
$ sqlite3 chat.db \
 "SELECT datetime(m.date/1000000000+978307200,'unixepoch') t, h.id,
         m.text, a.transfer_name, a.filename
  FROM message m
  JOIN handle h ON m.handle_id=h.ROWID
  LEFT JOIN message_attachment_join maj ON m.ROWID=maj.message_id
  LEFT JOIN attachment a ON maj.attachment_id=a.ROWID
  WHERE m.text LIKE '%файл%';"
2024-11-03 22:14:02  +79990001122  скинь файл на почту  payroll.xlsx  ~/Library/.../payroll.xlsx
```

Строка `filename` показывает **где физически лежит вложение** в образе macOS — по этому
пути его и забирают. Если файла по пути уже нет (удалён), остаётся `transfer_name` и
метаданные, по которым ведут поиск карвингом.

## Ограничения и подводные камни

- **iMessage шифруется сквозным (E2E).** На диске ты видишь уже расшифрованное сообщение
  (у отправителя/получателя), но перехватить трафик и прочитать без ключей нельзя.
- **Синхронизация через iCloud.** Часть сообщений может быть только в облаке и
  синхронизироваться по требованию — тогда на диске их нет.
- **`is_from_me` не отличает устройство.** Сообщение «своё» и на iPhone, и на Mac;
  авторство определяют по другим артефактам.
- **База меняется на лету.** Пока устройство включено, новые сообщения пишутся; снимай
  образ **на выключенном** устройстве или в режиме только-чтения, иначе данные изменятся.

## Связь с другими артефактами macOS

`chat.db` редко анализируют в одиночку — её ценность растёт в связке:

- **`AddressBook`** — контакты: превращает номера в имена.
- **`CallHistory.storedata`** — звонки: сопоставление с перепиской по времени.
- **`KnowledgeC.db`** — активность приложений: когда открывали Messages.
- **Unified Logs** (`log show`) — системные события: запуск, ошибки, синхронизация.
- **Файлы вложений** — `~/Library/Messages/Attachments/...` — реальные документы и фото.

Собранные вместе, они отвечают на вопросы «кто», «что», «когда» и «с какого именно
устройства».
Например, `KnowledgeC.db` покажет, что Messages был активен ровно в минуту отправки
сообщения, а Unified Logs подтвердят, что в этот момент работала синхронизация iCloud.

## Квиз

Проверь себя.

```quiz
- question: Где хранится переписка iMessage?
  options:
    - 'в /etc/passwd'
    - 'в ~/Library/Messages/chat.db'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'chat.db — SQLite-база сообщений macOS.'
- question: Как перевести время message.date в unix?
  options:
    - 'умножить на 8'
    - 'date/1e9 + 978307200'
    - 'вычесть 1000'
    - 'никак'
  answer: 1
  explanation: 'date хранится в наносекундах Apple epoch.'
- question: Что означает is_from_me=0?
  options:
    - 'сообщение удалено'
    - 'входящее сообщение'
    - 'исходящее сообщение'
    - 'ошибка'
  answer: 1
  explanation: 'is_from_me=0 — сообщение получено, 1 — отправлено.'
- question: Где лежат вложения iMessage?
  options:
    - 'в /tmp'
    - 'в ~/Library/Messages/Attachments/'
    - 'в /etc'
    - 'в /boot'
  answer: 1
  explanation: 'Вложения хранятся в каталоге Attachments внутри Messages.'
```
