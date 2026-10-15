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
estimated_minutes: 45
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
