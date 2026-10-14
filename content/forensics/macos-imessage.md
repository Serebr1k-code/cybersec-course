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
