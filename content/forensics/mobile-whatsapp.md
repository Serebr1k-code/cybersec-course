---
id: mobile-whatsapp
title: "WhatsApp форензика: msgstore.db и шифрованный Crypt15"
category: forensics
parent: forensics-app-artifacts
difficulty: hard
order: 3
tags: [forensics, mobile, whatsapp, msgstore, crypt15, sqlite, forensics]
prerequisites: [forensics-app-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "Mobile Forensics"
  - "DFIR / Incident Response"
estimated_minutes: 55
summary: "Как устроено хранилище WhatsApp: открытая база msgstore.db и её шифрованный вариант .crypt15, ключ шифрования и разбор таблиц сообщений."
lab:
  kind: shell
  title: "Практика: разбор хранилища WhatsApp"
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md, wa_dump.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - 'Прочитай выгрузку: `cat wa_dump.txt`.'
    - 'Вспомни prerequisite forensics-app-artifacts: мессенджеры хранят SQLite-базы.'
    - 'Найди таблицу сообщений: `grep -iE "message|chat" wa_dump.txt`.'
    - 'Собери метку: `grep nto wa_dump.txt > found.txt`.'
---

## Вопрос, с которого всё начинается

Тебе нужно восстановить переписку из телефона. WhatsApp — самый популярный
мессенджер, и его сообщения точно где-то лежат. Но приложение заявляет сквозное
шифрование — значит ли это, что переписку прочитать нельзя? И почему одни файлы
открываются, а другие выглядят как случайный набор байтов?

Этот урок продолжает ветку артефактов приложений. Мы уже знаем, что мессенджеры
хранят данные в SQLite-базах; теперь разберём конкретно WhatsApp.

## Наш пример: выгрузка хранилища

Перед нами `wa_dump.txt` — выдержка из каталога WhatsApp и таблицы сообщений.

```
$ cat wa_dump.txt
/data/data/com.whatsapp/databases/msgstore.db          -> plain SQLite (rooted)
/data/data/com.whatsapp/databases/msgstore.db.crypt15  -> encrypted (normal)
/data/data/com.whatsapp/files/key                       -> encryption key (rooted)
table message (key_id, from_me, text_data, timestamp)
0  1 "Привет, встречаемся в 10" 1710144000
1  0 "Ок, буду" 1710144120
2  1 "nto{wh4ts4pp_crypt15}" 1710145000
note: key file present (rooted device)
```

Разберём, что здесь происходит.

## Шаг 1: два формата базы

WhatsApp хранит сообщения в базе `msgstore.db` (SQLite). Но на обычном
(не рутованном) устройстве база лежит **зашифрованной** — `msgstore.db.crypt15`
(раньше `.crypt14`, `.crypt12`). Открытая `msgstore.db` появляется либо на
рутованном устройстве, либо после расшифровки копии.

Формат `.crypt` — это не сам SQLite, а контейнер: заголовок с версией, соль и
зашифрованное тело.

## Шаг 2: ключ шифрования

Ключ, которым расшифровывается `.crypt15`, лежит рядом — в файле `key` (на
рутованном устройстве) или выводится из данных устройства. Без этого ключа
зашифрованную базу не открыть:

```
$ head -c 32 key | xxd
00000000: 9f 3a ... (32 байта ключа)
```

Важно: «сквозное шифрование» (end-to-end) защищает сообщение **в пути** между
устройствами. Но **на самом устройстве** сообщение хранится в расшифрованном виде
(внутри защищённой базы). Поэтому извлечение с телефона даёт доступ к переписке —
это и есть ключевая мысль для следователя.

## Шаг 3: структура таблиц

Ключевые таблицы `msgstore.db`:

- `message` — сами сообщения (`text_data`, `timestamp`, `from_me`);
- `chat` — список чатов (`jid`, `subject`);
- `jid` — адресная книга (номера, имена);
- `message_media` — ссылки на вложения.

Поле `from_me` отличает отправленные (1) от принятых (0). `timestamp` — Unix-время.
По этим двум полям восстанавливается хронология диалога.

## Шаг 4: восстановление переписки

Порядок:

1. извлечь `msgstore.db` (рут) или `msgstore.db.crypt15` + `key`;
2. при необходимости расшифровать (инструменты `wa-crypt-tools`);
3. открыть SQLite и выгрузить `message` с `chat`;
4. отсортировать по `timestamp`;
5. сопоставить `jid` с именами.

Отсортированный вывод даёт готовую переписку:

```
$ sqlite3 msgstore.db 'select timestamp, from_me, text_data from message order by timestamp'
1710144000|1|Привет, встречаемся в 10
1710144120|0|Ок, буду
```

## Шаг 5: медиа и звонки

Кроме текста, WhatsApp хранит:

- медиа в `WhatsApp/Media/` (фото/видео с EXIF-геометками);
- историю звонков в таблице `call_log`;
- статусы и группы в `chat`.

Медиафайлы часто содержат метаданные (время, GPS), которые перекрёстно
подтверждают переписку.

## Что мы теперь знаем

- WhatsApp хранит сообщения в SQLite `msgstore.db`; на устройстве — как `.crypt15`.
- Ключ шифрования — в файле `key` (рут) или выводится из данных устройства.
- End-to-end шифрование защищает путь, но не данные на устройстве.
- Таблицы `message`/`chat`/`jid` дают полную переписку.
- Медиа и `call_log` дополняют картину.

## Если не сработало

- База зашифрована и нет `key`? Нужен рут или расшифровка из бэкапа.
- Нет сообщений? Проверь, не перенесена ли база в `msgstore.db.crypt14`.
- Нужны имена? Сопоставь `jid` с адресной книгой или контактами.

## Квиз

Проверь себя.

```quiz
- question: В каком файле WhatsApp хранит сообщения?
  options:
    - 'chat.db'
    - 'msgstore.db (SQLite)'
    - 'messages.txt'
    - 'wa.log'
  answer: 1
  explanation: 'msgstore.db — база сообщений WhatsApp.'
- question: Что такое msgstore.db.crypt15?
  options:
    - 'сжатая копия'
    - 'зашифрованная база'
    - 'резервная копия контактов'
    - 'лог звонков'
  answer: 1
  explanation: 'На обычном устройстве база хранится в зашифрованном контейнере.'
- question: Защищает ли end-to-end шифрование данные на устройстве?
  options:
    - 'да, полностью'
    - 'нет, на устройстве сообщение расшифровано'
    - 'только фото'
    - 'только звонки'
  answer: 1
  explanation: 'E2E защищает передачу, но локальная база хранит текст.'
- question: Какое поле отличает отправленные от принятых?
  options:
    - 'jid'
    - 'from_me'
    - 'subject'
    - 'key_id'
  answer: 1
  explanation: 'from_me=1 — отправленное, 0 — принятое.'
- question: Что нужно для расшифровки .crypt15?
  options:
    - 'пароль аккаунта'
    - 'ключ из файла key (или вывод из данных устройства)'
    - 'Wi-Fi'
    - 'номер телефона'
  answer: 1
  explanation: 'Ключ шифрования хранится в файле key на рутованном устройстве.'
```

## Куда дальше

Мы разобрали WhatsApp. Дальше — Signal и Telegram: у них свои форматы и своя
защита. А пока запомни: `msgstore.db` + файл `key` — и переписка WhatsApp у тебя
на столе.

## Где пригодится

- Mobile forensics: восстановление переписки WhatsApp из образа телефона.
- DFIR: разбор переговоров злоумышленников после инцидента.
- CTF Forensics: задания с выгрузкой `msgstore.db` и поиском флага в сообщениях.
