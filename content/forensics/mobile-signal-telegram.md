---
id: mobile-signal-telegram
title: "Signal и Telegram: SQLite-хранилища и их защита"
category: forensics
parent: forensics-app-artifacts
difficulty: hard
order: 4
tags: [forensics, mobile, signal, telegram, sqlite, cache4, forensics]
prerequisites: [forensics-app-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "Mobile Forensics"
  - "DFIR / Incident Response"
estimated_minutes: 50
summary: "Чем отличаются хранилища Signal и Telegram: SQLite-базы, ключи, tdata и secret chats, и что реально можно извлечь с устройства."
lab:
  kind: shell
  title: "Практика: разбор баз Signal/Telegram"
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md, st_dump.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - 'Прочитай выгрузку: `cat st_dump.txt`.'
    - 'Вспомни prerequisite forensics-app-artifacts: базы SQLite и ключи рядом.'
    - 'Найди базы обоих мессенджеров: `grep -iE "signal|telegram" st_dump.txt`.'
    - 'Собери метку: `grep nto st_dump.txt > found.txt`.'
---

## Вопрос, с которого всё начинается

После WhatsApp у тебя на руках телефон с Signal и Telegram. Оба заявляют сильное
шифрование, оба хранят сообщения локально. Но если WhatsApp использует один формат
базы, то у этих двух всё иначе. Что именно искать на диске и где проходит граница
между «достанем» и «не достанем»?

Этот урок — продолжение разбора мессенджеров. Мы уже знаем общий принцип:
локальная база на устройстве хранит расшифрованный текст. Проверим, как он
работает у Signal и Telegram.

## Наш пример: выгрузка каталогов

Перед нами `st_dump.txt` — выдержка путей обоих приложений.

```
$ cat st_dump.txt
Signal:   /data/data/org.thoughtcrime.securesms/databases/signal.db
Signal:   /data/data/org.thoughtcrime.securesms/databases/signal.db-wal
Telegram: /data/data/org.telegram.messenger/files/cache4.db
Telegram: /data/data/org.telegram.messenger/files/tdata/
Telegram: secret chats stored separately (MTProto)
table (signal) sms (thread_id, body, date)
1  7  "встреча в 12"
1  8  "nto{s1gn4l_t3l3gr4m}"
note: signal.db uses SQLCipher; passphrase derived from device
```

Разберём каждый мессенджер отдельно.

## Шаг 1: Signal и SQLCipher

Signal хранит всё в `signal.db` — базе **SQLCipher**, то есть зашифрованном
SQLite. Ключ (passphrase) не лежит рядом в открытом виде: он выводится из
секрета, хранящегося в Android Keystore / iOS Keychain, плюс иногда из
пользовательского пароля.

Значит, для чтения `signal.db` нужно:

- устройство с ключом (рут + доступ к Keystore), либо
- разблокированное состояние + перехват ключа в памяти, либо
- пароль, если включён.

Файл `-wal` (write-ahead log) содержит самые свежие, ещё не сброшенные
сообщения — его нельзя игнорировать.

## Шаг 2: Telegram и tdata/cache4

Telegram на Android хранит данные иначе, чем Signal:

- `cache4.db` — SQLite с сообщениями, чатами, контактами (в открытом виде);
- `tdata/` — каталог с бинарными файлами сессий и ключей (в основном на desktop);
- **secret chats** — отдельные, не сохраняются в облако и хранятся зашифрованными
  локально.

Ключевое отличие: обычные (облачные) чаты Telegram доступны в `cache4.db`, а
секретные чаты защищены end-to-end и на диск почти не пишутся.

## Шаг 3: что реально извлекается

Сводка:

- **Signal**: текст в `signal.db` (SQLCipher) — нужен ключ; `-wal` содержит свежее.
- **Telegram**: обычные чаты в `cache4.db` (открыто); secret chats — нет.

Поэтому в отчёте важно различать: «извлечено» и «зашифровано, ключ недоступен».

## Шаг 4: порядок разбора

1. Найти каталоги приложений.
2. Для Signal — получить ключ SQLCipher (рут/память) или открыть незашифрованный
   бэкап.
3. Для Telegram — открыть `cache4.db` и выгрузить таблицы `messages`, `dialogs`.
4. Не забыть `-wal` и `-shm` файлы Signal.
5. Сопоставить время и контакты.

Пример выгрузки сообщений Signal:

```
$ sqlite3 signal.db 'select date, body from sms order by date'
1710148000|встреча в 12
1710148120|nto{s1gn4l_t3l3gr4m}
```

## Шаг 5: типичные ошибки

- Забыть про `-wal`: свежие сообщения окажутся «потерянными».
- Считать, что secret chats Telegram лежат в `cache4.db`: их там нет.
- Пытаться открыть `signal.db` обычным `sqlite3`: он выдаст «file is not a
  database» — это SQLCipher.

## Что мы теперь знаем

- Signal хранит данные в SQLCipher-базе `signal.db`; нужен ключ из Keystore.
- Telegram хранит обычные чаты в открытом `cache4.db`.
- Secret chats Telegram и часть данных Signal защищены сильнее.
- Файлы `-wal`/`-shm` содержат свежие данные.
- В отчёте разделяй извлечённое и зашифрованное.

## Если не сработало

- `signal.db` не открывается? Это SQLCipher — нужен ключ.
- Нет secret chats Telegram? Они не хранятся локально.
- Пропали свежие сообщения? Проверь `-wal`.

## Квиз

Проверь себя.

```quiz
- question: В каком формате база Signal?
  options:
    - 'обычный SQLite'
    - 'SQLCipher (зашифрованный SQLite)'
    - 'JSON'
    - 'CSV'
  answer: 1
  explanation: 'signal.db зашифрован SQLCipher, нужен ключ.'
- question: Что хранит cache4.db в Telegram?
  options:
    - 'только фото'
    - 'обычные чаты и сообщения'
    - 'секретные чаты'
    - 'пароли'
  answer: 1
  explanation: 'Обычные (облачные) чаты Telegram лежат в cache4.db.'
- question: Где хранятся secret chats Telegram?
  options:
    - 'в cache4.db'
    - 'не сохраняются локально в открытом виде'
    - 'в tdata'
    - 'в контактах'
  answer: 1
  explanation: 'Секретные чаты защищены end-to-end и почти не пишутся на диск.'
- question: Зачем файл -wal у Signal?
  options:
    - 'для красоты'
    - 'содержит свежие, ещё не сброшенные сообщения'
    - 'это пароль'
    - 'это лог звонков'
  answer: 1
  explanation: 'Write-ahead log содержит самые новые данные.'
- question: Что нужно, чтобы прочитать signal.db?
  options:
    - 'ничего'
    - 'ключ SQLCipher (из Keystore/памяти)'
    - 'Wi-Fi'
    - 'номер телефона'
  answer: 1
  explanation: 'Без ключа SQLCipher база не открывается.'
```

## Куда дальше

Мы разобрали мессенджеры. Дальше — облачная синхронизация: как данные попадают
на серверы iCloud/Google и как их оттуда извлекают легально. А пока запомни:
Signal — это SQLCipher, Telegram — открытый `cache4.db` плюс защищённые secret chats.

## Где пригодится

- Mobile forensics: разбор Signal и Telegram из образа телефона.
- DFIR: восстановление переговоров злоумышленников.
- CTF Forensics: задания с SQLCipher-базой и ключом рядом.
