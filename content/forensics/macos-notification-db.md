---
id: macos-notification-db
title: 'База уведомлений macOS: тексты тостов и их источники'
category: forensics
parent: forensics-macos-artifacts-deep
difficulty: medium
order: 3
tags: [macos, notifications, usernoted, sqlite, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 40
summary: 'Как читать record.db уведомлений macOS: восстановить тексты тостов, приложения-источники и время.'
lab:
  kind: shell
  title: 'Практика: База уведомлений macOS'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Пользователю приходили уведомления — от почты, мессенджеров, приложений. macOS хранит
их историю в базе **usernoted**. Для расследования это золото: в тостах видны
сообщения, имена, коды, даже одноразовые пароли. Разберём, как их достать.

## Наш пример: база уведомлений

## Шаг 1: находим базу

```
$ ls ~/Library/Group\ Containers/group.com.apple.usernoted/db2/
db  db-shm  db-wal
```

Основная база — `db`, рядом WAL-журнал (свежие изменения могут быть ещё в нём).

## Шаг 2: смотрим таблицы

```
$ sqlite3 db '.tables'
app  app_metadata  dbinfo  record
```

Таблица `record` — сами уведомления, `app` — приложения-источники.

## Шаг 3: извлекаем уведомления

```
$ sqlite3 db 'SELECT a.identifier, r.data FROM record r JOIN app a ON a.app_id=r.app_id LIMIT 5;'
com.apple.mail|bplist00...Your code is 482913...
com.apple.iChat|bplist00...Meeting at 15:00...
```

Поле `data` — бинарный plist. Прочитаем его:

```
$ plutil -p data.bin | grep -i 'body\|title'
"body" => "Your code is 482913"
"title" => "Verification"
```

## Шаг 4: время и источник

Время в `record` — Apple epoch. Приложение-источник даёт контекст: уведомление от
`com.apple.mail` — это почта, от `com.apple.iChat` — сообщения.

```
$ sqlite3 db 'SELECT datetime(delivered_date+978307200,"unixepoch"), app_id FROM record ORDER BY delivered_date DESC LIMIT 3;'
2026-01-14 03:31:02|42
```

## Шаг 5: что искать

Уведомления раскрывают:

- коды двухфакторной аутентификации;
- имена отправителей и темы;
- названия файлов/ссылок;
- ошибки приложений.

Это часто быстрее, чем разбирать сами приложения.

## Что мы теперь знаем

- Уведомления хранятся в `record.db` (Group Containers/usernoted).
- `record.data` — бинарный plist с текстом тоста.
- `plutil -p` превращает его в читаемый вид.
- Время — Apple epoch (+978307200).
- Тексты могут содержать OTP, имена, ссылки.

## Если не сработало

- База пуста? Проверь WAL (`db-wal`) — свежие записи там.
- Нужны вложения? Смотри соседние каталоги Group Containers.
- База зашифрована? На современных macOS часть данных защищена — нужен доступ
  пользователя.

## Квиз

Проверь себя.

```quiz
- question: Где macOS хранит историю уведомлений?
  options:
    - 'в /etc/hosts'
    - 'в record.db (usernoted)'
    - 'в /boot'
    - 'в /var/log'
  answer: 1
  explanation: 'База уведомлений лежит в group.com.apple.usernoted.'
- question: Что содержит поле data записи уведомления?
  options:
    - 'пароль диска'
    - 'бинарный plist с текстом тоста'
    - 'IP-адрес'
    - 'размер файла'
  answer: 1
  explanation: 'data — это bplist с title/body уведомления.'
- question: Чем полезны уведомления в расследовании?
  options:
    - 'они занимают место'
    - 'могут содержать OTP, имена и ссылки'
    - 'они шифруют диск'
    - 'они ускоряют систему'
  answer: 1
  explanation: 'В текстах тостов часто попадаются коды и контакты.'
- question: Где искать самые свежие записи, если базы «нет»?
  options:
    - 'в db-wal'
    - 'в /tmp'
    - 'в реестре'
    - 'в /etc/passwd'
  answer: 0
  explanation: 'WAL-журнал SQLite хранит не зафиксированные изменения.'
```
