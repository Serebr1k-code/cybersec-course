---
id: tool-osquery
title: 'osquery: SQL-запросы к состоянию хоста'
category: forensics
parent: forensics-tools-open
difficulty: medium
order: 3
tags: [forensics, tools, osquery, sql, live-response]
prerequisites: [forensics-tooling]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как osquery превращает систему в базу данных: таблицы процессов, сети, файлов и запросы к ним.'
lab:
  kind: shell
  title: 'Практика: osquery'
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

Нужно быстро узнать состояние хоста: какие процессы, соединения, автозапуск. Вместо
десятка утилит — один инструмент с **SQL**. Это **osquery**. Разберём.

## Наш пример: живой хост

## Шаг 1: идея

osquery представляет ОС как **базу данных**: процессы, сокеты, файлы, пользователи,
реестр — это таблицы. Ты пишешь SQL:

```sql
SELECT pid, name, path FROM processes WHERE name = 'sshd';
```

## Шаг 2: полезные таблицы

- `processes` — процессы;
- `listening_ports` — открытые порты;
- `logged_in_users` — кто вошёл;
- `startup_items` — автозапуск;
- `users`, `groups`.

```
osquery> SELECT * FROM listening_ports WHERE port = 4444;
```

Порт 4444 — типичный бэкдор.

## Шаг 3: форензика

Типовые запросы:

```sql
-- процессы из /tmp
SELECT * FROM processes WHERE path LIKE '/tmp/%';
-- соединения к внешним адресам
SELECT * FROM process_open_sockets WHERE remote_address != '';
```

Так быстро выявляешь подозрительное.

## Шаг 4: флот

osquery может работать как **агент** с централизованной конфигурацией: один запрос —
на тысячи хостов. Это делает его частью live-DFIR.

## Шаг 5: ограничения

- это **снимок состояния**, не история;
- данные можно подделать (руткит);
- требует прав.

osquery дополняют логированием (диффы по расписанию).

## Что мы теперь знаем

- osquery даёт SQL-доступ к системе.
- Таблицы: процессы, порты, пользователи, автозапуск.
- Запросы выявляют аномалии.
- Работает на флоте как агент.
- Это снимок, а не история.

## Если не сработало

- Нужна история? Включи логирование/диффы.
- Таблица недоступна? Проверь ОС/версию.
- Нужны удалённые хосты? Разверни агент.

## Квиз

Проверь себя.

```quiz
- question: Что такое osquery?
  options:
    - 'антивирус'
    - 'инструмент SQL-запросов к состоянию ОС'
    - 'шифрование'
    - 'сканер портов'
  answer: 1
  explanation: 'osquery представляет систему как базу данных.'
- question: Какая таблица покажет открытые порты?
  options:
    - 'users'
    - 'listening_ports'
    - 'groups'
    - 'files'
  answer: 1
  explanation: 'listening_ports содержит слушающие сокеты.'
- question: Что даёт запрос к processes с path LIKE /tmp/%?
  options:
    - 'пароли'
    - 'процессы, запущенные из /tmp (часто вредоносные)'
    - 'маршруты'
    - 'обои'
  answer: 1
  explanation: 'Запуск из /tmp — типичный признак малвари.'
- question: Чем osquery ограничен?
  options:
    - 'нет ограничений'
    - 'это снимок состояния, а не история'
    - 'только Windows'
    - 'только сеть'
  answer: 1
  explanation: 'Для истории нужны логирование и диффы.'
```
