---
id: web-server-logs
title: 'Логи веб-сервера: чтение, фильтрация и аномалии'
category: forensics
parent: forensics-web-attack
difficulty: medium
order: 1
tags: [forensics, web, logs, access-log, apache, nginx]
prerequisites: [forensics-web-forensics]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как читать access/error-логи веб-сервера: формат, фильтрация, выявление атак и корреляция.'
lab:
  kind: shell
  title: 'Практика: Логи веб-сервера'
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

Веб-сервер оставил гигабайты `access.log`. Где среди них атака? Нужен метод, а не
перелистывание. Разберём.

## Наш пример: access.log

## Шаг 1: формат

Стандарт (combined):

```
$ tail -1 /var/log/nginx/access.log
203.0.113.5 - - [14/Jan/2026:03:20:00 +0000] "GET /admin.php?id=1 HTTP/1.1" 200 1234 "-" "sqlmap/1.7"
```

Поля: IP, время, запрос, статус, размер, referer, **User-Agent**. UA `sqlmap` — уже
сигнал.

## Шаг 2: фильтрация

```
$ awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
  9000 203.0.113.5
```

Один IP с 9000 запросами — брутфорс/сканирование.

## Шаг 3: ищем атаки

```
$ grep -iE 'union.*select|<script|\.\./|/etc/passwd' access.log | head
```

Паттерны SQLi, XSS, path traversal видны прямо в URL.

```
$ grep -E ' (4[0-9]{2}|5[0-9]{2}) ' access.log | wc -l
```

## Шаг 4: ошибки

`error.log` содержит детали:

```
$ tail -3 /var/log/nginx/error.log
... PHP Fatal error: ... in /var/www/.../shell.php
```

Ошибки выдают путь к шеллу.

## Шаг 5: корреляция

- сопоставь IP с другими логами (auth, firewall);
- найди первый запрос атакующего (точка входа);
- проверь, что было загружено (POST на upload).

## Что мы теперь знаем

- Формат: IP, время, запрос, статус, UA.
- Агрегация по IP выявляет брутфорс.
- Паттерны атак видны в URL.
- error.log выдаёт пути и ошибки.
- Корреляция даёт точку входа.

## Если не сработало

- Логи ротированы? Проверь `.1`, `.gz`.
- Нет access.log? Смотри логи прокси/шлюза.
- Нужны тела POST? Включи отдельное логирование.

## Квиз

Проверь себя.

```quiz
- question: Что содержит access.log?
  options:
    - 'только ошибки'
    - 'IP, время, запрос, статус, UA'
    - 'пароли'
    - 'обои'
  answer: 1
  explanation: 'Combined-формат фиксирует запрос и клиента.'
- question: Как найти брутфорс?
  options:
    - 'по цвету'
    - 'агрегацией по IP (uniq -c)'
    - 'по размеру'
    - 'никак'
  answer: 1
  explanation: 'Один IP с массой запросов выделяется агрегацией.'
- question: Что искать в error.log?
  options:
    - 'погоду'
    - 'пути к файлам и ошибки PHP'
    - 'обои'
    - 'шрифты'
  answer: 1
  explanation: 'Ошибки раскрывают пути, включая шеллы.'
- question: Что даёт корреляция логов?
  options:
    - 'красоту'
    - 'точку входа и связь с другими событиями'
    - 'ускорение'
    - 'шифрование'
  answer: 1
  explanation: 'Сопоставление логов восстанавливает цепочку атаки.'
```
