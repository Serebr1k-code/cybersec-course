---
id: web-elasticsearch
title: 'Elasticsearch-форензика: индексы, логи и утечки'
category: forensics
parent: forensics-web-apps
difficulty: medium
order: 3
tags: [forensics, web, elasticsearch, logs, data-leak]
prerequisites: [forensics-web-forensics]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как расследовать компромисс Elasticsearch: открытые индексы, аудит-логи, изменения данных и утечки.'
lab:
  kind: shell
  title: 'Практика: Elasticsearch-форензика'
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

Elasticsearch часто выставляют наружу без аутентификации — и из него утекают данные
или его используют для RCE. Разберём, где следы.

## Наш пример: Elasticsearch

## Шаг 1: открытый доступ

```
$ curl -s http://target:9200/_cat/indices?v
green open logs-2026.01.14 ...
```

Если ответ приходит без авторизации — кластер открыт. Это уже находка.

## Шаг 2: аудит-логи

Elasticsearch умеет логировать запросы (audit):

```
$ grep -i 'rest.request' /var/log/elasticsearch/audit.log | tail
```

Видно, кто и что запрашивал (в т.ч. удаление индексов).

## Шаг 3: удаление данных

Атакующий может удалить индексы (anti-forensics):

```
$ grep -i 'DELETE.*_index' audit.log | tail
```

Или перезаписать документы. Проверь целостность и бэкапы (snapshots).

## Шаг 4: RCE через скрипты

Elasticsearch позволял RCE через `script` (Groovy) и плагины:

```
$ grep -i 'script' audit.log | tail
```

Аномальные скрипт-запросы — признак эксплуатации.

## Шаг 5: что искать

- несанкционированный доступ (внешние IP);
- удаление/изменение индексов;
- скрипт-запросы;
- утечку чувствительных индексов;
- новые пользователи/роли (X-Pack).

## Что мы теперь знаем

- Открытый ES проверяется запросом без авторизации.
- Audit-лог фиксирует запросы.
- Удаление индексов — anti-forensics.
- Скрипты/плагины давали RCE.
- Смотрим доступ, изменения, скрипты.

## Если не сработало

- Аудит выключен? Смотри логи балансировщика/сети.
- Нужны данные? Восстанавливай из snapshot.
- Нужны права? Читай роли X-Pack.

## Квиз

Проверь себя.

```quiz
- question: Как проверить открытость Elasticsearch?
  options:
    - 'ping'
    - 'запрос к _cat/indices без авторизации'
    - 'grep'
    - 'ssh'
  answer: 1
  explanation: 'Ответ без аутентификации означает открытый кластер.'
- question: Что фиксирует audit-лог ES?
  options:
    - 'погоду'
    - 'запросы REST и доступ'
    - 'обои'
    - 'шрифты'
  answer: 1
  explanation: 'Audit-лог хранит rest.request события.'
- question: Что такое удаление индексов с точки зрения форензики?
  options:
    - 'норма'
    - 'anti-forensics (уничтожение данных)'
    - 'обновление'
    - 'шифрование'
  answer: 1
  explanation: 'Удаление индексов стирает данные и следы.'
- question: Как ES мог давать RCE?
  options:
    - 'через CSS'
    - 'через скрипты (Groovy) и плагины'
    - 'через обои'
    - 'никак'
  answer: 1
  explanation: 'Динамические скрипты и плагины позволяли выполнение кода.'
```
