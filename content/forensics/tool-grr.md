---
id: tool-grr
title: 'GRR: удалённый live-осмотр'
category: forensics
parent: forensics-tools-open
difficulty: hard
order: 4
tags: [forensics, tools, grr, rapid-response, fleet]
prerequisites: [forensics-tooling]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как GRR (Google Rapid Response) проводит удалённый live-осмотр хостов: агенты, flows, сбор и анализ.'
lab:
  kind: shell
  title: "Практика: flow-и GRR"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, grr_flows.json]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "GRR запускает на хостах «flows» — единицы работы агента."
    - "Стандартные flow: ListProcesses, FileFinder, GetFile."
    - "`grep nto grr_flows.json > answer.txt`."
---

## Вопрос, с которого всё начинается

Нужно осмотреть хост в другой стране, не выезжая. **GRR** — платформа удалённого
live-ответа: агенты на хостах, сервер управления, «flows» для сбора. Разберём.

## Наш пример: удалённый хост

## Шаг 1: архитектура

GRR: **агенты** на хостах + **фронтенд/сервер**. Агент постоянно подключён к серверу
и ждёт задач.

## Шаг 2: flows

Действие в GRR — это **flow** (поток):

- `ListProcesses` — список процессов;
- `ListDirectory` — каталог;
- `GetFile` — скачать файл;
- `MemoryDump` — снять память;
- `Timeline` — построить таймлайн.

Запускаешь flow → получаешь результат на сервере.

## Шаг 3: сбор

```
Flow: FileFinder
  path: /var/log
  → collected 124 files
```

GRR может собирать файлы по шаблонам, сохраняя структуру и метаданные.

## Шаг 4: анализ

Результаты:

- **клиентские артефакты** (client-side search);
- скачанные файлы;
- таймлайны.

Интегрируется с YARA для сканирования на хосте.

## Шаг 5: применение

- **масштабный live-ответ**;
- **удалённый сбор** без выезда;
- **мониторинг** подозрительной активности;
- **охота** по индикаторам.

## Что мы теперь знаем

- GRR = агенты + сервер.
- Flows — единицы работы (процессы, файлы, память).
- Собирает файлы по шаблонам с метаданными.
- Интегрируется с YARA.
- Для масштабного удалённого ответа.

## Если не сработало

- Агент offline? Жди подключения/проверь сеть.
- Нужен свой сбор? Комбинируй flows.
- Нужны артефакты? Используй client-side search.

## Квиз

Проверь себя.

```quiz
- question: Что такое GRR?
  options:
    - 'игра'
    - 'платформа удалённого live-осмотра'
    - 'формат образа'
    - 'шифр'
  answer: 1
  explanation: 'GRR — Google Rapid Response для удалённой форензики.'
- question: Что такое flow в GRR?
  options:
    - 'сетевой поток'
    - 'единица работы (сбор процессов, файлов, памяти)'
    - 'пароль'
    - 'образ'
  answer: 1
  explanation: 'Flows выполняют конкретные задачи на хосте.'
- question: Как GRR собирает файлы?
  options:
    - 'только вручную'
    - 'по шаблонам через FileFinder'
    - 'никак'
    - 'по email'
  answer: 1
  explanation: 'FileFinder собирает файлы по маскам, сохраняя структуру.'
- question: С чем интегрируется GRR для сканирования?
  options:
    - 'Photoshop'
    - 'YARA'
    - 'Excel'
    - 'nmap'
  answer: 1
  explanation: 'YARA-сканирование выполняется прямо на хосте.'
```
