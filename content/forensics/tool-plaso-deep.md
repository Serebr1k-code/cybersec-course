---
id: tool-plaso-deep
title: 'plaso: супертаймлайн из сотен артефактов'
category: forensics
parent: forensics-tools-open
difficulty: medium
order: 1
tags: [forensics, tools, plaso, timeline, log2timeline]
prerequisites: [forensics-tooling]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как plaso строит супертаймлайн: сбор из множества артефактов, psort и работа с результатом.'
lab:
  kind: shell
  title: "Практика: событие в супертаймлайне plaso"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, plaso_timeline.csv]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "plaso собирает артефакты в единый таймлайн; psort печатает CSV."
    - "Персистентность на Windows — прежде всего Run-ключи (`win:runkey`)."
    - "`grep nto plaso_timeline.csv > answer.txt`."
---

## Вопрос, с которого всё начинается

У тебя образ Windows с десятками типов артефактов. Как собрать **единый** таймлайн,
где события из реестра, EVTX, MFT и браузера стоят рядом? Ответ — **plaso** (бывший
log2timeline). Разберём.

## Наш пример: образ Windows

## Шаг 1: что делает plaso

plaso собирает временные метки из **сотен** артефактов и приводит к общему формату:

- файловая система (MFT, USN);
- реестр (Shellbags, UserAssist);
- журналы событий (EVTX);
- браузеры, prefetch, LNK;
- метаданные файлов.

## Шаг 2: сбор

```
$ log2timeline.py --storage-file timeline.plaso /evidence/disk.E01
```

Он проходит по образу и извлекает события в хранилище `.plaso`. Это долгий этап.

## Шаг 3: фильтрация

Сырой таймлайн огромен. Фильтруем:

```
$ psort.py -o l2tcsv -w timeline.csv timeline.plaso "date > '2026-01-14 03:00:00' and date < '2026-01-14 04:00:00'"
```

Так получаем только окно инцидента — то, что реально нужно.

## Шаг 4: анализ

Результат открывают в **Timesketch** (веб) или разбирают CSV:

```
datetime,source,type,description
2026-01-14 03:28:11,WEBHIST,Safari,https://203.0.113.5/
```

События разных источников стоят рядом — видна причинно-следственная связь.

## Шаг 5: практика

- сначала **собери** всё;
- потом **фильтруй** по времени/источнику;
- ищи **аномалии** и цепочки;
- помни про **часовые пояса** и расхождения часов.

## Что мы теперь знаем

- plaso строит единый таймлайн из сотен артефактов.
- `log2timeline.py` собирает, `psort.py` фильтрует.
- Фильтр по времени/источнику — обязателен.
- Timesketch визуализирует.
- Часовые пояса надо учитывать.

## Если не сработало

- Сбор падает? Разбей образ на части.
- Таймлайн пуст? Проверь поддержку ФС.
- Нужна визуализация? Загрузи в Timesketch.

## Квиз

Проверь себя.

```quiz
- question: Что делает plaso/log2timeline?
  options:
    - 'шифрует диск'
    - 'собирает единый таймлайн из артефактов'
    - 'сканирует сеть'
    - 'удаляет файлы'
  answer: 1
  explanation: 'plaso извлекает временные метки из множества источников.'
- question: Какая команда фильтрует таймлайн?
  options:
    - 'log2timeline.py'
    - 'psort.py'
    - 'grep'
    - 'nmap'
  answer: 1
  explanation: 'psort.py фильтрует и экспортирует хранилище .plaso.'
- question: Почему сырой таймлайн фильтруют?
  options:
    - 'он красивый'
    - 'он огромен, нужен только интервал инцидента'
    - 'он зашифрован'
    - 'он пуст'
  answer: 1
  explanation: 'Фильтр по времени/источнику оставляет релевантные события.'
- question: Чем визуализируют таймлайн?
  options:
    - 'Photoshop'
    - 'Timesketch'
    - 'Excel только'
    - 'nmap'
  answer: 1
  explanation: 'Timesketch — веб-интерфейс для таймлайнов plaso.'
```
