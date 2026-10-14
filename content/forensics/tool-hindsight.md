---
id: tool-hindsight
title: 'Hindsight: разбор истории браузеров на Chromium'
category: forensics
parent: forensics-tools-open
difficulty: medium
order: 5
tags: [forensics, tools, hindsight, browser, chromium]
prerequisites: [forensics-tooling]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 40
summary: 'Как Hindsight разбирает браузерные артефакты Chromium: история, загрузки, кэш, cookies и сессии.'
lab:
  kind: shell
  title: "Практика: история Chromium через Hindsight"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, history_export.csv]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "Hindsight разбирает `History` SQLite из профиля Chromium."
    - "Тип перехода `download` = файл сохранялся на диск."
    - "`grep nto history_export.csv > answer.txt`."
---

## Вопрос, с которого всё начинается

Нужно понять, что пользователь делал в браузере. Chrome/Edge (Chromium) хранят данные в
SQLite-базах с нетривиальной структурой (время в микросекундах от 1601). **Hindsight**
делает разбор за тебя. Разберём.

## Наш пример: профиль Chromium

## Шаг 1: что разбирает

Hindsight читает профиль и извлекает:

- **историю** (`History`);
- **загрузки** (`History` → downloads);
- **cookies** (`Cookies`);
- **сессии/вкладки** (`Sessions`, `Current Session`);
- **кэш** (Cache);
- **автозаполнение** (`Web Data`).

## Шаг 2: запуск

```
$ hindsight.py -i /evidence/Default -o /out
```

Указываешь каталог профиля (`Default`/`Profile 1`), получаешь отчёты в SQLite/JSON/CSV.

## Шаг 3: время

Chromium хранит время как **микросекунды с 1601-01-01** (Windows epoch):

```
python: datetime(1601,1,1) + timedelta(microseconds=value)
```

Hindsight конвертирует автоматически — не нужно считать руками.

## Шаг 4: что искать

- посещённые URL (особенно скачивания);
- поисковые запросы;
- cookies сессий;
- **переходы** (referrer) — откуда пришёл;
- **redirect-цепочки** (через `transitions`).

```
$ sqlite3 out/urls.sqlite 'SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 5;'
```

## Шаг 5: несколько профилей

В браузере может быть несколько профилей. Разбирай **все** — у каждого своя история.

## Что мы теперь знаем

- Hindsight разбирает профиль Chromium.
- Извлекает историю, загрузки, cookies, сессии, кэш.
- Конвертирует время из 1601-эпохи.
- Показывает переходы/referrer.
- Нужно разбирать все профили.

## Если не сработало

- Профиль зашифрован (DPAPI)? Расшифруй cookies отдельно.
- Нужна Firefix? Используй другой парсер.
- Кэш очищен? Смотри историю и другие источники.

## Квиз

Проверь себя.

```quiz
- question: Что разбирает Hindsight?
  options:
    - 'реестр'
    - 'профиль браузера Chromium'
    - 'сеть'
    - 'память'
  answer: 1
  explanation: 'Hindsight специализирован на артефактах Chromium.'
- question: В каком формате время в Chromium?
  options:
    - 'unix epoch'
    - 'микросекунды с 1601-01-01'
    - 'текст'
    - 'секунды с 1970'
  answer: 1
  explanation: 'Chromium использует Windows-эпоху (1601) в микросекундах.'
- question: Что показывает referrer/transitions?
  options:
    - 'пароль'
    - 'откуда пришёл пользователь на страницу'
    - 'размер'
    - 'обои'
  answer: 1
  explanation: 'Transitions отражают переходы и источник визита.'
- question: Сколько профилей нужно разбирать?
  options:
    - 'один'
    - 'все существующие'
    - 'ни одного'
    - 'только Default'
  answer: 1
  explanation: 'У каждого профиля своя история — разбирай все.'
```
