---
id: macos-safari
title: 'Safari-форензика: история, загрузки и кэш'
category: forensics
parent: forensics-macos-artifacts-deep
difficulty: medium
order: 5
tags: [macos, safari, browser, history, downloads, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как читать History.db, Downloads.plist и кэш Safari, восстанавливать посещения, загрузки и сессии.'
lab:
  kind: shell
  title: 'Практика: Safari-форензика'
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

Пользователь скачал вредоносный файл. Через какой браузер, с какого сайта и что ещё он
смотрел? Safari хранит историю в SQLite и plist. Разберём три источника: историю,
загрузки и сессии.

## Наш пример: история Safari

## Шаг 1: база истории

```
$ ls ~/Library/Safari/History.db
-rw-r--r-- 1 user staff 245760 Jan 14 03:30 History.db
$ sqlite3 History.db '.tables'
history_items  history_visits  ...
```

`history_items` — сами страницы, `history_visits` — когда их открывали.

## Шаг 2: извлекаем посещения

```
$ sqlite3 History.db 'SELECT datetime(v.visit_time+978307200,"unixepoch"), i.url FROM history_visits v JOIN history_items i ON i.id=v.history_item ORDER BY v.visit_time DESC LIMIT 5;'
2026-01-14 03:27:40|https://203.0.113.5/download.html
2026-01-14 03:28:10|https://203.0.113.5/payload.dmg
```

Время — Apple epoch. Видно, что за минуту до скачивания пользователь был на
`203.0.113.5` — это точка входа.

## Шаг 3: список загрузок

```
$ plutil -p ~/Library/Safari/Downloads.plist | head
{
  "DownloadHistory" => [
    { "DownloadEntryPath" => "/Users/user/Downloads/payload.dmg",
      "DownloadEntryURL" => "https://203.0.113.5/payload.dmg",
      "DownloadEntryDateAdded" => 2026-01-14 03:28:10 +0000 }
  ]
}
```

`Downloads.plist` — журнал загрузок. Даже если файл удалили, запись остаётся.

## Шаг 4: сессии и окна

Safari хранит открытые вкладки:

```
$ plutil -p ~/Library/Safari/LastSession.plist | grep -i url | head
```

Отсюда видно, что было открыто в момент завершения работы.

## Шаг 5: кэш и авто-заполнение

Кэш страниц (`~/Library/Caches/com.apple.Safari/`) может содержать тела ответов, а
`AutoFill` — сохранённые формы (без паролей). Это помогает восстановить содержимое
страницы, которой уже нет.

## Что мы теперь знаем

- `History.db` — история посещений (время в Apple epoch).
- `Downloads.plist` — журнал загрузок с URL.
- `LastSession.plist` — открытые вкладки.
- Кэш хранит тела страниц.
- Цепочка «сайт → скачивание → установка» восстанавливается полностью.

## Если не сработало

- Файлы пусты? Проверь `~/Library/Safari/` всех пользователей.
- Приватный режим? История не пишется — ищи в кэше и сети.
- Кэш очищен? Смотри Time Machine и системные логи.

## Квиз

Проверь себя.

```quiz
- question: Где Safari хранит историю посещений?
  options:
    - 'в /etc/hosts'
    - 'в History.db'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'History.db — SQLite с history_items и history_visits.'
- question: Что хранит Downloads.plist?
  options:
    - 'пароли'
    - 'журнал загрузок с URL и датой'
    - 'маршруты'
    - 'обои'
  answer: 1
  explanation: 'В DownloadHistory есть путь, URL и дата каждой загрузки.'
- question: В каком формате время в Safari?
  options:
    - 'unix epoch'
    - 'Apple epoch (+978307200)'
    - 'Windows FILETIME'
    - 'текст'
  answer: 1
  explanation: 'Safari использует Apple epoch, начинающийся с 2001-01-01.'
- question: Что можно найти в кэше Safari?
  options:
    - 'пароль диска'
    - 'тела страниц, которых уже нет'
    - 'сетевые маршруты'
    - 'логи ядра'
  answer: 1
  explanation: 'Кэш может содержать сохранённые ответы сервера.'
```
