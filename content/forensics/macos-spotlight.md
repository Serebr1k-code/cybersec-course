---
id: macos-spotlight
title: 'Spotlight: индекс macOS как источник метаданных'
category: forensics
parent: forensics-macos-artifacts-deep
difficulty: medium
order: 2
tags: [macos, spotlight, metadata, index, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Что хранит индекс Spotlight, как читать store.db и использовать метаданные файлов, даже если сами файлы удалены.'
lab:
  kind: shell
  title: "Практика: метаданные Spotlight"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, spotlight_store.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "Spotlight хранит метаданные даже после удаления файла."
    - "Путь /private/tmp + flag=1 — зацепка."
    - "`grep nto spotlight_store.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Файл удалён, но macOS его «помнит». Индекс **Spotlight** хранит метаданные обо всём,
что когда-либо было в системе: имена, пути, размеры, даты. Это архив теней удалённых
файлов. Разберёмся, как его читать.

## Наш пример: удалённый документ

## Шаг 1: где индекс

```
$ ls ~/Library/Application\ Support/com.apple.spotlight/
index.V2  store.db  ...
```

`store.db` — это SQLite-база индекса. Откроем и посмотрим таблицы:

```
$ sqlite3 store.db '.tables'
...
```

## Шаг 2: метаданные через mdls

Проще всего — встроенный инструмент `mdls`, он читает метаданные файла:

```
$ mdls -name kMDItemDisplayName -name kMDItemContentCreationDate /Users/user/Documents/report.pdf
kMDItemDisplayName = "report.pdf"
kMDItemContentCreationDate = 2026-01-14 03:31:02 +0000
```

`kMDItem*` — это атрибуты Spotlight. Их десятки: автор, где создан, какой программой,
сколько раз открывали.

## Шаг 3: поиск через mdfind

Найти файлы по метаданным:

```
$ mdfind -onlyin /Users/user 'kMDItemWhereFroms == "*203.0.113.5*"'
/Users/user/Downloads/payload.dmg
```

`kMDItemWhereFroms` — откуда файл скачан. Так можно найти всё, что пришло с
подозрительного адреса, даже если оно переименовано.

## Шаг 4: удалённые файлы в индексе

Если файл удалили, но индекс не перестроили, запись может остаться:

```
$ sqlite3 store.db 'SELECT * FROM ... LIMIT 5;'
```

Структура `store.db` недокументирована, поэтому на практике используют утилиты вроде
`mac_apt` или `Spotlight`-парсеры. Они извлекают имена, пути и даты удалённых файлов.

## Шаг 5: что ещё в индексе

Spotlight индексирует не только документы, но и:

- почту (`kMDItemContentType = com.apple.mail.emlx`);
- историю браузера (заголовки страниц);
- переписку;
- музыку/фото с метаданными.

Поэтому `mdfind` — быстрый способ найти «всё про X» по всей системе.

## Что мы теперь знаем

- Spotlight хранит индекс метаданных в `store.db` и `index.V2`.
- `mdls` показывает атрибуты одного файла.
- `mdfind` ищет по метаданным по всей системе.
- `kMDItemWhereFroms` = источник скачивания.
- Удалённые файлы могут остаться в индексе.

## Если не сработало

- Индекс отключён? Проверь `mdutil -s /`.
- Индекс перестроен? Используй бэкап Time Machine.
- Нужны детали? Парси `store.db` утилитами mac_apt.

## Квиз

Проверь себя.

```quiz
- question: Где хранится индекс Spotlight?
  options:
    - 'в /etc/passwd'
    - 'в store.db / index.V2'
    - 'в /boot'
    - 'в реестре'
  answer: 1
  explanation: 'Индекс лежит в ~/Library/Application Support/com.apple.spotlight/.'
- question: Что делает mdfind?
  options:
    - 'удаляет файлы'
    - 'ищет по метаданным Spotlight'
    - 'сжимает диск'
    - 'шифрует'
  answer: 1
  explanation: 'mdfind — CLI-поиск по индексу Spotlight.'
- question: Что означает kMDItemWhereFroms?
  options:
    - 'размер файла'
    - 'откуда файл скачан'
    - 'автор'
    - 'формат'
  answer: 1
  explanation: 'Атрибут хранит URL-источник загрузки файла.'
- question: Почему Spotlight важен для форензики?
  options:
    - 'он быстрый'
    - 'хранит метаданные даже удалённых файлов'
    - 'он шифрует'
    - 'он только для фото'
  answer: 1
  explanation: 'Индекс может сохранить следы файлов, которых уже нет на диске.'
```
