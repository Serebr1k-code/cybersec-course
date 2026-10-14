---
id: tool-fiwalk
title: 'fiwalk: обход образов через Sleuth Kit'
category: forensics
parent: forensics-tools-utility
difficulty: medium
order: 2
tags: [forensics, tools, fiwalk, sleuthkit, disk-image]
prerequisites: [forensics-tooling]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как fiwalk обходит образ и выдаёт метаданные всех файлов в XML/JSON — для скриптов и массового анализа.'
lab:
  kind: shell
  title: "Практика: обход образа fiwalk"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, fiwalk_files.xml]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "fiwalk обходит образ через Sleuth Kit и печатает XML со всеми записями."
    - "meta_type 1 — выделенный файл, 0 — удалённый."
    - "`grep nto fiwalk_files.xml > answer.txt`."
---

## Вопрос, с которого всё начинается

Нужно получить **список всех файлов** в образе с метаданными — для скриптового анализа.
Кликать в GUI долго. **fiwalk** обходит образ через Sleuth Kit и выдаёт структурированный
вывод. Разберём.

## Наш пример: образ диска

## Шаг 1: что такое fiwalk

fiwalk — обёртка над Sleuth Kit, которая обходит файловую систему и печатает метаданные
каждого файла: inode, имя, размер, времена, хеши (опционально).

## Шаг 2: запуск

```
$ fiwalk -f -X out.xml disk.img
```

`-X` — XML-вывод. Для больших образов это удобно: файл можно парсить скриптом.

## Шаг 3: что внутри

```xml
<fileobject>
  <inode>12345</inode>
  <filename>report.pdf</filename>
  <filesize>24576</filesize>
  <mtime>2026-01-14T03:31:02Z</mtime>
</fileobject>
```

Отсюда строишь таблицы, фильтруешь по времени, ищешь аномалии.

## Шаг 4: практика

```bash
fiwalk -X out.xml disk.img
python3 -c "import xml.etree.ElementTree as ET; ..."  # фильтр по mtime
```

Можно генерировать списки по типам, искать файлы в окне инцидента, считать статистику.

## Шаг 5: связка с другими

- **Sleuth Kit** (`fls`, `icat`, `mmls`) — низкий уровень;
- **plaso** — таймлайн;
- **Autopsy** — GUI поверх того же движка.

fiwalk — «мост» между Sleuth Kit и скриптами.

## Что мы теперь знаем

- fiwalk обходит образ и выдаёт метаданные.
- Вывод — XML (удобно парсить).
- Даёт inode, имя, размер, времена.
- Строит основу для скриптового анализа.
- Работает поверх Sleuth Kit.

## Если не сработало

- ФС не распознана? Проверь разделы (`mmls`).
- Нужен контент? Используй `icat`.
- Нужен GUI? Используй Autopsy.

## Квиз

Проверь себя.

```quiz
- question: Что делает fiwalk?
  options:
    - 'шифрует диск'
    - 'обходит образ и печатает метаданные файлов'
    - 'сканирует сеть'
    - 'удаляет файлы'
  answer: 1
  explanation: 'fiwalk выдаёт метаданные каждого файла образа.'
- question: В каком формате удобен вывод fiwalk для скриптов?
  options:
    - 'PDF'
    - 'XML'
    - 'DOCX'
    - 'MP4'
  answer: 1
  explanation: 'XML легко парсится программно.'
- question: На чём основан fiwalk?
  options:
    - 'на Photoshop'
    - 'на Sleuth Kit'
    - 'на nmap'
    - 'на nginx'
  answer: 1
  explanation: 'fiwalk — обёртка над Sleuth Kit.'
- question: Что даёт icat в связке?
  options:
    - 'метаданные'
    - 'содержимое файла по inode'
    - 'сеть'
    - 'пароли'
  answer: 1
  explanation: 'icat извлекает контент файла по inode.'
```
