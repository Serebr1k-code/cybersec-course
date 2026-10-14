---
id: doc-odf
title: 'ODF: открытый формат документов изнутри'
category: forensics
parent: forensics-doc-formats
difficulty: medium
order: 2
tags: [forensics, odf, opendocument, metadata, documents]
prerequisites: [forensics-file-magic]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 40
summary: 'Как устроен ODF (odt/ods/odp), где метаданные и встроенные объекты, чем отличается от OOXML.'
lab:
  kind: shell
  title: 'Практика: ODF'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "Повторение (`forensics-file-magic`): сначала `head -n 5 evidence.txt` — вспомни приём из «forensics-file-magic»."
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Встречается документ `.odt` (LibreOffice/OpenOffice). Это тоже ZIP, но со своей
структурой и метаданными. Разберём, как его читать.

## Наш пример: .odt

## Шаг 1: структура

```
$ unzip -l doc.odt
  mimetype
  content.xml
  meta.xml
  styles.xml
  settings.xml
  Thumbnails/thumbnail.png
```

`mimetype` — тип документа, `content.xml` — содержимое, `meta.xml` — метаданные.

## Шаг 2: метаданные

```
$ unzip -p doc.odt meta.xml
<meta:initial-creator>Ivan</meta:initial-creator>
<meta:creation-date>2026-01-14T03:20:00Z</meta:creation-date>
<meta:editing-cycles>4</meta:editing-cycles>
```

ODF хранит **initial-creator** и число циклов редактирования — то, чего нет в OOXML так
явно.

## Шаг 3: отличия от OOXML

- ODF — открытый стандарт (ISO);
- метаданные в `meta.xml` (отдельный файл);
- макросы — в `Basic/` (LibreOffice Basic) или через внешние ссылки;
- нет `vbaProject.bin`.

## Шаг 4: что искать

- автора и время;
- историю правок (editing-cycles);
- встроенные объекты/картинки;
- внешние ссылки;
- макросы (реже, но бывают).

## Шаг 5: практика

```
$ unzip -o doc.odt -d odt_out
$ grep -ri 'macro\|script' odt_out/ | head
```

## Что мы теперь знаем

- ODF — ZIP с `content.xml`/`meta.xml`.
- `meta.xml` хранит автора и циклы правок.
- Отличия от OOXML: открытый стандарт, иные метаданные.
- Макросы реже, но возможны.
- Разбирается распаковкой.

## Если не сработало

- Файл повреждён? Попробуй восстановить ZIP.
- Макросы? Ищи Basic-скрипты.
- Нужен контент? Читай content.xml.

## Квиз

Проверь себя.

```quiz
- question: Что такое ODF?
  options:
    - 'бинарный формат'
    - 'открытый ZIP-формат документов'
    - 'сетевой протокол'
    - 'образ диска'
  answer: 1
  explanation: 'ODF (odt/ods) — открытый стандарт на базе ZIP+XML.'
- question: Где метаданные ODF?
  options:
    - 'в content.xml'
    - 'в meta.xml'
    - 'в mimetype'
    - 'в стилях'
  answer: 1
  explanation: 'meta.xml содержит автора, даты, циклы редактирования.'
- question: Что даёт editing-cycles?
  options:
    - 'размер'
    - 'число циклов редактирования документа'
    - 'пароль'
    - 'сеть'
  answer: 1
  explanation: 'Это косвенная история правок документа.'
- question: Как разобрать ODF?
  options:
    - 'запустить'
    - 'распаковать как ZIP'
    - 'открыть в браузере'
    - 'никак'
  answer: 1
  explanation: 'ODF — zip-контейнер, разбирается распаковкой.'
```

## Куда дальше

Дальше — **RTF**: старый текстовый формат, который до сих пор живёт в фишинге. А пока
запомни: принцип разбора один — распаковать и читать XML.

## Где пригодится

- **CTF Forensics** — задачи с ODF-документами.
- **Анализ малвари** — разбор документов LibreOffice.
- **DFIR / Incident Response** — исследование вложений.
