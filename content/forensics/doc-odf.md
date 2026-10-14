---
id: doc-odf
title: 'ODF: открытый формат .odt/.ods/.odp'
category: forensics
parent: forensics-doc-formats
difficulty: medium
order: 2
tags: [odf, odt, ods, zip, xml, document-forensics]
prerequisites: [forensics-file-magic]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ малвари'
estimated_minutes: 40
summary: 'Как устроен OpenDocument (ODF): mimetype, content.xml, meta.xml, manifest, макросы Basic — и чем он отличается от OOXML при разборе.'
lab:
  kind: shell
  title: 'Практика: ODF'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

В руки попал `budget.ods` из LibreOffice. Формат незнакомый, открывать не хочется. Что
внутри и где искать скрытое?

## Наш пример: budget.ods

```
$ file budget.ods
budget.ods: OpenDocument Spreadsheet
```

**ODF (OpenDocument Format)** — открытый стандарт, используемый LibreOffice и рядом других
пакетов. Как и OOXML, это **ZIP-архив** с XML.

## Шаг 1: распаковать

```
$ unzip -l budget.ods
  Length      Name
  --------    ----
        46    mimetype
      2048    content.xml
       512    meta.xml
       380    META-INF/manifest.xml
      1024    styles.xml
```

Отличие от OOXML бросается в глаза: первая часть — `mimetype`.

## Шаг 2: роль mimetype

У ODF `mimetype` — это первый файл в архиве, **без сжатия**, содержащий MIME-тип:

```
$ unzip -p budget.ods mimetype
application/vnd.oasis.opendocument.spreadsheet
```

Именно так `file` определяет ODF: по этой части. Это удобно и для форензика — тип виден
сразу, даже без разбора XML.

## Шаг 3: content.xml и meta.xml

- **`content.xml`** — содержимое документа (текст, таблицы, ячейки);
- **`meta.xml`** — метаданные: автор, время создания, время правок, иногда статистика.

```
$ unzip -p budget.ods meta.xml | grep -E 'meta:initial-creator|dc:creator|meta:creation-date'
<meta:initial-creator>alice</meta:initial-creator>
<dc:creator>bob</dc:creator>
<meta:creation-date>2026-03-10T03:14:00</meta:creation-date>
```

Видно, что файл создал `alice`, а последним редактором был `bob` — история изменений.

## Шаг 4: META-INF/manifest.xml

`META-INF/manifest.xml` перечисляет все части пакета и их типы. По нему видно, есть ли
неожиданные части — например, встроенные объекты или макросы.

## Шаг 5: макросы Basic

В ODF макросы (Basic) хранятся в отдельных частях, часто с расширением `.xml` внутри
папки `Basic/` или в `Scripts/`. Их наличие — сигнал, что документ может исполнять код.
Ищем:

```
$ unzip -l budget.ods | grep -iE 'Basic|Scripts'
```

## Сравнение с OOXML

| Признак | OOXML | ODF |
|---------|-------|-----|
| Контейнер | ZIP | ZIP |
| Тип-маркер | `[Content_Types].xml` | `mimetype` |
| Текст | `word/document.xml` | `content.xml` |
| Метаданные | `docProps/core.xml` | `meta.xml` |
| Макросы | `vbaProject.bin` | `Basic/`, `Scripts/` |

Принцип разбора один: распаковать и читать XML.

## Что мы теперь знаем

- ODF — ZIP-архив с XML, как и OOXML.
- `mimetype` — первый файл, определяющий тип документа.
- `content.xml` — содержимое, `meta.xml` — метаданные.
- `META-INF/manifest.xml` перечисляет части пакета.
- Макросы Basic лежат в отдельных частях.

## Квиз

Проверь себя.

```quiz
- question: Как определить тип ODF-файла без разбора XML?
  options:
    - 'по имени файла'
    - 'по первой части mimetype в архиве'
    - 'по размеру'
    - 'по дате'
  answer: 1
  explanation: 'mimetype хранится первым и без сжатия; по нему работает file.'
- question: Где в ODF лежит содержимое документа?
  options:
    - 'meta.xml'
    - 'content.xml'
    - 'styles.xml'
    - 'manifest.xml'
  answer: 1
  explanation: 'content.xml содержит текст, таблицы и ячейки.'
- question: Что описывает META-INF/manifest.xml?
  options:
    - 'пароли'
    - 'перечень частей пакета и их типов'
    - 'версию ОС'
    - 'шрифты'
  answer: 1
  explanation: 'manifest перечисляет все части пакета.'
- question: Где в ODF могут лежать макросы?
  options:
    - 'в mimetype'
    - 'в папках Basic/ или Scripts/'
    - 'в meta.xml'
    - 'в styles.xml'
  answer: 1
  explanation: 'Макросы Basic хранятся в отдельных частях пакета.'
```

## Куда дальше

Мы разобрали два «архивных» формата. Дальше — **RTF**: старый текстовый формат, который
до сих пор живёт в фишинге. А пока запомни: принцип один — распаковать и читать XML.

## Где пригодится

- **CTF Forensics** — задачи с ODF-документами.
- **Анализ малвари** — разбор документов LibreOffice.
- **DFIR / Incident Response** — исследование вложений.
