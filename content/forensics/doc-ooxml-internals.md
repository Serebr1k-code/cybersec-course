---
id: doc-ooxml-internals
title: 'OOXML: анатомия .docx/.xlsx/.pptx'
category: forensics
parent: forensics-doc-formats
difficulty: medium
order: 1
tags: [docx, ooxml, zip, xml, macros, document-forensics]
prerequisites: [forensics-file-magic, forensics-office-macros]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ малвари'
estimated_minutes: 45
summary: 'Как устроен OOXML-документ (ZIP + XML): части пакета, макросы, скрытый текст, вложенные объекты и метаданные — и как всё это разобрать через unzip.'
lab:
  kind: shell
  title: 'Практика: OOXML'
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

Тебе дали `report.docx`. Открывать в Word нельзя — это может быть вредоносно. Но нужно
понять, что внутри. Как заглянуть в документ, не запуская его?

## Наш пример: report.docx

Первым делом смотрим тип:

```
$ file report.docx
report.docx: Microsoft Word 2007+
```

`Microsoft Word 2007+` означает формат **OOXML** — открытый пакетный формат. И вот
главное: это **ZIP-архив** с XML внутри. Значит, его можно распаковать.

## Шаг 1: распаковать как архив

```
$ unzip -l report.docx
  Length      Name
  --------    ----
      1180    [Content_Types].xml
       586    _rels/.rels
      2048    word/document.xml
       720    word/_rels/document.xml.rels
      1024    docProps/core.xml
```

Уже по именам частей видно структуру. Разберём ключевые.

## Шаг 2: понять части пакета

- **`[Content_Types].xml`** — карта типов: какие части какого типа.
- **`_rels/.rels`** — связи верхнего уровня (где документ, где свойства).
- **`word/document.xml`** — сам текст документа.
- **`docProps/core.xml`** — метаданные: автор, время создания, последний редактор.
- **`word/_rels/document.xml.rels`** — связи документа: изображения, вложенные объекты,
  **внешние ссылки** (например, на шаблон).

Метаданные часто выдают больше, чем текст: автор, организация, время правок.

## Шаг 3: искать макросы

Макросы живут в отдельной части:

```
$ unzip -l report.docx | grep -i vba
      12288   word/vbaProject.bin
```

Наличие `vbaProject.bin` означает **встроенный макрос VBA**. Это главный вектор атак в
офисных документах. Разбирают его `olevba`:

```
$ olevba report.docx
VBA MACRO ThisDocument.cls
  AutoOpen() -> Shell("powershell -enc ...")
```

Функция `AutoOpen` запускается при открытии — классический признак малвари.

## Шаг 4: скрытый текст и правки

В `word/document.xml` можно спрятать текст:

- **скрытый текст** (`<w:vanish/>`) — виден в файле, но не отображается;
- **история правок** (`<w:ins>`/`<w:del>`) — удалённый текст остаётся в XML;
- **белый текст на белом** — визуально невидим.

Поэтому «в документе ничего нет» проверяют, читая XML, а не глядя на страницу.

## Шаг 5: вложенные объекты и внешние связи

В документ можно вложить OLE-объект (другой файл) или сослаться на внешний ресурс
(шаблон, изображение). В `.rels` ищем:

```
$ unzip -p report.docx word/_rels/document.xml.rels | grep -i Target
Target="https://evil.example/template.dotm"
```

Внешний шаблон — распространённый способ доставить макрос: документ «безобиден», а код
подгружается извне.

## Что мы теперь знаем

- OOXML — это ZIP-архив с XML-частями.
- `[Content_Types].xml` и `_rels` описывают структуру и связи.
- `vbaProject.bin` — встроенный макрос (главный риск).
- Скрытый текст и правки остаются в XML.
- Внешние связи могут подгружать код извне.

## Квиз

Проверь себя.

```quiz
- question: Что такое файл .docx по своей сути?
  options:
    - 'бинарный формат'
    - 'ZIP-архив с XML-частями'
    - 'текстовый файл'
    - 'образ диска'
  answer: 1
  explanation: 'OOXML — это OPC-пакет, то есть ZIP с XML внутри.'
- question: Какая часть документа содержит встроенный макрос?
  options:
    - 'docProps/core.xml'
    - 'word/vbaProject.bin'
    - '[Content_Types].xml'
    - 'word/document.xml'
  answer: 1
  explanation: 'vbaProject.bin хранит код VBA.'
- question: Где искать внешнюю ссылку на шаблон?
  options:
    - 'в core.xml'
    - 'в word/_rels/document.xml.rels'
    - 'в document.xml'
    - 'в [Content_Types].xml'
  answer: 1
  explanation: 'Связи документа описаны в .rels-файлах.'
- question: Что означает скрытый текст `<w:vanish/>`?
  options:
    - 'текст удалён'
    - 'текст есть в файле, но не отображается'
    - 'текст зашифрован'
    - 'текст в картинке'
  answer: 1
  explanation: 'Скрытый текст присутствует в XML, но не виден при просмотре.'
```

## Куда дальше

Дальше — **ODF**: открытый аналог OOXML с похожей, но своей структурой. А пока запомни:
`.docx` — это ZIP, и смотреть надо на части, а не на страницу.

## Где пригодится

- **CTF Forensics** — задачи со скрытыми данными в документах.
- **Анализ малвари** — разбор офисных документов без запуска.
- **DFIR / Incident Response** — исследование вложений из фишинга.
