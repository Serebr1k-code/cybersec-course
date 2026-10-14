---
id: doc-xps
title: 'XPS: документ как OPC-пакет'
category: forensics
parent: forensics-doc-formats
difficulty: medium
order: 4
tags: [xps, opc, zip, xml, document-forensics]
prerequisites: [forensics-file-magic]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ малвари'
estimated_minutes: 40
summary: 'Как устроен XPS (ZIP + XML, фиксированные страницы), чем похож на OOXML и как разбирать его как OPC-пакет.'
lab:
  kind: shell
  title: 'Практика: XPS'
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

Попался файл `scan.xps` — вроде документ, но не PDF и не Word. Что это и как его читать?

## Наш пример: scan.xps

```
$ file scan.xps
scan.xps: Microsoft XPS document
```

**XPS (XML Paper Specification)** — формат «фиксированных» документов от Microsoft, по
идее похожий на PDF: страницы описаны заранее и не переформатируются.

## Шаг 1: XPS — это OPC-пакет

Как OOXML, XPS — это **OPC-пакет** (Open Packaging Conventions): ZIP-архив с XML и
связями.

```
$ unzip -l scan.xps
  Length      Name
  --------    ----
       900    [Content_Types].xml
       620    _rels/.rels
      2048    FixedDocumentSequence.fdseq
      1024    Documents/1/FixedDocument.fdoc
      4096    Documents/1/Pages/1.fpage
```

Структура: `FixedDocumentSequence` → `FixedDocument` → страницы (`fpage`). Каждая страница —
XML с описанием содержимого.

## Шаг 2: страницы как XML

```
$ unzip -p scan.xps Documents/1/Pages/1.fpage | head -c 300
<FixedPage ...><Glyphs FontUri="/Resources/Fonts/..." UnicodeString="nto{xps_h1dd3n_p4g3}"/>
```

Текст страницы — в атрибутах `UnicodeString` элементов `Glyphs`. То есть читать XPS
можно прямо из XML, без специальной программы.

## Шаг 3: ресурсы и шрифты

XPS может ссылаться на ресурсы: изображения, шрифты. Они лежат в `Resources/`. Для
форензика важно: в ресурсах можно спрятать данные, а «шрифт» может быть не шрифтом.

## Шаг 4: чем похож на OOXML

Оба формата:

- ZIP-контейнер;
- `[Content_Types].xml` и `_rels/.rels`;
- XML внутри.

Разница: OOXML описывает «потоковый» документ (текст, который переформатируется), а XPS —
«фиксированные» страницы с точными координатами. Для разбора принцип один: распаковать и
читать XML.

## Что мы теперь знаем

- XPS — OPC-пакет (ZIP + XML), как OOXML.
- Иерархия: последовательность → документ → страницы.
- Текст страницы лежит в XML (`UnicodeString` у `Glyphs`).
- Ресурсы (шрифты, изображения) хранятся в `Resources/`.
- Разбирать XPS можно через `unzip`.

## Квиз

Проверь себя.

```quiz
- question: Что такое XPS по своей сути?
  options:
    - 'PDF'
    - 'OPC-пакет (ZIP + XML)'
    - 'текстовый файл'
    - 'образ диска'
  answer: 1
  explanation: 'XPS использует те же Open Packaging Conventions, что и OOXML.'
- question: Где в XPS описано содержимое страницы?
  options:
    - 'в [Content_Types].xml'
    - 'в файлах .fpage (XML)'
    - 'в _rels/.rels'
    - 'в mimetype'
  answer: 1
  explanation: 'Страницы представлены файлами FixedPage (.fpage).'
- question: Где хранятся шрифты и изображения XPS?
  options:
    - 'в корне архива'
    - 'в папке Resources/'
    - 'в meta.xml'
    - 'в документе Word'
  answer: 1
  explanation: 'Ресурсы пакета лежат в Resources/.'
- question: Чем XPS отличается от OOXML?
  options:
    - 'ничем'
    - 'XPS описывает фиксированные страницы, OOXML — потоковый документ'
    - 'XPS не ZIP'
    - 'XPS без XML'
  answer: 1
  explanation: 'XPS — «бумажный» формат с фиксированной вёрсткой.'
```

## Куда дальше

Мы закончили ветку форматов документов. Дальше можно вернуться к другим веткам дерева. А
пока запомни: и OOXML, и ODF, и XPS — это ZIP-контейнеры, и разбирать их надо через XML.

## Где пригодится

- **CTF Forensics** — задачи с «необычными» документами.
- **DFIR / Incident Response** — разбор вложений.
- **Анализ малвари** — поиск скрытого контента в пакетах.
