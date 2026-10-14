---
id: doc-xps
title: 'XPS: «PDF от Microsoft» и его разбор'
category: forensics
parent: forensics-doc-formats
difficulty: medium
order: 4
tags: [forensics, xps, oxps, documents, metadata]
prerequisites: [forensics-file-magic]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 40
summary: 'Что такое XPS/OXPS, как устроен формат, где метаданные и как его анализировать.'
lab:
  kind: shell
  title: 'Практика: XPS'
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

Встречается файл `.xps` — «документ фиксированного вида» от Microsoft. Это ZIP с
страницами в XML. Разберём структуру и что в нём искать.

## Наш пример: .xps

## Шаг 1: это ZIP

```
$ file doc.xps
doc.xps: Microsoft XPS Document
$ unzip -l doc.xps
  FixedDocumentSequence.fdseq
  Documents/1/Pages/1.fpage
  Metadata/...
  [Content_Types].xml
```

`FixedDocumentSequence` — корень, `Pages/*.fpage` — страницы (XML с элементами).

## Шаг 2: метаданные

XPS хранит метаданные в `Metadata/`:

```
$ unzip -p doc.xps 'Metadata/*' | head
<psf:DocumentProperties>
  <psf:Author>Ivan</psf:Author>
```

## Шаг 3: содержимое страниц

Страницы — XML с текстом и графикой:

```
$ unzip -p doc.xps 'Documents/1/Pages/1.fpage' | grep -o 'UnicodeString="[^"]*"' | head
UnicodeString="Confidential"
```

Текст извлекается как XML-атрибуты — легко искать ключевые слова.

## Шаг 4: встроенные ресурсы

XPS может содержать:

- изображения (`Resources/`);
- шрифты (в т.ч. встроенные);
- ссылки на внешние ресурсы (можно отключить).

## Шаг 5: практика

```
$ unzip -o doc.xps -d xps_out
$ grep -ri 'http\|script' xps_out/ | head
```

## Что мы теперь знаем

- XPS/OXPS — ZIP с XML-страницами.
- Метаданные в `Metadata/`.
- Текст извлекается как XML-атрибуты.
- Может содержать изображения и шрифты.
- Разбирается распаковкой.

## Если не сработало

- OXPS? Структура та же (OpenXPS).
- Нужен рендер? Используй XPS Viewer.
- Ссылки на внешние? Проверь rels.

## Квиз

Проверь себя.

```quiz
- question: Что такое XPS?
  options:
    - 'бинарный формат'
    - 'ZIP-формат фиксированного документа (XML)'
    - 'сеть'
    - 'образ'
  answer: 1
  explanation: 'XPS — zip-контейнер со страницами XML.'
- question: Где метаданные XPS?
  options:
    - 'в страницах'
    - 'в Metadata/'
    - 'в fdseq'
    - 'в шрифтах'
  answer: 1
  explanation: 'Каталог Metadata хранит свойства документа.'
- question: Как извлекается текст из страниц?
  options:
    - 'через рендер'
    - 'как XML-атрибуты (UnicodeString)'
    - 'никак'
    - 'через OCR'
  answer: 1
  explanation: 'Текст страниц лежит в XML-атрибутах.'
- question: Как разобрать XPS?
  options:
    - 'запустить'
    - 'распаковать как ZIP'
    - 'открыть в браузере'
    - 'никак'
  answer: 1
  explanation: 'XPS — zip; разбирается распаковкой.'
```
