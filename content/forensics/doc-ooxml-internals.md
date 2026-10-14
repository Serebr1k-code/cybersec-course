---
id: doc-ooxml-internals
title: 'OOXML изнутри: docx, xlsx, pptx как ZIP-архивы'
category: forensics
parent: forensics-doc-formats
difficulty: medium
order: 1
tags: [forensics, ooxml, docx, xlsx, macros, metadata]
prerequisites: [forensics-file-magic]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как устроены офисные документы OOXML, где метаданные, макросы и встроенные объекты, и как их извлекать.'
lab:
  kind: shell
  title: 'Практика: OOXML изнутри'
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

Пришёл документ `.docx` — он может быть безобидным, а может содержать макрос или
встроенный объект. Формат OOXML — это **ZIP** с XML внутри. Разберём структуру.

## Наш пример: подозрительный .docx

## Шаг 1: это ZIP

```
$ file report.docx
report.docx: Microsoft Word 2007+
$ unzip -l report.docx
  [Content_Types].xml
  word/document.xml
  word/vbaProject.bin
  docProps/core.xml
```

`vbaProject.bin` — уже сигнал: в документе есть **макросы**.

## Шаг 2: метаданные

```
$ unzip -p report.docx docProps/core.xml | head
<dc:creator>Ivan</dc:creator>
<cp:lastModifiedBy>Ivan</cp:lastModifiedBy>
<dcterms:created>2026-01-14T03:20:00Z</dcterms:created>
```

`core.xml` — авторство и времена. Расхождение created/modified — зацепка.

## Шаг 3: макросы

Макросы — это VBA. Извлекаем и анализируем:

```
$ olevba report.docx
VBA MACRO ThisDocument.cls
  AutoOpen → Shell("powershell -enc ...")
```

`AutoOpen` — автозапуск при открытии. Это классический вектор.

## Шаг 4: встроенные объекты

Документ может содержать:

- встроенный `.exe` (в `word/embeddings/`);
- OLE-объекты;
- внешние ссылки (`word/_rels/`) — откуда подгружаются данные (DDE, remote template).

```
$ unzip -l report.docx | grep embeddings
word/embeddings/oleObject1.bin
```

## Шаг 5: что искать

- макросы (`vbaProject.bin`);
- внешние ссылки (remote template injection);
- встроенные файлы;
- метаданные автора/времени.

## Что мы теперь знаем

- OOXML — ZIP с XML.
- `vbaProject.bin` = макросы.
- `core.xml` — авторство и времена.
- `embeddings/` — встроенные объекты.
- Внешние ссылки = потенциальная загрузка.

## Если не сработало

- Файл зашифрован паролем? Нужен пароль.
- Старый формат (.doc)? Используй OLE-парсеры.
- Макрос скомпилирован? Анализируй p-code.

## Квиз

Проверь себя.

```quiz
- question: Что представляет собой .docx?
  options:
    - 'бинарный файл'
    - 'ZIP-архив с XML'
    - 'текстовый файл'
    - 'образ диска'
  answer: 1
  explanation: 'OOXML — это zip-контейнер с XML-компонентами.'
- question: Что означает vbaProject.bin?
  options:
    - 'картинку'
    - 'наличие макросов VBA'
    - 'шрифт'
    - 'пароль'
  answer: 1
  explanation: 'Это хранилище VBA-макросов документа.'
- question: Где искать автора и время?
  options:
    - 'в document.xml'
    - 'в docProps/core.xml'
    - 'в vbaProject.bin'
    - 'в embeddings'
  answer: 1
  explanation: 'core.xml содержит creator и created/modified.'
- question: Чем опасен AutoOpen?
  options:
    - 'ничем'
    - 'запускает макрос при открытии документа'
    - 'удаляет файл'
    - 'шифрует'
  answer: 1
  explanation: 'AutoOpen — автозапуск VBA при открытии.'
```
