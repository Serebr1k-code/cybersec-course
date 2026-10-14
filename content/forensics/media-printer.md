---
id: media-printer
title: 'Печать в форензике: spool-файлы и задания'
category: forensics
parent: forensics-media-analysis
difficulty: medium
order: 4
tags: [forensics, printer, spool, emf, documents]
prerequisites: [forensics-file-magic]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 40
summary: 'Как анализировать задания печати: spool-файлы, EMF/RAW, метаданные и следы документов.'
lab:
  kind: shell
  title: 'Практика: Печать в форензике'
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

Что печатали на принтере и что было в документе? Windows сохраняет задания печати в
**spool**, часто даже после печати. Разберём.

## Наш пример: очередь печати

## Шаг 1: где spool

```
C:\Windows\System32\spool\PRINTERS\
```

Здесь временные файлы заданий: `.SPL` (данные) и `.SHD` (заголовок задания).

## Шаг 2: .SPL и .SHD

- `.SPL` — поток данных для принтера (часто EMF или RAW);
- `.SHD` — метаданные: имя документа, пользователь, принтер.

```
$ strings 00001.SHD | head
Document: secret_report.docx
User: CORP\Ivan
Printer: HP-LaserJet
```

Так узнаёшь, **что** и **кто** печатал.

## Шаг 3: EMF-задания

Если `.SPL` — EMF (Enhanced Metafile), внутри — векторное представление страниц:

```
$ file 00001.SPL
00001.SPL: MS Windows Enhanced Metafile
```

EMF можно открыть/конвертировать и увидеть содержимое документа.

## Шаг 4: восстановление

Задания могут оставаться после печати (особенно если принтер выключен/в очереди). Их
извлекают из образа:

```
$ strings -el 00001.SPL | grep -i 'confidential'
```

RAW-задания (PCL/PostScript) тоже несут текст.

## Шаг 5: что искать

- имя документа и пользователя;
- содержимое (EMF/RAW);
- время печати;
- несколько копий/заданий.

## Что мы теперь знаем

- Задания печати лежат в spool/PRINTERS.
- `.SHD` — метаданные, `.SPL` — данные.
- EMF несёт векторное содержимое.
- Задания могут оставаться после печати.
- Метаданные выдают документ и пользователя.

## Если не сработало

- Spool пуст? Смотри журнал печати (`PrintService` Event Log).
- RAW-формат? Парси PCL/PostScript.
- Нужен рендер? Конвертируй EMF.

## Квиз

Проверь себя.

```quiz
- question: Где Windows хранит задания печати?
  options:
    - 'в /tmp'
    - 'в spool/PRINTERS'
    - 'в реестре'
    - 'в браузере'
  answer: 1
  explanation: 'Каталог PRINTERS содержит .SPL и .SHD файлы заданий.'
- question: Что содержит .SHD?
  options:
    - 'данные для принтера'
    - 'метаданные задания (документ, пользователь)'
    - 'шрифты'
    - 'сеть'
  answer: 1
  explanation: 'SHD — заголовок с именем документа и пользователем.'
- question: Что такое EMF?
  options:
    - 'формат сети'
    - 'векторное представление страниц'
    - 'кодек'
    - 'архив'
  answer: 1
  explanation: 'EMF — Enhanced Metafile с содержимым документа.'
- question: Почему spool полезен для форензики?
  options:
    - 'он быстрый'
    - 'может сохранить что и кто печатал'
    - 'он шифрует'
    - 'он в облаке'
  answer: 1
  explanation: 'Задания могут оставаться после печати с содержимым.'
```
