---
id: tool-ntfs-tools
title: 'NTFS-утилиты: MFT, $LogFile и $UsnJrnl напрямую'
category: forensics
parent: forensics-tools-utility
difficulty: hard
order: 3
tags: [forensics, tools, ntfs, mft, usn, logfile]
prerequisites: [forensics-tooling]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как читать NTFS-структуры напрямую: MFT, журнал транзакций $LogFile и USN-журнал — ключевые источники следов.'
lab:
  kind: shell
  title: 'Практика: NTFS-утилиты'
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

Нужно понять, что происходило с файлами на NTFS: создание, удаление, переименование —
даже если запись в MFT подчищена. Три источника: **$MFT**, **$LogFile** и
**$UsnJrnl**. Разберём утилиты для них.

## Наш пример: том NTFS

## Шаг 1: $MFT

Главная таблица файлов. Каждому файлу — запись с атрибутами ($STANDARD_INFORMATION,
$FILE_NAME, $DATA).

```
$ analyzeMFT.py -f MFT -o mft.csv
```

`analyzeMFT` конвертирует MFT в CSV: имя, времена (4 штуки!), размер, родитель.

## Шаг 2: две пары временных меток

Ключевая тонкость NTFS: атрибут `$STANDARD_INFORMATION` (SI) и `$FILE_NAME` (FN)
хранят **разные** времена. Расхождение SI/FN — признак **timestomping**:

```
SI.mtime = 2020-01-01  (подделано)
FN.mtime = 2026-01-14  (реальное)
```

## Шаг 3: $LogFile

Журнал транзакций ФС. Фиксирует изменения метаданных **до** их применения:

```
$ LogFileParser.py -f LOGFILE
```

Позволяет восстановить последовательность операций (создание/удаление/переименование)
и найти записи, удалённые из MFT.

## Шаг 4: $UsnJrnl

USN (Update Sequence Number) — журнал изменений:

```
$ MFTECmd.exe -f '$UsnJrnl$J' --csv out/
```

Показывает: файл, причину изменения, время. Часто сохраняется даже при очистке MFT.

## Шаг 5: что искать

- **timestomping** (SI ≠ FN);
- **удалённые файлы** (в LogFile/UsnJrnl);
- **переименования**;
- **кто менял** (по времени).

## Что мы теперь знаем

- MFT — таблица файлов с атрибутами.
- SI и FN хранят разные времена → ловят timestomping.
- $LogFile — журнал транзакций (восстановление).
- $UsnJrnl — журнал изменений (устойчив к очистке MFT).
- Всё это — ключевые источники следов.

## Если не сработало

- MFT повреждён? Используй `$LogFile`.
- Нужны удалённые имена? Ищи в UsnJrnl.
- Нужен контент? Восстанавливай по кластерам.

## Квиз

Проверь себя.

```quiz
- question: Что такое $MFT?
  options:
    - 'журнал сети'
    - 'главная таблица файлов NTFS'
    - 'кэш браузера'
    - 'реестр'
  answer: 1
  explanation: 'MFT хранит записи обо всех файлах тома.'
- question: Как поймать timestomping на NTFS?
  options:
    - 'по размеру'
    - 'по расхождению SI и FN времён'
    - 'по имени'
    - 'по расширению'
  answer: 1
  explanation: 'SI и FN хранят разные метки; расхождение выдаёт подделку.'
- question: Что фиксирует $LogFile?
  options:
    - 'сеть'
    - 'транзакции метаданных ФС'
    - 'пароли'
    - 'обои'
  answer: 1
  explanation: '$LogFile — журнал изменений метаданных.'
- question: Чем полезен $UsnJrnl?
  options:
    - 'хранит контент'
    - 'журнал изменений, устойчивый к очистке MFT'
    - 'шифрует'
    - 'сканирует порты'
  answer: 1
  explanation: 'USN-журнал фиксирует изменения файлов по причинам.'
```
