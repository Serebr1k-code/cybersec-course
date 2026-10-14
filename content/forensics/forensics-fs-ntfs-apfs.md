---
id: forensics-fs-ntfs-apfs
title: "Модуль: NTFS и APFS"
category: forensics
parent: forensics-fs-internals
difficulty: medium
order: 2
tags: [forensics, module, roadmap]
prerequisites: [forensics-fs-internals]
useful_for:
- CTF Forensics.
- DFIR Windows/macOS.
- Экспертиза.
estimated_minutes: 10
summary: "Внутренности ntfs ($mft, $logfile, $usnjrnl, ads) и артефакты apfs/macos"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «NTFS и APFS»: внутренности NTFS ($MFT, $LogFile, $UsnJrnl, ADS) и артефакты APFS/macOS.

- **forensics-ntfs-mft** — NTFS изнутри: $MFT, $LogFile, $UsnJrnl, ADS.
- **forensics-apfs** — APFS и артефакты macOS.

## Почему такой порядок

NTFS и APFS — доминирующие ФС Windows и macOS, их артефакты — основа расследований.

## Что вы сможете после этапа

- Читать $MFT и USN-журнал.
- Разбирать артефакты APFS.

## Квиз

Проверь себя.

```quiz
- question: Что такое $MFT?
  options:
    - "Главная таблица файлов NTFS"
    - "Формат образа"
    - "Тип раздела"
    - "Сетевой протокол"
  answer: 0
  explanation: $MFT хранит записи о всех файлах.
- question: Что фиксирует $UsnJrnl?
  options:
    - "Изменения файлов и папок"
    - "Пароли"
    - "Сеть"
    - "GPS"
  answer: 0
  explanation: USN-журнал логирует изменения в томе.
- question: Что такое APFS-снапшот?
  options:
    - "Снимок состояния ФС"
    - "Формат файла"
    - "Тип ключа"
    - "Сетевой протокол"
  answer: 0
  explanation: APFS хранит мгновенные снимки тома.
```

## Где пригодится

- CTF Forensics.
- DFIR Windows/macOS.
- Экспертиза.
