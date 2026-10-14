---
id: forensics-fs-linux-cow
title: "Модуль: Linux и CoW-ФС"
category: forensics
parent: forensics-fs-internals
difficulty: medium
order: 1
tags: [forensics, module, roadmap]
prerequisites: [forensics-fs-internals]
useful_for:
- CTF Forensics.
- DFIR Linux.
- Экспертиза серверов.
estimated_minutes: 10
summary: "Журнал ext4, cow-фс (btrfs/zfs/xfs) и снапшоты"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Linux и CoW-ФС»: журнал ext4, CoW-ФС (Btrfs/ZFS/XFS) и снапшоты.

- **forensics-ext4-journal** — ext4 изнутри: журнал, inode, extent-дерево.
- **forensics-btrfs-zfs** — Btrfs / ZFS / XFS: форензика copy-on-write ФС.
- **fs-btrfs-snapshot** — Btrfs: форензика снапшотов и subvolume.
- **fs-zfs-arc-zil** — ZFS: uberblock, ARC, ZIL и SLOG в форензике.

## Почему такой порядок

Журналы и CoW-механизмы хранят историю изменений — ключ к восстановлению картины.

## Что вы сможете после этапа

- Читать журнал ext4.
- Анализировать снапшоты и ZIL/ARC.

## Квиз

Проверь себя.

```quiz
- question: Что хранит журнал ext4?
  options:
    - "Историю операций с метаданными"
    - "Пароли"
    - "DNS-кэш"
    - "GPS"
  answer: 0
  explanation: Журнал фиксирует изменения метаданных.
- question: Чем полезна CoW-ФС для форензики?
  options:
    - "Старые версии данных остаются на диске"
    - "Она быстрее"
    - "Она дешевле"
    - "Она шифрует"
  answer: 0
  explanation: Copy-on-write сохраняет прежние блоки.
- question: Что такое ZIL в ZFS?
  options:
    - "Журнал намерений для синхронных записей"
    - "Тип раздела"
    - "Сетевой протокол"
    - "Формат файла"
  answer: 0
  explanation: ZIL ускоряет синхронные записи.
```

## Где пригодится

- CTF Forensics.
- DFIR Linux.
- Экспертиза серверов.
