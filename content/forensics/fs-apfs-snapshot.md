---
id: fs-apfs-snapshot
title: 'APFS-снимки: версии тома во времени'
category: forensics
parent: forensics-fs-extra
difficulty: hard
order: 1
tags: [forensics, apfs, snapshot, macos, filesystem]
prerequisites: [forensics-fs-structure]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как устроены снимки APFS, как их монтировать и доставать из них удалённые или изменённые файлы.'
lab:
  kind: shell
  title: "Практика: снимок APFS"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, apfs_snapshots.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "APFS-снимок фиксирует версию тома; удалённые файлы в нём ещё есть."
    - "Снимок от 2026-02-09 — цель."
    - "`grep nto apfs_snapshots.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

На Mac файл изменён, а нужна его прежняя версия. APFS — copy-on-write ФС, поэтому старые
версии могут оставаться в **снимках** (snapshots). Разберём, как их найти и смонтировать.

## Наш пример: том APFS

## Шаг 1: что такое снимок APFS

Снимок — это «замороженное» состояние тома: все блоки на момент создания. Благодаря
copy-on-write, снимок занимает мало места, пока данные не меняются.

```
$ diskutil apfs listSnapshots /dev/disk1s1
Snapshots for disk1s1:
com.apple.TimeMachine.2026-01-14-030000.local
```

## Шаг 2: монтируем снимок

На macOS:

```
$ mkdir /tmp/snap
$ mount_apfs -s com.apple.TimeMachine.2026-01-14-030000.local /dev/disk1s1 /tmp/snap
```

На Linux/Windows (по образу) — `apfs-fuse`:

```
$ apfs-fuse -s 1 disk.img /mnt/apfs
```

`-s` указывает номер снимка.

## Шаг 3: достаём старые версии

В смонтированном снимке видны файлы на тот момент:

```
$ ls /tmp/snap/Users/user/Documents/
old_report.pdf
```

Файл, удалённый сейчас, в снимке ещё есть.

## Шаг 4: сравнение

```
$ diff /tmp/snap/Users/user/.bash_history ~/.bash_history
```

Разница показывает изменения — то, что дописал или удалил злоумышленник.

## Шаг 5: что искать

- удалённые файлы;
- прежние версии документов;
- историю правок;
- доказательства времени.

## Что мы теперь знаем

- APFS copy-on-write хранит старые версии в снимках.
- `diskutil`/`mount_apfs`/`apfs-fuse` дают доступ.
- В снимке видны удалённые файлы.
- Сравнение выявляет изменения.
- Снимок — надёжное доказательство.

## Если не сработало

- Снимков нет? Проверь все тома.
- Образ не читается? Укажи номер снимка в apfs-fuse.
- Нужен контент? Монтируй и копируй.

## Квиз

Проверь себя.

```quiz
- question: Что хранит снимок APFS?
  options:
    - 'только метаданные'
    - 'состояние тома на момент создания'
    - 'пароли'
    - 'сеть'
  answer: 1
  explanation: 'Снимок фиксирует все блоки тома благодаря copy-on-write.'
- question: Как смонтировать снимок APFS на Linux?
  options:
    - 'mount'
    - 'apfs-fuse -s <номер>'
    - 'cp'
    - 'tar'
  answer: 1
  explanation: 'apfs-fuse с -s монтирует конкретный снимок.'
- question: Почему снимок полезен для восстановления удалённого?
  options:
    - 'он быстрый'
    - 'в нём файл ещё существует'
    - 'он шифрует'
    - 'он маленький'
  answer: 1
  explanation: 'Снимок хранит состояние до удаления.'
- question: Что даёт сравнение снимка с текущим томом?
  options:
    - 'ничего'
    - 'выявляет изменения (дописки/удаления)'
    - 'шифрует'
    - 'ускоряет'
  answer: 1
  explanation: 'Diff показывает, что изменилось после снимка.'
```
