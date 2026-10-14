---
id: macos-timemachine
title: 'Time Machine и локальные снимки APFS: удалённые версии файлов'
category: forensics
parent: forensics-macos-system
difficulty: medium
order: 3
tags: [macos, timemachine, apfs, snapshots, recovery, forensics]
prerequisites: [forensics-macos-artifacts]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как использовать снимки Time Machine и APFS для восстановления удалённых или изменённых файлов и построения истории.'
lab:
  kind: shell
  title: "Практика: локальные снимки APFS"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, timemachine_snapshots.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "APFS-снимки дают версии тома во времени."
    - "Снимок от 2026-02-09 хранит удалённый файл."
    - "`grep nto timemachine_snapshots.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Файл удалён, диск зашифрован, индексы подчищены. Но macOS **сама** хранит снимки:
локальные снимки APFS и бэкапы Time Machine. Из них можно достать версии файлов,
которых уже нет. Это один из самых недооценённых источников.

## Наш пример: локальный снимок

## Шаг 1: список локальных снимков

```
$ tmutil listlocalsnapshots /
com.apple.TimeMachine.2026-01-14-020000.local
com.apple.TimeMachine.2026-01-14-030000.local
```

Локальные снимки создаются ежечасно и хранят состояние диска. Их можно монтировать
только для чтения.

## Шаг 2: монтируем снимок

```
$ mkdir /tmp/snap
$ mount_apfs -s com.apple.TimeMachine.2026-01-14-030000.local / /tmp/snap
$ ls /tmp/snap/Users/user/Downloads/
payload.dmg
```

Мы видим файл `payload.dmg`, который в текущей системе, возможно, уже удалён. Снимок
зафиксировал состояние на 03:00.

## Шаг 3: сравниваем версии

```
$ diff /tmp/snap/Users/user/.bash_history ~/.bash_history
```

Разница покажет, что злоумышленник дописал (или удалил) после снимка. Это прямые улики.

## Шаг 4: внешний Time Machine

Если есть внешний диск:

```
$ tmutil listbackups
/Volumes/Backup/Backups.backupdb/mac/2026-01-14-030000
$ tmutil compare
```

Бэкапы хранят историю за недели. Из них восстанавливают и файлы, и целые системы.

## Шаг 5: что это даёт

- **удалённые файлы** — версии из снимка;
- **timestomping** — сравнение меток между снимками;
- **история правок** — что менялось между снимками;
- **доказательство** — снимок нельзя изменить задним числом.

## Что мы теперь знаем

- macOS хранит локальные снимки APFS ежечасно.
- `tmutil listlocalsnapshots` и `mount_apfs` дают доступ.
- Внешние бэкапы Time Machine хранят историю за недели.
- Сравнение версий ловит удаления и подделки.
- Снимки — доказательство, которое трудно подделать.

## Если не сработало

- Снимков нет? Проверь `tmutil listlocalsnapshots` по всем томам.
- Снимок повреждён? Пробуй соседние.
- Нужен бэкап с другого Mac? Смотри `Backups.backupdb`.

## Квиз

Проверь себя.

```quiz
- question: Как часто macOS создаёт локальные снимки APFS?
  options:
    - 'раз в год'
    - 'примерно ежечасно'
    - 'никогда'
    - 'раз в месяц'
  answer: 1
  explanation: 'Time Machine делает локальные снимки примерно каждый час.'
- question: Как смонтировать локальный снимок?
  options:
    - 'mount /dev/sda1'
    - 'mount_apfs -s <snapshot>'
    - 'cp'
    - 'grep'
  answer: 1
  explanation: 'mount_apfs -s монтирует снимок только для чтения.'
- question: Чем полезно сравнение снимков?
  options:
    - 'экономит место'
    - 'показывает удаления и подделки меток'
    - 'ускоряет систему'
    - 'шифрует диск'
  answer: 1
  explanation: 'Diff версий выявляет изменения между моментами снимков.'
- question: Какая команда перечисляет бэкапы Time Machine?
  options:
    - 'ls'
    - 'tmutil listbackups'
    - 'df'
    - 'stat'
  answer: 1
  explanation: 'tmutil управляет Time Machine и показывает список бэкапов.'
```
