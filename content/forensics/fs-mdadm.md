---
id: fs-mdadm
title: 'mdadm: сборка программного RAID для анализа'
category: forensics
parent: forensics-fs-extra
difficulty: hard
order: 4
tags: [forensics, mdadm, raid, linux, filesystem]
prerequisites: [forensics-fs-structure]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как собрать программный RAID (mdadm) из отдельных дисков, чтобы получить цельный образ для анализа.'
lab:
  kind: shell
  title: "Практика: сборка RAID через mdadm"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, mdadm_scan.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "mdadm --assemble собирает цельный массив из отдельных дисков."
    - "Все члены md0 должны быть active sync."
    - "`grep nto mdadm_scan.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Пришли четыре диска — по отдельности непонятные. Вместе они образуют RAID-массив.
Чтобы анализировать, нужно **собрать** их обратно. Разберём `mdadm`.

## Наш пример: RAID из четырёх дисков

## Шаг 1: определяем метаданные

Linux-RAID хранит метаданные в суперблоке. Посмотрим:

```
$ mdadm --examine /dev/sdb1
/dev/sdb1:
   Magic : a92b4efc
   Array UUID : 1a2b3c4d:...
   Raid Level : raid5
   Devices : 4
```

Здесь видно уровень (raid5), UUID массива и число устройств.

## Шаг 2: собираем

Собираем по копиям (чтобы не трогать оригиналы):

```
$ mdadm --assemble --readonly /dev/md0 /dev/sdb1 /dev/sdc1 /dev/sdd1 /dev/sde1
mdadm: /dev/md0 has been started with 4 drives.
```

`--readonly` — критично: массив может запустить восстановление и изменить диски.

## Шаг 3: монтируем

```
$ mount -o ro /dev/md0 /mnt/raid
```

Если ФС распознана — читаем как обычный диск.

## Шаг 4: если сборка не идёт

- **не хватает диска** (degraded) — можно собрать в degraded-режиме;
- **неправильный порядок** — задай вручную (`--force` с порядком);
- **разные размеры** — учитывай.

```
$ mdadm --assemble --readonly --force /dev/md0 ...
```

## Шаг 5: определение уровня

- **RAID0** — страйп (нет избыточности);
- **RAID1** — зеркало;
- **RAID5/6** — чётность (нужны все, кроме одного/двух);
- **RAID10** — зеркало+страйп.

Уровень определяет, сколько дисков обязательно.

## Что мы теперь знаем

- `mdadm --examine` читает суперблок.
- `--assemble --readonly` собирает массив.
- Монтируем как обычный диск.
- Degraded-сборка возможна.
- Уровень определяет требования к дискам.

## Если не сработало

- Не собирается? Проверь уровень и UUID.
- Нужен порядок? Задай вручную.
- Диск мёртв? RAID5/6 переживёт один/два.

## Квиз

Проверь себя.

```quiz
- question: Что показывает mdadm --examine?
  options:
    - 'пароли'
    - 'суперблок: уровень, UUID, число устройств'
    - 'сеть'
    - 'обои'
  answer: 1
  explanation: 'Examine читает метаданные RAID-диска.'
- question: Зачем --readonly при сборке?
  options:
    - 'для скорости'
    - 'чтобы массив не изменил диски (восстановление)'
    - 'для шифрования'
    - 'для сети'
  answer: 1
  explanation: 'Автосборка может запустить ребилд и изменить улики.'
- question: Сколько дисков нужно для RAID5?
  options:
    - '1'
    - 'минимум 3 (переживёт потерю 1)'
    - '2'
    - '10'
  answer: 1
  explanation: 'RAID5 требует ≥3 дисков и выдерживает отказ одного.'
- question: Что такое degraded-сборка?
  options:
    - 'сборка без части дисков'
    - 'шифрование'
    - 'форматирование'
    - 'обновление'
  answer: 0
  explanation: 'Массив можно собрать, потеряв диск (для RAID1/5/6).'
```
