---
id: forensics-win-execution
title: "Модуль: артефакты выполнения и активности пользователя"
category: forensics
parent: forensics-windows-artifacts
difficulty: hard
order: 3
tags: [windows, execution, prefetch, shimcache, shellbags, lnk, wmi, roadmap]
prerequisites: [forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 14
summary: "Первый этап артефактов Windows: доказательства запуска программ и работы пользователя (Prefetch/ShimCache, Shellbags, LNK, WMI) — что читать."
lab:
  kind: shell
  title: "Практика: доказать запуск (Prefetch + AmCache)"
  toolset: [core, hex, dfir]
  workdir: /home/student/task
  files: [task.md, notes.txt, POWERSHELL.EXE-1A2B3C4D.pf, amcache.csv]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Подтверди формат Prefetch: `xxd -l 16 POWERSHELL.EXE-1A2B3C4D.pf` (магия `SCCA`)."
    - "Разбери Prefetch: `PECmd POWERSHELL.EXE-1A2B3C4D.pf`."
    - "Посмотри AmCache: `grep nto amcache.csv`."
    - "Загляни в строки Prefetch: `strings POWERSHELL.EXE-1A2B3C4D.pf | grep nto{`."
---

Первый и самый важный вопрос при расследовании Windows — **что запускалось и что открывал пользователь**. Этот модуль собирает артефакты «активности»: следы выполнения программ и навигации по файловой системе. Это ядро доказательной базы по инциденту.

## Что покрывает этот модуль

- **Выполнение программ** — Prefetch, Amcache, ShimCache (AppCompatCache).
- **Навигация пользователя** — Shellbags, UserAssist, RecentDocs.
- **Ярлыки и jump lists** — LNK-файлы и списки недавних файлов.
- **WMI** — репозиторий WMI и его следы активности.

## Рекомендуемый порядок изучения

1. `forensics-windows-execution` — доказательства запуска программ.
2. `forensics-shellbags` — навигация по папкам, включая удалённые и съёмные.
3. `forensics-lnk` — ярлыки и jump lists как источник путей и томов.
4. `forensics-wmi` — репозиторий WMI и следы автоматизации.

Порядок от самого прямого доказательства (запуск) к косвенным (навигация, ярлыки, WMI), которые дополняют картину.

## Что вы будете уметь

- Доказывать факт запуска программы и время её выполнения.
- Определять, какие папки и файлы открывал пользователь.
- Связывать ярлыки с томами и сетевыми путями.
- Извлекать артефакты WMI и понимать их роль в атаках.

## Инструмент: PECmd (разбор Prefetch)

Файл Prefetch (`*.pf`) доказывает, что программа запускалась. Читают его
утилитой PECmd:

```
$ PECmd POWERSHELL.EXE-1A2B3C4D.pf
POWERSHELL.EXE-1A2B3C4D.pf
  Run count:   3
  Last run:    2026-02-10 09:14:03
  Volume:      \VOLUME{...}
  Directories: \DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32
```

Магия `SCCA` в начале файла подтверждает формат. Сопоставив `Run count` и
время последнего запуска с AmCache, можно доказать факт исполнения даже без
других следов.

## Квиз

```quiz
- question: "Какой артефакт Windows доказывает факт запуска программы и число её запусков?"
  options:
    - "Shellbags"
    - "Prefetch"
    - "Recycle Bin"
    - "EVTX Security"
  answer: 1
  explanation: "Prefetch хранит записи о запуске и счётчик запусков."
- question: "Что доказывают Shellbags, даже если папка уже удалена?"
  options:
    - "Запуск программы"
    - "Что пользователь открывал эту папку в проводнике"
    - "Сетевой трафик"
    - "Шифрование диска"
  answer: 1
  explanation: "Shellbags кэшируют настройки отображения папок и сохраняют их путь."
- question: "Почему WMI-артефакты важны при hunt за атакующими?"
  options:
    - "Они всегда пусты"
    - "WMI часто используется для разведки и персистентности"
    - "Они хранят пароли в открытом виде"
    - "Они заменяют MFT"
  answer: 1
  explanation: "Злоумышленники применяют WMI для сбора данных и закрепления в системе."
```

## Где пригодится

- **CTF:** задачи с реестром и артефактами Windows.
- **DFIR:** установление факта запуска и активности пользователя.
- **Threat Hunting:** поиск подозрительных запусков и навигации.
- **Работа:** SOC/IR, поддержка расследований.
