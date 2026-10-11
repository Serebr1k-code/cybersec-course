---
id: reversing-mod-debuggers
title: "Модуль: Современные отладчики и точки наблюдения"
category: reversing
parent: reversing-module-advanced
difficulty: medium
order: 1
tags: [reversing, rizin, lldb, x64dbg, windbg, watchpoints, roadmap]
prerequisites: [reversing-intro]
useful_for:
  - "CTF Reversing: точная отладка сложных бинарников"
  - "Malware analysis: отладка под Windows и macOS"
estimated_minutes: 6
summary: "Подмодуль об отладочном инструментарии: rizin/Cutter, LLDB, Windows-отладчики (x64dbg/WinDbg), аппаратные breakpoints и watchpoints."
---

GDB — не единственный отладчик, и часто не лучший. Для Windows это x64dbg и WinDbg, для macOS —
LLDB, для быстрого интерактивного разбора — rizin/Cutter. А когда программные breakpoints
бесполезны (код расшифровывается на лету), на первый план выходят аппаратные точки останова и
watchpoints, следящие за чтением/записью памяти.

## Что покрывает подмодуль

- **reversing-rizin-cutter** — rizin (форк radare2) и графический Cutter: анализ, эмуляция,
  скрипты на r2pipe/Python, визуальный граф функций.
- **reversing-lldb** — LLDB: команды, Python-скриптинг, отладка Mach-O и ядра, интеграция с Xcode.
- **reversing-windows-debuggers** — x64dbg и WinDbg: скрипты, плагины, расширения `!analyze`,
  анализ дампов и структур Windows.
- **reversing-watchpoints-hwbp** — аппаратные точки останова (DR0–DR7), watchpoints на
  чтение/запись, ограничения (4 точки), применение к самомодифицирующемуся коду.

## Почему такой порядок

Инструменты идут от кроссплатформенного и лёгкого (rizin/Cutter) к платформенным (LLDB, Windows).
Аппаратные точки наблюдения — отдельный навык поверх любого отладчика, поэтому замыкают подмодуль:
они нужны, когда обычные средства не работают.

## Что вы будете уметь

- Выбирать отладчик под платформу и задачу и уверенно им пользоваться.
- Писать скрипты автоматизации для rizin/LLDB/WinDbg.
- Ставить аппаратные watchpoints на адрес памяти и ловить момент расшифровки/записи.
- Отлаживать бинарники там, где программные breakpoints неэффективны.

## Квиз

```quiz
- question: "Сколько аппаратных точек останова доступно на x86-64 обычно?"
  options:
    - "4"
    - "1"
    - "16"
    - "Неограниченно"
  answer: 0
- question: "Для чего используют watchpoint?"
  options:
    - "Остановиться при чтении/записи по адресу памяти"
    - "Ускорить выполнение"
    - "Подменить библиотеку"
    - "Распаковать бинарник"
  answer: 0
- question: "Какой отладчик штатный для macOS?"
  options:
    - "LLDB"
    - "WinDbg"
    - "x64dbg"
    - "OllyDbg"
  answer: 0
```

## Где пригодится

- **CTF Reversing:** crackme с самомодифицирующимся кодом, упакованные бинарники.
- **Malware analysis:** отладка Windows-образцов, анализ дампов.
- **Vuln research:** точное наблюдение за доступом к памяти при эксплуатации.
