---
id: reversing-cfg-guard-cet
title: 'CFG / Control-Flow Guard и Intel CET как препятствие реверсу'
category: reversing
parent: reversing-mod-obf2
difficulty: hard
order: 4
tags: [reversing, obfuscation, cfg, cet, endbr64, control-flow-integrity]
prerequisites: [reversing-anti-disassembly]
useful_for:
  - 'Анализ защищённых бинарников'
  - 'Windows internals'
  - 'Обход защит при реверсе'
estimated_minutes: 50
summary: 'Как CFG (Windows) и Intel CET (endbr64/shadow stack) меняют вид кода и мешают анализу и патчам.'
lab:
  kind: shell
  title: 'Практика: бинарник с CFG/CET'
  toolset: [core, hex, file]
  workdir: /home/student/task
  files: [task.md, hardened.exe]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`file hardened.exe` — PE-файл.'
    - '`strings -n 5 hardened.exe` — ищи метки CFG/CET.'
    - 'Ищи `endbr64`, `CET`, `GuardCF`.'
    - '`strings -n 5 hardened.exe > out.txt`, затем `grep nto out.txt > found.txt` и `check`.'
---

## Вопрос, с которого всё начинается

Ты открыл бинарник `hardened.exe`, а дизассемблер показывает странные инструкции `endbr64` перед каждой функцией и какие-то таблицы в `.rdata`. Обычные патчи (заменить `jne` на `nop`) приводят к падению. Что это за защита?

## Наш пример

Смотрим на файл:

```
$ file hardened.exe
hardened.exe: PE32+ executable (console) x86-64, for MS Windows
```

Обычный PE, но внутри — механизмы **Control-Flow Integrity** (CFI): Windows **CFG** (Control Flow Guard) и Intel **CET** (Control-flow Enforcement Technology). Разберём, как они видны и почему мешают.

## Шаг 1: что такое CFI

**Control-Flow Integrity** — защита, которая разрешает косвенные переходы (через указатели, таблицы) только к легитимным целям. Обычный `call rax` может прыгнуть куда угодно; с CFI процессор/ОС сначала проверяет, что цель — допустимая точка входа.

Это ломает эксплуатацию (нельзя прыгнуть в середину функции) и усложняет реверс (патчи нарушают проверки).

## Шаг 2: Intel CET и endbr64

Intel CET добавляет **теневой стек** (shadow stack) для защиты возвратов и **IBT** (Indirect Branch Tracking): косвенный переход обязан вести на инструкцию `endbr64` (End Branch 64). Компилятор ставит `endbr64` в начало каждой функции-цели.

Поэтому в листинге каждая функция начинается с `f3 0f 1e fa`:

```
000000000140001000 <main>:
  140001000: f3 0f 1e fa    endbr64
  140001004: 55             push rbp
```

Для реверсера `endbr64` — удобный маркер начала функции. Но если ты патчишь код и ломаешь `endbr64`, косвенный вызов упадёт.

## Шаг 3: Windows CFG и таблицы

Windows CFG работает иначе: в бинарнике есть таблица допустимых адресов (Guard CF Function Table), а вызовы косвенных переходов проходят через `_guard_check_icall`. Признаки: строки `__guard_check_icall_fptr`, `GuardCFCheckFunctionPointer`, таблица в `.rdata`.

Если ты добавишь свою функцию или патч, её адреса нет в таблице — косвенный вызов к ней заблокируется.

## Шаг 4: как это мешает патчить

Классические патчи ломаются:

- вставка кода в новое место → адрес не в CFG-таблице;
- перезапись `endbr64` → нарушение IBT;
- возврат по адресу не из тени → падение на shadow stack.

Поэтому приходится либо работать в рамках легитимных целей, либо снимать защиту (патчить саму проверку/`endbr64` целиком), либо эмулировать код (CET в Unicorn можно отключить).

## Шаг 5: что делать реверсеру

Практический подход:

1. Определить, включён ли CFG/CET (по строкам, по наличию `endbr64`, по флагам PE).
2. При статическом анализе — не путать `endbr64` с полезным кодом.
3. При патчах — сохранять `endbr64` или обновлять CFG-таблицу.
4. Для эмуляции — отключать проверки в эмуляторе.

## Шаг 6: артефакт

Найдём метки защиты:

```
$ strings -n 5 hardened.exe | grep -Ei 'cet|guard|endbr'
endbr64
GuardCFCheckFunctionPointer
nto{cf1_3ndbr64_sh4d0w_stack}
```

Строка `GuardCFCheckFunctionPointer` подтверждает CFG, `endbr64` — CET. В реальном анализе это первые подсказки о защите.

## Что мы теперь знаем

- CFI разрешает косвенные переходы только к легитимным целям.
- Intel CET: `endbr64` в начале функций + теневой стек для возвратов.
- Windows CFG: таблица допустимых адресов + `_guard_check_icall`.
- Патчи ломаются, если нарушить `endbr64`/таблицу/shadow stack.
- Реверсер учитывает защиту и обходит её осознанно.

## Квиз

Проверь себя.

```quiz
- question: "Что означает инструкция endbr64 в начале функции?"
  options:
    - "Легитимную точку входа для косвенного перехода (Intel CET/IBT)"
    - "Конец функции"
    - "Вызов системной функции"
    - "Сохранение стека"
  answer: 0
  explanation: "IBT требует, чтобы косвенный переход вёл на endbr64."
- question: "Как Windows CFG проверяет косвенный вызов?"
  options:
    - "Через таблицу допустимых адресов (Guard CF Function Table) и guard_check_icall"
    - "Через пароль"
    - "Через шифрование кода"
    - "Через антивирус"
  answer: 0
  explanation: "CFG сверяет цель с таблицей допустимых точек входа."
- question: "Почему патч может сломать CET?"
  options:
    - "Он нарушает endbr64 или возврат по адресу не из теневого стека"
    - "Он меняет цвет"
    - "Он уменьшает файл"
    - "Он добавляет строку"
  answer: 0
  explanation: "IBT и shadow stack проверяют целостность переходов/возвратов."
- question: "Что делать при эмуляции кода с CET?"
  options:
    - "Отключить проверки в эмуляторе"
    - "Запустить на реальном CPU"
    - "Удалить endbr64 из файла"
    - "Ничего, CET не влияет"
  answer: 0
  explanation: "Эмулятор позволяет не эмулировать проверки IBT/shadow stack."
```

## Куда дальше

Дальше — лицензионные схемы и offline-активация: ещё один слой защит. Пока главное запомни: **CFG/CET — это маркеры `endbr64` и таблицы; патчи должны их учитывать, иначе бинарник упадёт**.

## Где пригодится

- **Анализ защищённых бинарников:** понимание CFI.
- **Windows internals:** CFG и его таблицы.
- **Обход защит:** осознанное снятие CFI при реверсе.
