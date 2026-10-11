---
id: reversing-lldb
title: "LLDB: отладка под macOS и Linux"
category: reversing
parent: reversing-mod-debuggers
difficulty: medium
order: 1
tags: [reversing, lldb, macos, gdb, python, debugger]
prerequisites: [reversing-intro]
useful_for:
  - "CTF Reversing: отладка Mach-O/ELF"
  - "Mobile: отладка iOS-приложений"
  - "Malware analysis: отладка под macOS"
estimated_minutes: 55
summary: "LLDB: базовые и продвинутые команды, точки останова и watchpoints, Python-скриптинг, отладка Mach-O и iOS, практические сценарии и сравнение с gdb."
---

LLDB — отладчик из проекта LLVM, штатный инструмент для macOS и Xcode. Он заменил GDB в экосистеме
Apple и активно используется для отладки C/C++/Rust/Swift, а также для анализа Mach-O и iOS-
приложений. Синтаксис команд отличается от GDB, но возможности те же: точки останова, просмотр
памяти, пошаговое исполнение, скрипты. Если вы работаете с macOS или iOS, LLDB — обязательный
навык; на Linux он тоже доступен и иногда удобнее gdb (особенно с Python 3).

## Почему LLDB, а не gdb

На macOS `gdb` официально не поддерживается (проблемы с подписью и `task_for_pid`); `lldb` —
штатный отладчик. Он интегрирован в Xcode, поддерживает Swift-выражения и современный DWARF.
На Linux LLDB также работает и предоставляет удобный Python-API (`SBFrame`, `SBValue`,
`SBProcess`). Главное отличие в синтаксисе: вместо `b` — `breakpoint set`, вместо `p` — `expression`
(сокращённо `expr`/`p`), вместо `info registers` — `register read`.

## Запуск и базовые команды

Запуск: `lldb ./crackme`, затем `run` (или `r`). Аргументы передаются через `settings set
target.run-args` или прямо в `run arg1 arg2`. Базовые команды:

| Команда LLDB | Аналог gdb | Действие |
|---|---|---|
| `run` / `r` | `run` | запустить |
| `breakpoint set -n main` | `break main` | точка останова по имени |
| `breakpoint set -a 0x1140` | `break *0x1140` | по адресу |
| `continue` / `c` | `continue` | продолжить |
| `next` / `n` | `next` | шаг через вызов |
| `step` / `s` | `step` | шаг внутрь |
| `finish` | `finish` | до конца функции |
| `register read` / `reg r` | `info registers` | регистры |
| `memory read` / `x` | `x` | чтение памяти |
| `expression` / `p` | `print` | вычислить выражение |
| `bt` | `bt` | стек вызовов |
| `disassemble` / `dis` | `disas` | дизассемблировать |

Проверка состояния: `frame variable` (`fr v`) показывает локальные переменные текущего кадра;
`thread backtrace all` — стек всех потоков.

## Точки останова

LLDB гибко настраивает breakpoints. `breakpoint set -n <symbol>` ставит по имени,
`breakpoint set -a <addr>` — по адресу, `breakpoint set -r <regex>` — по регулярному выражению
имени, `breakpoint set -s <lib> -n <func>` — в конкретной библиотеке. Условные: `breakpoint set -n
verify -c '(int)$rdi > 0'`. После установки можно добавлять команды, исполняемые при срабатывании:
`breakpoint command add 1 -o 'register read rax' -o 'continue'`.

Watchpoints: `watchpoint set expression -w write -- 0x1000` следит за записью по адресу,
`-w read` — за чтением. Это аппаратные точки (DR-регистры), их доступно 4. Они незаменимы, когда
надо поймать момент, когда программа расшифровывает или перезаписывает данные, а программный
breakpoint поставить негде.

## Просмотр памяти и регистров

`memory read` (`x`) читает память с форматом: `x/16xb 0x1000` — 16 байт hex, `x/s 0x2000` — строку,
`x/8gx $rsp` — 8 64-битных слов со стека. `register read rax` (`reg r rax`) читает регистр;
`register write rax 0x10` — пишет. `expression` умеет вызывать функции в контексте процесса:
`expr (int)puts("hi")` напечатает строку прямо из отладчика — полезно для проверки гипотез. Также
`image lookup -a 0x1140` скажет, в какой функции и по какому смещению находится адрес.

## Python-скриптинг

LLDB имеет полноценный Python-API. Скрипт может автоматизировать анализ:

```python
import lldb
def run(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    frame = process.GetSelectedThread().GetSelectedFrame()
    # пройтись по аргументам strcmp
    rdi = frame.FindRegister("rdi").GetValueAsUnsigned()
    rsi = frame.FindRegister("rsi").GetValueAsUnsigned()
    s1 = process.ReadCStringFromMemory(rdi, 256, lldb.SBError())
    s2 = process.ReadCStringFromMemory(rsi, 256, lldb.SBError())
    print("strcmp(%r, %r)" % (s1, s2))
lldb.debugger.HandleCommand('command script add -f hook.run mystrcmp')
```

Загрузив скрипт (`command script import hook.py`), вы получаете команду `mystrcmp`. Типовой приём:
поставить breakpoint на `strcmp` с командой, которая печатает оба аргумента и продолжает — так
собираются все сравнения, которые делает crackme. На macOS аргументы передаются в `rdi`/`rsi`
(x86-64) или `x0`/`x1` (arm64).

## Отладка Mach-O и iOS

LLDB — основной инструмент для iOS. Отладка приложения на устройстве: запуск через `debugserver`
на устройстве и подключение с хоста (`process connect connect://device:port`). На симуляторе проще:
`lldb` + `run`. Для iOS-приложений из App Store бинарник зашифрован (FairPlay), поэтому сначала
нужно снять шифрование (например, `frida-ios-dump`), а затем отлаживать. Для перехвата методов
Objective-C удобно ставить breakpoint на `objc_msgSend` и смотреть селектор.

Особенность Mach-O: адреса начинаются с `0x100000000` (база `__TEXT`), и при ASLR реальная база
сдвигается. `image list` показывает загруженные образы и их базы; `image lookup -n <func>` находит
символ с учётом слайдов.

## Практический разбор

Разберём crackme, где пароль проверяется через `strcmp`:

```
$ lldb ./crackme
(lldb) target create "./crackme"
(lldb) breakpoint set -n strcmp
Breakpoint 1: where = crackme`strcmp, address = 0x...
(lldb) run
Process launched
Process stopped
* thread #1, stop reason = breakpoint 1.1
    frame #0: libsystem_c.dylib`strcmp
(lldb) register read rdi rsi
     rdi = 0x0000000100002004  "secret"
     rsi = 0x00007ffeefbff8a0  "hunter2"
(lldb) memory read --format c --size 1 --count 20 $rsi
0x7ffeefbff8a0: hunter2
(lldb) continue
```

Здесь сразу видно, что ожидаемый пароль — `secret`, а введён — `hunter2`. Точка останова на
`strcmp` — универсальный приём: она показывает все сравнения строк.

## Инструменты и флаги

| Задача | Команда LLDB |
|---|---|
| Точка по имени | `br s -n func` |
| Точка по адресу | `br s -a 0x...` |
| Условная | `br s -n f -c 'cond'` |
| Команды на bp | `br command add <id>` |
| Watchpoint | `watch s e -w write -- addr` |
| Память | `x/16xb addr`, `x/s addr` |
| Регистры | `reg r`, `reg w rax 0x10` |
| Выражение | `expr ...` |
| Образ | `image lookup -n func` |
| Скрипт | `command script import x.py` |

## Swift и Objective-C в LLDB

LLDB — единственный отладчик с первоклассной поддержкой Swift. Выражения `expression` понимают
синтаксис Swift, умеют работать с `String`, `Array`, опциональными типами и протоколами. Для
реверса Swift-приложений это бесценно: вместо ручного разбора mangled-имён (`$s...`) вы пишете
`expression someSwiftFunction()` и видите результат. Деманглинг имён — команда `image lookup -n`
или `swift demangle`.

Для Objective-C ключевой инструмент — перехват `objc_msgSend`, через который проходят все вызовы
методов. Поставив breakpoint на `objc_msgSend`, можно логировать селекторы и объекты-получатели:

```
(lldb) br s -n objc_msgSend
(lldb) br command add 1
> po $rdi           # объект-получатель
> p (char*)$rsi     # селектор (SEL)
> c
> DONE
```

Так вы видите последовательность вызовов методов и быстро локализуете проверку. Для Swift-классов
аналогично работают breakpoints по символам после деманглинга.

## Удалённая отладка и ядро

LLDB поддерживает удалённую отладку: `platform select remote-ios`, затем `process connect
connect://<device>:<port>` после запуска `debugserver` на устройстве. Это штатный способ отладки
iOS-приложений и драйверов. На Linux можно подключаться к `gdbserver` или `lldb-server`:
`lldb-server gdbserver :1234 ./bin` на целевой машине и `gdb-remote 1234` на хосте.

Отладка ядра macOS (`kernel debugging`) также выполняется через LLDB с `kdp-remote`. Для
большинства CTF и malware-задач это избыточно, но знание о существовании этих возможностей полезно:
если цель — драйвер или системный компонент, LLDB остаётся основным инструментом под Apple.

## Подводные камни

Первое: синтаксис команд отличается от gdb — `p` в LLDB это `expression`, а не `print` в смысле
gdb; будьте внимательны при переносе скриптов. Второе: `breakpoint set -n main` не сработает, если
символ mangled или stripped. Третье: на macOS для отладки нужны права (подпись отладчика, `DevTools
Security`). Четвёртое: watchpoints ограничены 4 аппаратными регистрами. Пятое: Python-API требует
Python 3 и правильной загрузки модуля (`command script import`). Шестое: при ASLR адреса меняются
между запусками — используйте `image lookup`, а не «жёсткие» адреса. Седьмое: на Apple Silicon
arm64 аргументы функций передаются в регистрах `x0`–`x7`, а не `rdi`/`rsi` — учитывайте
архитектуру при написании скриптов. Восьмое: символы Swift могут быть очень длинными и mangled —
используйте встроенный деманглер, а не читайте их вручную.

## Что дальше / решение

Практика: соберите crackme с `strcmp`, отладьте в LLDB, поставьте breakpoint на `strcmp`, соберите
оба аргумента. Напишите Python-скрипт, который автоматически печатает аргументы `strcmp`. На macOS
попробуйте `image lookup -n main` и `watchpoint set expression`. Далее — `reversing-windows-debuggers`
для Windows и `reversing-watchpoints-hwbp` для глубокого разбора аппаратных точек.

## Квиз

```quiz
- question: "Как поставить точку останова по имени функции в LLDB?"
  options:
    - "breakpoint set -n func"
    - "break func"
    - "b func"
    - "stop at func"
  answer: 0
- question: "Сколько аппаратных watchpoints обычно доступно?"
  options:
    - "4"
    - "1"
    - "8"
    - "Неограниченно"
  answer: 0
- question: "Что делает image lookup -a 0x1140?"
  options:
    - "Находит, какой образ и функция содержат адрес"
    - "Загружает образ"
    - "Удаляет образ"
    - "Печатает регистры"
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

- **CTF Reversing:** отладка Mach-O/ELF, перехват сравнений.
- **Mobile:** отладка iOS-приложений, Objective-C/Swift.
- **Malware analysis:** динамический анализ под macOS.
