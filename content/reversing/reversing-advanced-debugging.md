---
id: reversing-advanced-debugging
title: "Продвинутая отладка: breakpoints, watchpoints, lldb"
category: reversing
parent: reversing-dynamic-debug
difficulty: hard
order: 2
tags: [reversing, gdb, lldb, watchpoint, breakpoint, hardware, remote, gdbserver]
prerequisites: [reversing-dynamic-debug]
useful_for:
  - "CTF Reversing"
  - "Анализ malware"
  - "Разработка эксплойтов"
estimated_minutes: 55
summary: "Глубокие приёмы отладки: условные/аппаратные точки останова, watchpoints, скрипты, remote."
---
Отладчик — это не «кнопка F9», а полноценный инструмент с десятками возможностей, о которых многие
не знают: условные точки, watchpoints на память, аппаратные точки, скриптование, reverse debugging,
удалённая и ядерная отладка. Умение отлаживать *методично* отличает профессионала от новичка,
который ставит breakpoint на всё подряд. Этот урок — про продвинутые техники отладки в gdb (Linux)
и x64dbg/WinDbg (Windows), обход anti-debug и автоматизацию.

## Модель отладки: как это работает

Отладчик управляет процессом через **ptrace** (Linux) или **Debug API** (`WaitForDebugEvent`,
`ContinueDebugEvent` — Windows). Ключевые события:

- **Точки останова (breakpoints).** Программные (байт `0xCC`/`int 3`), аппаратные (DR0–DR7 регистры
  x86, лимит 4), и точки на память (watchpoints).
- **Одиночный шаг.** Через флаг `TF` (trap flag) в EFLAGS/RFLAGS.
- **События.** Исключения, сигналы (`SIGTRAP`, `SIGSEGV`), создание потоков/процессов, загрузка DLL.

Понимание модели критично: anti-debug-техники детектят именно эти механизмы, а обход — маскирует их.

## gdb: продвинутые команды

```bash
gdb -q ./target
```

**Точки останова:**
```text
b *0x401000                       # по адресу
b main                            # по символу
b file.c:42                       # по строке
b func if x == 5                  # условная
condition 2 argc > 3              # условие на существующий bp
ignore 1 100                      # пропустить 100 срабатываний
delete / disable / enable 1       # управление
```

**Watchpoints (наблюдение за памятью):**
```text
watch *(int*)0x601040             # сработает при записи
rwatch *(int*)0x601040            # при чтении
awatch *(int*)0x601040            # чтение/запись
```

**Аппаратные точки** (не меняют код, их сложнее детектить):
```text
hbreak *0x401000                  # hardware breakpoint
```

**Просмотр и навигация:**
```text
info registers / i r
x/16gx $rsp                       # hex dump
x/s 0x402000                      # строка
x/10i $pc                         # 10 инструкций
disas /r $pc                      # с байтами
bt / bt full                      # backtrace
frame 2                           # перейти к кадру
info locals / info args
```

**Память и файлы:**
```text
set {int}0x601040 = 1             # записать
dump memory /tmp/dump.bin 0x400000 0x410000
restore file.bin binary 0x400000
```

## Reverse debugging и запись/воспроизведение

Reverse debugging позволяет **шагать назад** — бесценно для разбора сложных багов и проверок:

```text
(gdb) record full                 # начать запись (или record btrace на Intel PT)
(gdb) continue
(gdb) reverse-stepi               # шаг назад
(gdb) reverse-continue            # назад до предыдущего breakpoint
(gdb) record stop
```

Альтернативы: **rr** (Mozilla) — записывает всё исполнение и позволяет «отмотать»:
```bash
rr record ./target
rr replay
(rr) reverse-continue
```
`rr` незаменим, когда падение происходит редко и невоспроизводимо.

## Скриптование gdb на Python

gdb встраивает Python — можно автоматизировать анализ:

```python
# script.py
import gdb
class TraceCalls(gdb.Command):
    def __init__(self):
        super().__init__("tracecalls", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        while True:
            pc = int(gdb.parse_and_eval("$pc"))
            sym = gdb.execute("info symbol $pc", to_string=True).strip()
            print(hex(pc), sym)
            gdb.execute("si", to_string=True)
TraceCalls()
```

Запуск:
```text
(gdb) source script.py
(gdb) tracecalls
```

Полезно: `gdb.execute("...", to_string=True)`, `gdb.parse_and_eval`, breakpoint-классы
(`gdb.Breakpoint` с кастомным `stop()`), чтение памяти (`gdb.selected_inferior().read_memory`).

## x64dbg и WinDbg: Windows-арсенал

**x64dbg** — GUI-отладчик с мощными фичами:

- **Условные breakpoints**: `bp 401000, "strcmp(rax, \"flag\") == 0"`.
- **Логирование**: `log "rax={rax}"`.
- **Скрипты** (команды + условные переходы) для трассировки.
- **Патчи**: правый клик → Assemble/Patch.
- **Стек-вызовы**, **trace record** (запись потока выполнения), **Memory Map**.

**WinDbg** — для ядра и сложных случаев:

```text
kd> bp nt!NtCreateFile
kd> bp /p <EPROCESS> 0xfffff800`12345678     # conditional by process
kd> !process 0 0 target.exe
kd> dt nt!_EPROCESS <addr>                    # типизированный дамп
kd> !analyze -v                               # разбор краша
kd> .reload /f                                # подгрузить символы
```

WinDbg умеет **time-travel debugging** (TTD) — запись и откат, как `rr`, но для Windows.

## Обход anti-debug

Классические техники и их нейтрализация:

| Детект | Обход |
|---|---|
| `IsDebuggerPresent` | патч возврата / ScyllaHide |
| PEB `BeingDebugged` | обнулить через плагин/патч |
| `NtQueryInformationProcess` | хук результата |
| `rdtsc` timing | патч сравнения / замедление |
| `INT 3`/`0xCC` checks | аппаратные breakpoints вместо `0xCC` |
| `OutputDebugString` | корректный результат |
| `ptrace(PTRACE_TRACEME)` | патч вызова (Linux) |
| `getppid`/`/proc/self/status` | маскировка под отладчиком |

Практика: **ScyllaHide** (Windows) и **`set follow-fork-mode`/патч ptrace** (Linux) снимают
большинство. Для Linux-специфики — проверьте `/proc/self/status` (поле `TracerPid`) и `ptrace`.

## Удалённая отладка

**gdbserver** (Linux):
```bash
# на цели
gdbserver :1234 ./target
# на хосте
gdb ./target -ex "target remote 10.0.0.5:1234"
```

**WinDbg kernel-debug** (через serial/network):
```text
bcdedit /debug on
bcdedit /dbgsettings net hostip:10.0.0.1 port:50000 key:1.2.3.4
# хост: WinDbg → Attach to Kernel → Net
```

**IDA/Ghidra + gdb** — синхронизация GUI с отладчиком (ret-sync, ghidra-bridge).

## Разобранный пример: найти, откуда берётся значение

Дано: бинарник, проверяющий пароль; нужно понять, как формируется эталон. Ставим watchpoint.

```text
(gdb) b *0x401234            # после ввода пароля
(gdb) run
(gdb) x/s $rdi               # введённая строка
(gdb) ni                     # шагаем
(gdb) watch *(char*)0x602060 # следим за эталоном в .bss
(gdb) continue
Hardware watchpoint 2: *(char*)0x602060
Old value = 0 '\000'
New value = 70 'F'
0x0000000000401199 in build_expected ()
```

Отладчик остановился **в момент записи** эталона — мы видим функцию `build_expected`. Дизассемблируем
её, разбираем алгоритм, воспроизводим на Python. Watchpoint избавил от ручного трассирования.

## Крайние случаи и подводные камни

- **Программные breakpoints видны коду** (байт `0xCC`) — anti-debug их находит. Используйте
  аппаратные (`hbreak`) или ScyllaHide.
- **Лимит аппаратных точек** — 4 на x86/x64. Для большего — программные или трассировка.
- **ASLR мешает адресам.** Отключите (`set disable-randomization on` в gdb, `bcdedit` в Windows)
  или работайте по RVA.
- **Многопоточность.** gdb: `set scheduler-locking on/off`, `thread apply all bt`. Остановка всех
  потоков может сломать программу.
- **Fork/exec.** gdb: `set follow-fork-mode child|parent`, `set detach-on-fork off`.
- **Не тот модуль.** В Windows адрес может принадлежать DLL — проверяйте `lm`/`info sharedlibrary`.
- **Оптимизация (`-O2`).** Переменные «исчезают», код переупорядочен — отлаживайте `-O0`-сборку или
  смотрите регистры.
- **Reverse debugging замедляет** исполнение в разы — включайте точечно.

## Что дальше / решение

1. Определить цель отладки: понять алгоритм, найти краш, обойти проверку.
2. Выбрать точки: breakpoint на API/строку, watchpoint на данные.
3. Если не воспроизводится — `rr`/TTD для записи и отката.
4. Автоматизировать рутину скриптами (gdb Python, x64dbg scripts).
5. При anti-debug — ScyllaHide/патчи, аппаратные точки.
6. Для ядра — WinDbg + символы.

Принцип: **отладка — это гипотеза → точка останова → наблюдение → вывод**. Ставьте точки осмысленно,
а не «на всякий случай».

## Справочная таблица: инструмент → задача

| Задача | gdb | x64dbg | WinDbg |
|---|---|---|---|
| Условный bp | `b f if x==1` | `bp a,"cond"` | `bp /p` |
| Watchpoint | `watch *addr` | Hardware BP | `ba w4 addr` |
| Аппаратный bp | `hbreak` | HW BP | `ba e1 addr` |
| Reverse | `record`/`rr` | trace record | TTD |
| Скрипт | Python | scripts | `.script` |
| Ядро | kgdb | — | WinDbg |
| Удалённо | gdbserver | remote | kd |

## Трассировка: Intel PT, btrace и запись потока

Когда нужно понять **весь** поток выполнения (например, разобрать алгоритм или найти, где портится
значение), точечные breakpoints неэффективны. На помощь приходит трассировка:

**Intel Processor Trace (Intel PT)** — аппаратная запись потока управления с минимальным замедлением.
gdb использует её через `record btrace`:
```text
(gdb) record btrace pt
(gdb) continue
(gdb) record instruction-history /m      # история инструкций с исходниками
(gdb) record function-history            # история вызовов
```
Инструменты: `perf record -e intel_pt// ./target` + `perf script`, а также **`ptxed`** (из libipt) —
декодирует трассу в поток инструкций.

**Trace record в x64dbg** — записывает каждую инструкцию (регистры, изменения памяти) в лог; потом
можно прокручивать. Полезно для разбора обфусцированного кода и VM.

**rr** (Mozilla) — полная запись с детерминированным воспроизведением и откатом (см. выше).
Требует CPU с поддержкой `perf`/PT и совместимого ядра.

## Пример: скрипт x64dbg для трассировки вызовов

Скриптовый движок x64dbg позволяет логировать вызовы без остановки:

```text
// logcalls.txt
bp kernel32.CreateFileW
  log "CreateFileW({utf16@rcx})"
  run
bp kernel32.WriteFile
  log "WriteFile(h={rcx}, n={r8})"
  run
```

Загрузка: `Scripting → Load script`. Итог — лог всех файловых операций, что быстро вскрывает
поведение malware (какие файлы создаёт, что пишет).

Для условной логики:
```text
bp 401000
  log "arg0={rcx} arg1={rdx}"
  cmp rcx, 0
  je skip
  log "nonzero!"
skip:
  run
```

## Продвинутые приёмы: слепые зоны

- **Отладка без точек останова** (stealth): используйте трассировку (PT/rr), аппаратные точки,
  `int3`-инъекции через ScyllaHide.
- **Патчинг на лету**: меняйте инструкции в памяти (`set {char}addr = 0x90`) и восстанавливайте
  после проверки — это обходит integrity-чеки.
- **Маскировка PEB** (Windows) и `/proc/self/status` (Linux) — чтобы код не видел отладчик.
- **Обход таймингов**: на время отладки можно замедлить/ускорить `rdtsc` через патч или плагин.
- **Символическое исполнение в паре с отладкой**: angr/Triton помогают там, где ручная трассировка
  упирается в большой поток.

## Чек-лист методичной отладки

1. **Понять цель**: что именно ищем (значение, ветвление, краш).
2. **Сузить область**: найти функцию/строку/API через статику (IDA/Ghidra).
3. **Точка**: поставить breakpoint на входе нужной функции.
4. **Наблюдение**: посмотреть аргументы (`rdi/rsi/rdx` — SysV, `rcx/rdx/r8/r9` — Win64).
5. **Гипотеза о формате данных** → watchpoint на поле структуры.
6. **Шаг за шагом** через критичный участок.
7. **Воспроизвести** логику на Python и проверить.

Этот цикл повторяется, пока алгоритм не станет полностью ясен.

## Квиз

```quiz
- question: "Чем hardware breakpoint лучше software?"
  options:
    - "Не модифицирует код (пишет `0xCC`), работает в read-only и не детектируется как int3"
    - "Работает быстрее"
    - "Поддерживает больше точек"
    - "Работает только на Windows"
  answer: 0
- question: "Как остановиться при записи в адрес?"
  options:
    - "`break *0x404060`"
    - "`watch *0x404060`"
    - "`rwatch *0x404060`"
    - "`catch *0x404060`"
  answer: 1
- question: "Сколько аппаратных точек останова доступно на x86?"
  options:
    - "1"
    - "4"
    - "8"
    - "Неограниченно"
  answer: 1
- question: "Как в gdb перейти в отлаживаемый процесс-потомок после fork?"
  options:
    - "`set detach-on-fork on`"
    - "`set follow-fork-mode child`"
    - "`attach child`"
    - "`catch fork`"
  answer: 1
- question: "Какая команда lldb ставит breakpoint по адресу?"
  options:
    - "`break *0x1000`"
    - "`br set -a 0x1000`"
    - "`b 0x1000`"
    - "`watch 0x1000`"
  answer: 1
```

## Где пригодится

- **CTF Reversing:** watchpoints для поиска «кто портит данные», условные точки для сложных проверок.
- **Pwn:** анализ heap/стека, трассировка аллокаций, поиск смещений.
- **Malware analysis:** удалённая отладка в изолированной VM, трассировка API.
- **Работа (RE-команда):** диагностика крашей, поиск причин некорректного поведения без исходников.
- **Собес:** условные breakpoints, watchpoints, remote-отладка — практические вопросы RE-интервью.
