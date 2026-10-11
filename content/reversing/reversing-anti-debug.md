---
id: reversing-anti-debug
title: "Анти-отладка и её обход"
category: reversing
parent: reversing-patching
difficulty: hard
order: 2
tags: [reversing, anti-debug, ptrace, scyllahide, evasion]
prerequisites: [reversing-patching]
useful_for:
  - "CTF Reversing (hard)"
  - "Malware analysis"
  - "Анализ защищённого ПО"
estimated_minutes: 50
summary: "Техники детекта отладчика (ptrace, timing, self-debug) и способы их нейтрализации."
---
**Анти-отладка** — это техники, которыми программа обнаруживает, что её анализируют под отладчиком (или трассируют), и меняет поведение: завершается, портит результат, уходит в бесконечный цикл. Для реверс-инженера это обязательный навык: нужно распознать проверку и нейтрализовать её, чтобы продолжить анализ. Урок разбирает уровни техник (API, точки останова, тайминги, ловушки, самомодификация, Linux-специфика), способы обхода (ScyllaHide, Frida, патчи) и полный разобранный пример.

## Зачем анти-отладка

Мотивы: защита от реверса (коммерческие приложения), античит, малварь (уйти от анализа). Цель — не «сломать» отладчик навсегда, а **не дать аналитику увидеть реальную логику**. Понимание техник важно и для обхода, и для детекции (анти-отладочные приёмы — индикатор семейства).

## Уровни и классы техник

- **API-проверки** — Windows: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, чтение PEB; Linux: `ptrace(PTRACE_TRACEME)`, `/proc/self/status`.
- **Детекция точек останова** — проверка байта `0xCC` (int3), `DR0-DR7` (hardware breakpoints), `TF`-флага.
- **Тайминги** — `rdtsc`/`QueryPerformanceCounter`: под отладчиком код выполняется медленнее.
- **Ловушки** — `int3`, `int 0x2d`, `ICEBP` (`0xF1`), `SIGTRAP`.
- **Самомодификация/CRC** — проверка целостности кода, ломающая патчи.
- **Linux-специфика** — `ptrace`, `fork`+`wait`, `/proc/self/status` (`TracerPid`), `personality`.

## API-проверки (Windows)

```c
if (IsDebuggerPresent()) exit(0);                  // читает PEB.BeingDebugged
BOOL dbg; CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
if (dbg) exit(0);
// прямой доступ к PEB
PPEB peb = (PPEB)__readgsqword(0x60);
if (peb->BeingDebugged) exit(0);
```

Обход: подменить результат этих API (ScyllaHide/Frida) или занулить `PEB.BeingDebugged`.

```javascript
// Frida: скрыть отладчик
var p = Module.getExportByName("kernel32.dll", "IsDebuggerPresent");
Interceptor.replace(p, new NativeCallback(() => 0, "int", []));
```

## Детекция точек останова

Программный breakpoint = байт `0xCC` в коде. Программа может читать свой код и искать `0xCC` (или сравнивать CRC с ожидаемым). Аппаратные — через `GetThreadContext` и регистры `Dr0-Dr3`.

```c
// проверка байта на int3
if (*(unsigned char*)func == 0xCC) exit(0);
// проверка hardware breakpoints
CONTEXT ctx = {0}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
GetThreadContext(GetCurrentThread(), &ctx);
if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) exit(0);
```

Обход: скрывать breakpoints (ScyllaHide умеет), использовать hardware breakpoints аккуратно, или патчить саму проверку.

## Тайминги

```c
unsigned long long t1 = __rdtsc();
// ... немного кода ...
unsigned long long t2 = __rdtsc();
if (t2 - t1 > THRESHOLD) exit(0);   // слишком медленно -> отладчик
```

Обход: хук `rdtsc`/`QueryPerformanceCounter`, возвращающий «нормальные» значения; либо патч сравнения.

## Ловушки и самомодификация

- **`int3`/`int 0x2d`/`ICEBP`** — если отладчик перехватывает исключение, поток управления меняется (программа видит разницу).
- **`SIGTRAP`-обработчики** — установка своего обработчика и проверка, доходит ли сигнал.
- **Самомодификация** — код расшифровывается/переписывается в рантайме; статический патч затирается.
- **CRC/хеш кода** — сверка контрольной суммы секции `.text` с константой.

```c
// пример CRC-проверки
if (crc32(text_section, size) != EXPECTED) exit(0);
```

Обход: не патчить статически (ломает CRC), а хукать проверку или подменять вычисление CRC.

## Linux-специфика

```c
// классика: ptrace на самого себя -> если уже трассируют, вернёт -1
if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) exit(1);
// чтение /proc/self/status: TracerPid != 0 => отладчик
FILE *f = fopen("/proc/self/status", "r");   // ищем "TracerPid:"
// fork + wait: отладчик ломает семантику
```

Обход: патч `ptrace`-вызова (или хук через `LD_PRELOAD`), подмена `/proc/self/status`.

```bash
# gdb: перехватить ptrace и вернуть 0
catch syscall ptrace
commands
  set $rax = 0
  continue
end
```

## Обход: инструменты и подходы

| Инструмент | Назначение | Платформа |
|---|---|---|
| ScyllaHide | скрыть отладчик от API | Windows (x64dbg/IDA) |
| TitanHide | kernel-level сокрытие | Windows |
| Frida | хук API/функций | все |
| `LD_PRELOAD` | подмена функций | Linux |
| патч проверок | прямая правка | все |

```javascript
// Frida: общий обход анти-отладки
var names = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"];
names.forEach(function (n) {
  var p = Module.findExportByName(null, n);
  if (p) Interceptor.replace(p, new NativeCallback(() => 0, "int", []));
});
```

## Разобранный пример: обход анти-отладки

**Шаг 1. Найти проверку.** В Ghidra видим `call IsDebuggerPresent; test eax,eax; jne fail`.

**Шаг 2. Динамически — скрыть отладчик.** ScyllaHide в x64dbg (профиль по умолчанию скроет PEB/API/DR). Или Frida-хук (выше).

**Шаг 3. Статически — патч.**

```asm
; было
call IsDebuggerPresent
test eax, eax
jne  fail
; стало: NOP проверку
nop (x5)
```

**Шаг 4. Проверка.** Программа больше не завершается, доходим до интересующей логики. Read-back: убедиться, что исполнение пошло по «успешной» ветке.

## Частые ошибки и подводные камни

- **Патч одного API.** Проверок много (PEB, DR, timing, int3); нужен комплексный обход (ScyllaHide/Frida).
- **Патч ломает CRC.** Если есть самомодификация/контроль целостности, статический патч обнаружится — хукайте проверку.
- **Hardware breakpoints видны.** Программа читает `Dr0-Dr3`; используйте софт-обход или скрытие.
- **Забыть про тайминги.** Даже при скрытых API остаются `rdtsc`-проверки.
- **Не проверить результат.** «Патч применился» ≠ «логика открылась»; проверяйте исполнение.
- **Linux-специфика.** `ptrace`/`/proc` легко упустить, если фокус на Windows.

## Что дальше / решение

Маршрут: **найти проверки (статика + трассировка) → выбрать обход (ScyllaHide/Frida для комплекса, патч для простого) → учесть самомодификацию/CRC → проверить, что логика открылась**. Дальше — `reversing-anti-vm` (детекция среды), `reversing-packing-upx` (упаковка) и `reversing-advanced-debugging`.

## macOS/iOS-специфика

На Apple-платформах анти-отладка опирается на `ptrace` и системные вызовы.

```c
// классика macOS: запретить отладку
ptrace(PT_DENY_ATTACH, 0, 0, 0);
// sysctl: проверка флага P_TRACED в kinfo_proc
int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
struct kinfo_proc info; size_t size = sizeof(info);
sysctl(mib, 4, &info, &size, NULL, 0);
if (info.kp_proc.p_flag & P_TRACED) exit(0);
```

Обход — хук `ptrace`/`sysctl` через Frida:

```javascript
Interceptor.replace(Module.getExportByName(null, "ptrace"),
  new NativeCallback(() => 0, "int", ["int","int","pointer","int"]));
```

Для iOS к этому добавляется проверка `getppid` (отладчик меняет родителя) и `sysctl`.

## VEH и обработка исключений (Windows)

Некоторые защиты используют **Vectored Exception Handling** и сами перехватывают `int3`/`SIGTRAP`, чтобы отладчик «не понял», что происходит. Программа ставит свой обработчик и проверяет, доходит ли исключение до него.

```c
AddVectoredExceptionHandler(1, handler);   // перехват исключений
// затем намеренный int3 и проверка поведения
```

Обход: понимать, что VEH-обработчик — часть логики; снять его или захукать `AddVectoredExceptionHandler`.

## Обход самомодифицирующегося кода и CRC

Если программа проверяет CRC секции `.text` или расшифровывает код в рантайме, статический патч не работает.

- **Дампить после расшифровки.** Остановиться в отладчике после распаковки и снять дамп памяти (Scylla/x64dbg dump).
- **Хукать CRC-функцию** так, чтобы она всегда возвращала ожидаемое значение.
- **Точка останова после самомодификации** — работать с расшифрованным кодом.

```bash
# x64dbg: найти точку после unpack, дампить модуль
# Scylla: dump + fix IAT
```

## Практика: gdb-скрипт для обхода Linux-проверок

```bash
gdb -q ./target
(gdb) catch syscall ptrace
(gdb) commands
> silent
> set $rax = 0
> continue
> end
(gdb) break fopen
(gdb) commands
> silent
> if (char*) $rdi == "/proc/self/status"
>   return 0
> end
> continue
> end
(gdb) run
```

Так нейтрализуются `ptrace`- и `/proc`-проверки без патча бинарника.

## Комбинированные защиты и стратегия обхода

Реальные приложения комбинируют 5-10 проверок (PEB + DR + timing + CRC + ловушки). Стратегия: сначала **картировать** все проверки (трассировка API + чтение кода), затем обходить **комплексно** — ScyllaHide/TitanHide для API/DR/PEB, хук таймингов, дамп после распаковки, обход CRC. Единичный патч в такой схеме бесполезен.

## Детекция через родительский процесс и окружение

Отладчик меняет окружение процесса, и это можно заметить.

- **`getppid()`** — у отлаженного процесса родитель — отладчик (gdb/x64dbg), а не shell.
- **Переменные окружения** — `LD_PRELOAD`, отладочные переменные.
- **Список процессов** — поиск `gdb`, `x64dbg`, `ida` в системе (грубо, но встречается).
- **Время старта** — аномалии.

```c
// Linux: родитель подозрителен?
if (getppid() == 1) { /* возможно, отлажен */ }
```

Обход: хук `getppid`, фильтрация списка процессов, чистка окружения.

## Инструменты и их флаги (расширенно)

| Инструмент | Флаги/настройка | Назначение |
|---|---|---|
| ScyllaHide | профили, `Options → Profiles` | скрытие API/PEB/DR |
| x64dbg | `Options → Preferences` | отладка + плагины |
| Frida | `-l script.js`, `--no-pause` | хук API |
| gdb | `catch syscall ptrace` | перехват syscall |
| `LD_PRELOAD` | — | подмена функций |
| angr | `SimProcedure` | обход условий |

## Разобранный пример: комбинированная защита (Windows)

Дано: программа проверяет `IsDebuggerPresent`, читает `Dr0`, меряет `rdtsc` и сверяет CRC `.text`.

**Шаг 1. Картировать проверки.** Трассировка импортов (`IsDebuggerPresent`, `GetThreadContext`, `rdtsc`) в IDA/Ghidra + точки останова.

**Шаг 2. Комплексный обход.**

- ScyllaHide — скрывает `IsDebuggerPresent`/PEB/DR.
- Хук `rdtsc` (плагин или патч) — нормализует тайминги.
- CRC — не патчим `.text` статически; хукаем функцию CRC, возвращая ожидаемое значение.

**Шаг 3. Проверка.** Read-back: программа доходит до основной логики; в логе видно, что ни одна проверка не сработала.

## Проверка результата обхода

После обхода обязательно подтвердите, что защита действительно снята: пройдите до функции, скрытой за проверкой, и убедитесь, что она исполняется (точка останова/лог). Патч или хук «применился» — не доказательство; доказательство — реальный переход в защищённую логику.

## Квиз

```quiz
- question: "Какой вызов чаще всего используется для анти-отладки на Linux?"
  options:
    - "`fork`"
    - "`ptrace(PTRACE_TRACEME)`"
    - "`malloc`"
    - "`signal`"
  answer: 1
  explanation: "`PTRACE_TRACEME` не даёт внешнему отладчику присоединиться."
- question: "Какой файл читает программа для проверки `TracerPid`?"
  options:
    - "`/etc/passwd`"
    - "`/proc/self/status`"
    - "`/proc/self/maps`"
    - "`/var/log/syslog`"
  answer: 1
  explanation: "Поле `TracerPid` в `/proc/self/status`."
- question: "Что такое timing-проверка?"
  options:
    - "Замер времени выполнения участка кода для детекта паузы отладчика"
    - "Проверка системного времени"
    - "Сравнение хэшей"
    - "Проверка сети"
  answer: 0
  explanation: "Под отладчиком участок выполняется дольше — это детектится."
- question: "Как в gdb обойти детект софт-брейкпоинтов (скана 0xCC)?"
  options:
    - "Использовать `hbreak` (hardware breakpoints)"
    - "Использовать `continue`"
    - "Отключить ASLR"
    - "Запустить `strace`"
  answer: 0
  explanation: "Hardware breakpoints не пишут `0xCC` в память."
- question: "Какой плагин x64dbg автоматически маскирует анти-отладочные проверки?"
  options:
    - "xAnalyzer"
    - "ScyllaHide"
    - "IDAPython"
    - "Ghidra"
  answer: 1
  explanation: "ScyllaHide (и TitanHide) маскируют большинство Windows-проверок."
```

## Где пригодится

- **CTF Reversing (hard):** задачи с «Debugger detected» — нужно понять и обойти каждую технику.
- **Malware analysis:** образцы активно прячутся от отладчика; обход — обязательный навык.
- **Аудит защищённого ПО:** понять, как реализована защита, и оценить её стойкость.
- **Game hacking / anti-cheat research:** анализ механизмов детекта.
- **Собес:** вопросы про `ptrace`, `/proc/self/status`, ScyllaHide — признак серьёзного RE-опыта.
