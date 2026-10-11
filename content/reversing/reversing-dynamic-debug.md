---
id: reversing-dynamic-debug
title: "Динамический анализ: gdb, pwndbg, x64dbg"
category: reversing
parent: reversing-decompiler
difficulty: medium
order: 2
tags: [reversing, gdb, pwndbg, x64dbg, debugging, dynamic]
prerequisites: [reversing-decompiler]
useful_for:
  - "CTF Reversing"
  - "Pwn (разработка эксплойтов)"
  - "Анализ malware"
estimated_minutes: 55
summary: "Отладка бинарников: точки останова, шаг с исполнением, инспекция памяти, патчинг на лету."
---
Динамический анализ — это наблюдение за программой в момент исполнения. Он незаменим, когда код
обфусцирован, упакован, зависит от окружения или когда статический анализ упирается в стену.
Инструменты динамики делятся на три уровня: **системные вызовы** (`strace`/`ltrace`),
**инструментирование** (Frida/Pin/DynamoRIO) и **отладка** (gdb/x64dbg). Этот урок — про арсенал
динамического анализа, трассировку, хукинг и безопасное исполнение образцов.

## Три уровня динамического анализа

| Уровень | Инструменты | Что видно |
|---|---|---|
| Syscall/API | strace, ltrace, Procmon, API Monitor | обращения к ОС/библиотекам |
| Инструментирование | Frida, Pin, DynamoRIO, Intel PT | каждая инструкция/функция |
| Отладка | gdb, x64dbg, WinDbg | состояние регистров/памяти |

Правило: **начинайте с верхнего уровня** (syscalls) — он даёт общую картину поведения за минуты.
Спускайтесь ниже, только если нужно больше деталей.

## Syscall-трассировка: strace и ltrace

**strace** (Linux) показывает системные вызовы:
```bash
strace -f -tt -s 200 ./target              # -f следить за потомками, -tt таймстампы
strace -e trace=open,read,write ./target    # только нужные вызовы
strace -o trace.txt ./target                # в файл
strace -c ./target                          # сводка по вызовам
```

Пример вывода:
```text
openat(AT_FDCWD, "/etc/license", O_RDONLY) = 3
read(3, "KEY=SECRET123\n", 1024) = 15
write(1, "Access granted\n", 15) = 15
```
Сразу видно: программа читает файл лицензии и проверяет содержимое.

**ltrace** — трассировка библиотечных вызовов:
```bash
ltrace -f -s 200 ./target
ltrace -e 'strcmp+strcpy' ./target
```

Полезно для быстрого понимания: какие файлы открывает, куда коннектится, какие строки сравнивает.

## Frida: универсальный хукинг

Frida — самый гибкий инструмент динамики: внедряется в процесс и позволяет хукать функции на JS.

**Базовый запуск:**
```bash
frida -l hook.js -f ./target
frida -p <PID> -l hook.js
```

**Хук функции с логированием аргументов:**
```javascript
Interceptor.attach(Module.getExportByName(null, "strcmp"), {
    onEnter(args) {
        console.log("strcmp(", args[0].readUtf8String(), ",", args[1].readUtf8String(), ")");
    },
    onLeave(retval) {
        console.log("  ->", retval.toInt32());
    }
});
```

**Хук по адресу (обфусцированный код):**
```javascript
var base = Module.getBaseAddress("target");
Interceptor.attach(base.add(0x1234), {
    onEnter(args) { console.log("arg0 =", args[0].toInt32()); }
});
```

**Замена возврата (обход проверки):**
```javascript
Interceptor.replace(base.add(0x1500), new NativeCallback(function() {
    return 1;               // всегда «успех»
}, "int", []));
```

Frida работает на Linux/Windows/macOS/Android/iOS — отсюда её популярность в mobile-реверсе.

## Pin и DynamoRIO: инструментирование инструкций

**Pin** — DBI-фреймворк Intel: перехватывает каждую инструкцию/функцию.

```c
// Pintool: логировать все вызовы
VOID ImageLoad(IMG img, VOID *v) { /* ... */ }
VOID InsCallback(INS ins, VOID *v) {
    if (INS_IsCall(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log_call, IARG_INST_PTR, IARG_END);
    }
}
int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(InsCallback, 0);
    PIN_StartProgram();
}
```

**DynamoRIO** — похожий, с готовыми инструментами:
```bash
drrun -t drcov -- ./target           # покрытие блоков
drrun -t drltrace -- ./target        # трассировка библиотечных вызовов
```

Применение: снятие покрытия (какие блоки исполнены), построение реального CFG, обход обфускации.

## API-мониторинг (Windows)

- **Process Monitor (Procmon)** — файловая система, реестр, сеть, процессы. Незаменим для malware.
- **API Monitor** — перехват Win32 API с аргументами.
- **Frida** — кроссплатформенная альтернатива.
- **Wireshark** — сетевой трафик.

Типовой сценарий malware-анализа: запустить образец в изолированной VM с Procmon + Wireshark,
зафиксировать создаваемые файлы, ключи реестра, сетевые соединения — получить карту поведения.

## Песочницы и безопасное исполнение

Динамика опасна: код реально исполняется. Меры:

- **VM** (VirtualBox/VMware/KVM) — изоляция от хоста.
- **Изолированная сеть** — `INetSim`/`FakeNet-NG` для эмуляции сервисов (DNS, HTTP) и перехвата C2.
- **Снапшоты** — откат после каждого запуска.
- **Песочницы** (Cuckoo/CAPE, Any.run) — автоматический анализ с отчётом.
- **Ограничение прав** — запуск от непривилегированного пользователя, seccomp/AppArmor.

**FakeNet-NG** эмулирует интернет, отвечая на DNS/HTTP/HTTPS, — так malware «думает», что вышел в сеть,
и вы видите его запросы.

## Разобранный пример: обход проверки через Frida

Дано: бинарник просит пароль, проверка обфусцирована. Статически тяжело; идём динамикой.

**Шаг 1. strace.** `strace ./target` → видим `read(0, "test\n", ...)` и `write(1, "Wrong\n")`.
Программа читает ввод и печатает результат.

**Шаг 2. Найти функцию проверки.** `ltrace -e strcmp ./target` → видим сравнение:
```text
strcmp("test", "s3cr3t") = -1
```
Возможно, строка «s3cr3t» — эталон (или часть). Вводим `s3cr3t` → `Access granted`.

**Шаг 3. Если строки зашифрованы.** `ltrace` не показывает — тогда Frida-хук на `strcmp`:
```javascript
Interceptor.attach(Module.getExportByName(null, "strcmp"), {
    onEnter(a) { console.log("cmp:", a[0].readUtf8String(), a[1].readUtf8String()); }
});
```
Даже если строки расшифровываются в рантайме, в момент `strcmp` они уже в памяти — хук их поймает.

**Шаг 4. Обход.** Если нужно пройти дальше без пароля — `Interceptor.replace` на функцию проверки.

## Инструменты: сводная таблица

| Инструмент | Уровень | Платформа |
|---|---|---|
| strace | syscalls | Linux |
| ltrace | библиотечные вызовы | Linux |
| Frida | инструментирование | все |
| Pin | инструкции | x86 |
| DynamoRIO | инструкции | x86/ARM |
| Procmon | API/ФС/реестр | Windows |
| API Monitor | Win32 API | Windows |
| Wireshark | сеть | все |
| FakeNet-NG | эмуляция сети | Windows |
| CAPE/Cuckoo | песочница | все |

## Крайние случаи и подводные камни

- **Anti-debug/anti-VM.** Образец может детектить анализ и вести себя иначе — обходите (ScyllaHide,
  hardened VM, патч проверок).
- **Frida-детект.** Некоторые образцы ищут `frida-agent`/порты — переименуйте агент, используйте
  stealth-режим (`frida-server` под другим именем).
- **Сетевые зависимости.** Без эмуляции сети программа может ждать таймаута или падать — FakeNet.
- **Вредоносный код.** Только изолированная среда; никогда не запускайте образец на рабочей машине.
- **Оптимизации.** `strace`/`ltrace` замедляют программу и меняют тайминги — учитывайте это.
- **Многопоточность.** `-f` в strace, следите за всеми потоками; Frida видит все потоки.
- **Strip/обфускация.** Имён функций нет — хукайте по адресу/сигнатуре.
- **Детерминизм.** Поведение может зависеть от времени/окружения — несколько запусков.

## Что дальше / решение

1. Начать с syscall-трассировки (`strace`/Procmon) — общая картина.
2. Уточнить библиотечные вызовы (`ltrace`/API Monitor).
3. Для точечного анализа — Frida (хук функций/адресов).
4. Для покрытия/CFG — Pin/DynamoRIO.
5. Изолировать исполнение (VM + FakeNet + снапшоты).
6. Комбинировать с отладчиком для глубокого разбора.

Принцип: **динамика отвечает на вопрос «что реально происходит»**, статика — «как это устроено».
Идеальный анализ использует оба: статика задаёт гипотезы, динамика их проверяет.

## Справочная таблица: задача → инструмент

| Задача | Инструмент |
|---|---|
| Какие файлы открывает | strace, Procmon |
| Какие функции вызывает | ltrace, Frida |
| Перехватить API | Frida, API Monitor |
| Заменить возврат | Frida Interceptor.replace |
| Покрытие кода | DynamoRIO drcov, Pin |
| Сеть | Wireshark, FakeNet |
| Автоанализ | CAPE, Cuckoo |
| Глубокая отладка | gdb, x64dbg |

## Символьное исполнение как дополнение к динамике

Динамика проходит **один** путь на **одних** входных данных. Символьное исполнение (angr, Triton)
позволяет исследовать **многие** пути сразу:

```python
import angr
p = angr.Project("./target", auto_load_libs=False)
s = p.factory.entry_state()
simgr = p.factory.simulation_manager(s)
simgr.explore(find=lambda st: b"Access granted" in st.posix.dumps(1))
if simgr.found:
    print(simgr.found[0].posix.dumps(0))    # вход, дающий успех
```

Комбинация: **динамика** даёт карту реального исполнения (какие функции, какие ветви), **символика**
решает ограничения на вход. Вместе они закрывают большинство задач без ручного разбора.

## Разобранный пример: Frida на Android

Дано: Android-приложение проверяет пароль в нативном коде. Статически сложно; идём Frida.

**Шаг 1. Запуск.** `frida -U -f com.example.app -l hook.js --no-pause`.

**Шаг 2. Хук нативной функции.**
```javascript
var base = Module.getBaseAddress("libnative-lib.so");
Interceptor.attach(base.add(0x1234), {
    onEnter(args) { console.log("input:", args[0].readCString()); },
    onLeave(retval) { console.log("result:", retval.toInt32()); }
});
```

**Шаг 3. Хук Java-метода** (если проверка в Java):
```javascript
Java.perform(function() {
    var C = Java.use("com.example.app.Check");
    C.verify.implementation = function(s) {
        console.log("verify(", s, ")");
        var r = this.verify(s);
        console.log("  ->", r);
        return r;
    };
});
```

**Шаг 4. Обход.** Если нужно пройти проверку — вернуть `true` из хука. Так динамика решает задачу без
полного реверса алгоритма.

## Логирование и отчёт по динамическому анализу

Собирайте результаты системно:

- **Поведение**: файлы, реестр, сеть, процессы (Procmon/strace).
- **API-вызовы**: последовательность и аргументы (Frida/API Monitor).
- **Покрытие**: какие функции/блоки исполнены (drcov/Pin).
- **Ввод/вывод**: что читает и что печатает (hooks).
- **Окружение**: время, пользователь, сеть (для детерминизма).

Отчёт позволяет воспроизвести анализ и сравнить образцы между собой. Для malware — это основа
профиля поведения.

## Комбинированный рабочий процесс

1. **Статика** (Ghidra/IDA) — понять структуру, найти точки интереса.
2. **Syscall-трассировка** — общая картина поведения.
3. **Frida/API Monitor** — точные аргументы и возвраты.
4. **Отладчик** — глубокий разбор критичного участка.
5. **Символика** — решить ограничения на вход.
6. **Песочница** — безопасно зафиксировать полное поведение.

Переход между уровнями — по мере усложнения вопросов. Начинайте с дешёвых и переходите к дорогим.

## Квиз

```quiz
- question: "Какая команда gdb покажет строку, на которую указывает RDI?"
  options:
    - "`print $rdi`"
    - "`x/s $rdi`"
    - "`info registers rdi`"
    - "`bt`"
  answer: 1
  explanation: "`x/s` печатает строку по адресу."
- question: "Что делает `ni` в отличие от `si`?"
  options:
    - "Выполняет вызов целиком (step over)"
    - "Входит внутрь вызова (step into)"
    - "Перезапускает программу"
    - "Ставит breakpoint"
  answer: 0
  explanation: "`ni` (nexti) проходит `call` целиком."
- question: "Какой инструмент покажет, что программа сравнивает ввод с секретом, без отладчика?"
  options:
    - "`nm`"
    - "`ltrace`"
    - "`readelf`"
    - "`checksec`"
  answer: 1
  explanation: "`ltrace` трассирует вызовы libc, включая `strcmp`."
- question: "Команда gdb `watch *(int*)0x404060` — что делает?"
  options:
    - "Читает значение"
    - "Останавливается при изменении значения по адресу"
    - "Ставит breakpoint на функцию"
    - "Патчит байты"
  answer: 1
  explanation: "Это watchpoint на запись."
- question: "Что покажет `vmmap` в pwndbg?"
  options:
    - "Список строк"
    - "Карту памяти с адресами регионов и правами"
    - "Стек вызовов"
    - "Регистры"
  answer: 1
  explanation: "`vmmap` — карта памяти (полезно при PIE/ASLR)."
```

## Где пригодится

- **CTF Reversing:** быстрый выхват пароля через breakpoint на `strcmp`/`memcmp`.
- **Pwn:** разработка эксплойтов немыслима без gdb/pwndbg (утечки, heap, ROP).
- **Malware analysis:** наблюдение реального поведения, обход анти-статических трюков.
- **Отладка проприетарного ПО:** понять, почему падает чужой бинарник.
- **Собес:** вопросы про `si`/`ni`, breakpoints, watchpoints — стандарт для RE/pwn ролей.
