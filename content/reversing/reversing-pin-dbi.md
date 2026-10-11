---
id: reversing-pin-dbi
title: "Intel PIN и DynamoRIO: классический DBI"
category: reversing
parent: reversing-taint-analysis
difficulty: hard
order: 1
tags: [reversing, pin, dynamorio, dbi, instrumentation, taint, tracing]
prerequisites: [reversing-taint-analysis, reversing-advanced-debugging]
useful_for:
  - "CTF Reversing"
  - "Malware analysis"
  - "Program analysis / research"
estimated_minutes: 60
summary: "Динамическая бинарная инструментация: Intel PIN и DynamoRIO, pintools, трассировка и taint-анализ."
---
**Intel PIN** и **DynamoRIO** — классические фреймворки **динамической бинарной инструментации (DBI)**: они перехватывают исполнение на уровне инструкций и базовых блоков, транслируя код «на лету», и позволяют писать плагины для трассировки, покрытия, taint-анализа и профилирования. Это основа многих исследовательских инструментов и анализа malware. DBI работает без пересборки и без исходников, что делает его незаменимым для реверса. В этом уроке — архитектура PIN/DynamoRIO, написание pintool, компиляция и практические сценарии.

## Что такое DBI и зачем он нужен

Динамическая бинарная инструментация вставляет код анализа **во время исполнения**: движок (PIN/DynamoRIO) разбирает инструкции, строит их копии в кодовом кэше и вызывает колбэки инструмента до/после каждой инструкции или блока. Аналитик пишет плагин, который получает доступ к регистрам, памяти, адресам и может модифицировать состояние. Применения: трассировка API и сисколлов, покрытие (для fuzzing), taint-анализ (отслеживание потока данных), детект уязвимостей, деобфускация. В отличие от отладчика, DBI не останавливает программу и работает быстрее.

## Intel PIN: архитектура и модель

PIN перехватывает управление при загрузке, JIT-компилирует базовые блоки и даёт API на C++ (и Python через `pin` bindings). Основные понятия:

- **IMG/SEC/RTN/INS** — образ, секция, рутина (функция), инструкция.
- **`INS_AddInstrumentFunction`** — колбэк на каждую инструкцию.
- **`TRACE_AddInstrumentFunction`** — на каждый трассировочный блок (выполняемый блок кода).
- **`IMG_AddInstrumentFunction`** — на загрузку образа.
- **`INS_InsertCall`** — вставить вызов анализа перед/после инструкции.

Скелет pintool:

```cpp
#include "pin.H"
#include <iostream>

VOID BeforeIns(ADDRINT ip) {
    std::cout << "exec " << std::hex << ip << std::endl;
}

VOID Instruction(INS ins, VOID *v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BeforeIns,
                   IARG_INST_PTR, IARG_END);
}

int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();
    return 0;
}
```

## Компиляция и запуск pintool

Pintool компилируется как shared library с заголовками PIN и Makefile из дистрибутива:

```bash
# в каталоге pintools
make obj-intel64/mytool.so
pin -t obj-intel64/mytool.so -- ./target arg1
pin -t obj-intel64/mytool.so -o trace.out -- ./target
```

Флаги PIN: `-t` (инструмент), `-o` (вывод), `-follow_execv`, `-pid` (attach к процессу), `-logfile`. Для Windows — `pin.exe`. Типовые готовые tools: `inscount0` (счётчик инструкций), `itrace` (трасса), `malloctrace`, `pinatrace` (доступы к памяти).

## DynamoRIO: отличия и API

DynamoRIO — open-source DBI-фреймворк (изначально HP, теперь community). Он также JIT-компилирует код и предоставляет клиентский API на C/C++. Ключевые события: `dr_init`, `dr_register_bb_event` (базовый блок), `dr_register_exit_event`, `dr_insert_clean_call` (вызов клиента), `dr_register_trace_event`. Пример клиента:

```c
#include "dr_api.h"

static void event_exit(void) { dr_printf("done\n"); }

static dr_emit_flags_t bb_event(void *drcontext, void *tag, instrlist_t *bb,
                                bool for_trace, bool translating) {
    for (instr_t *i = instrlist_first(bb); i; i = instr_get_next(i)) {
        dr_insert_clean_call(drcontext, bb, i, (void *)dr_printf,
                             0, OPND_CREATE_STRING("ins\n"));
    }
    return DR_EMIT_DEFAULT;
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_register_bb_event(bb_event);
    dr_register_exit_event(event_exit);
}
```

Компиляция — через `DynamoRIOConfig.cmake`, запуск: `drrun -c libclient.so -- ./target`. Преимущества DynamoRIO: кроссплатформенность (Linux/Windows/ARM), открытый код, встроенный `drmemtrace` для трасс.

## Taint-анализ и трассировка

Taint-анализ отслеживает, как «заражённые» (пользовательские) данные влияют на вычисления и ветвления — ключ к поиску уязвимостей. В PIN/DynamoRIO его строят вручную: помечают источник (`taint source`), затем на каждой инструкции обновляют метки регистров/памяти по правилам (например, результат `add` заражён, если заражён любой операнд), а при использовании заражённого значения как адреса/условия — сигналят. Готовые инструменты: **libdft** (PIN), **Triton** (через DBI), `drtaint`. Трассировка проще: логируют каждый вызов API с аргументами или каждое обращение к памяти (`pinatrace`).

## Практика: покрытие и трасса API

Для fuzzing-покрытия собирают уникальные адреса выполненных базовых блоков:

```cpp
VOID BBL(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        INS_InsertCall(BBL_InsHead(bbl), IPOINT_BEFORE,
                       (AFUNPTR)RecordBB, IARG_ADDRINT,
                       BBL_Address(bbl), IARG_END);
    }
}
```

Список адресов → битмап покрытия для AFL/LibFuzzer. Для трассы API хукают вызовы (`RTN_AddInstrumentFunction`) и логируют имя функции и аргументы. Для обращений к памяти — `INS_MemoryOperand*`.

## Сравнение с Frida/QBDI

| Свойство | Intel PIN | DynamoRIO | Frida | QBDI |
|---|---|---|---|---|
| Уровень | инструкции/BBL | инструкции/BBL | функции/инструкции | инструкции |
| Язык плагинов | C++ | C/C++ | JS/Python | C++ |
| Платформы | x86/x64 | x86/x64/ARM | много | x86/ARM/ARM64 |
| Taint «из коробки» | нет (libdft) | drtaint | нет | нет |
| Внедрение в процесс | отдельный запуск | отдельный запуск | attach/spawn | в процесс |
| Оверхед | высокий | средний | средний | низкий |

PIN/DynamoRIO сильны для тяжёлого анализа и покрытия, Frida — для быстрых хуков, QBDI — для инструментации в процессе с низким оверхедом.

## Полный разбор: трасса обращений к памяти

**Шаг 1 — написать pintool** на основе `pinatrace`: на каждую инструкцию с памятью вставляем `RecordMemRead/Write` с адресом и размером. **Шаг 2 — собрать:** `make obj-intel64/pinatrace.so`. **Шаг 3 — запустить:** `pin -t obj-intel64/pinatrace.so -- ./crackme input.txt > mem.log`. **Шаг 4 — анализ:** по логу находим, какие адреса читает проверка, и восстанавливаем таблицу сравнения. **Шаг 5 — вывод:** извлекаем ключ, зная, какие байты читаются.

## Шпаргалка

| Задача | PIN | DynamoRIO |
|---|---|---|
| Инструмент инструкций | `INS_AddInstrumentFunction` | `dr_register_bb_event` |
| Инструмент блоков | `TRACE_AddInstrumentFunction` | `dr_register_trace_event` |
| Вставить вызов | `INS_InsertCall` | `dr_insert_clean_call` |
| Запуск | `pin -t tool.so -- bin` | `drrun -c client.so -- bin` |
| Покрытие | `BBL_Address` | `instrlist` |
| Готовые tools | `itrace`, `pinatrace` | `drmemtrace` |

## Что дальше / решение

Маршрут: напишите простой pintool (трасса инструкций), скомпилируйте `make`, запустите `pin -t`, затем усложните до трассы памяти/API или покрытия. Для кроссплатформенных задач и ARM — DynamoRIO. Дальше изучайте taint-анализ (libdft, drtaint) и интеграцию с fuzzer'ами, а также сравните с QBDI/Frida для задач, где оверхед критичен.

## Пример taint-анализа на базе PIN

Taint-анализ в PIN строят через библиотеку libdft или вручную. Идея: пометить источник (например, буфер ввода) и на каждой инструкции обновлять метки. Схема libdft:

```cpp
#include "libdft_api.h"
#include "ins_helper.h"

VOID Instruction(INS ins, VOID *v) {
    if (INS_IsMemoryRead(ins) || INS_IsMemoryWrite(ins))
        ins_taint_op(ins);                  // пометить операнды
    if (INS_IsBranch(ins) || INS_IsRet(ins))
        ins_taint_branch(ins);              // проверить ветвление
}
```

Правила распространения: `mov dst,src` копирует метку, `add dst,src` объединяет метки операндов, `xor a,a` обнуляет метку. Когда заражённое значение используется как адрес или условие перехода — это потенциальная уязвимость (control-flow hijack). libdft перехватывает такие события и логирует. Для поиска конкретной уязвимости (например, переполнения) taint-анализ указывает, какие входные байты влияют на критичный адрес.

## Производительность и оптимизация

DBI замедляет программу в 5–100 раз. Чтобы уложиться в разумное время: инструментируют только нужные инструкции (`if (INS_IsCall(ins))`), используют `IPOINT_BEFORE` вместо тяжёлых колбэков, кэшируют результаты, избегают `IARG_PTR` на строки, применяют `INS_InsertIfCall`/`INS_InsertThenCall` для условных вызовов. В DynamoRIO предпочитают `dr_insert_clean_call` с `dr_cleancall` и буферизуют вывод, чтобы не тормозить I/O. Для покрытия используют битмап вместо списка адресов. Профилируйте pintool (`perf`) и отключайте неиспользуемые проверки.

## DynamoRIO drmemtrace и готовые клиенты

DynamoRIO поставляется с `drmemtrace` — готовым инструментом для записи трасс инструкций и обращений к памяти, который затем анализируют офлайн (`drraw2trace`, `drrun -t drmemtrace`). Это позволяет собирать огромные трассы и обрабатывать их без повторного исполнения. Готовые клиенты DynamoRIO: `bbcount` (покрытие блоков), `instrace` (трасса), `memtrace`, `cbrtrace` (условные переходы). Их используют для fuzzing (AFL++ QEMU/DR-режим), профилирования и реверса. Для кастомных задач пишут свой клиент на C.

## Отладка pintool

Pintool — обычная библиотека, и её можно отлаживать. Ошибки в колбэках приводят к падению процесса-цели; чтобы найти причину, включают диагностику:

```bash
pin -t obj-intel64/mytool.so -xyzzy -mesgon log_ins -- ./target
```

Флаги `-xyzzy` и внутренние логи (`-mesgon`) выводят отладочную информацию PIN. Дополнительно проверяют `INS_Valid`, корректность `IARG_*` (несовпадение типов — частая причина крашей), инициализацию глобальных структур. Для сложных колбэков используют `PIN_LockClient`/`PIN_UnlockClient`. Отладку ведут, запуская PIN под gdb: `gdb --args pin -t tool.so -- ./target`.

## PIN, DynamoRIO и аппаратная трассировка: что выбрать

DBI (PIN/DynamoRIO) даёт полный контроль: чтение/запись регистров, модификация состояния, произвольные колбэки. Аппаратная трассировка (Intel PT, ARM ETM) даёт поток управления с минимальным оверхедом, но без чтения данных и без вмешательства. Выбор зависит от задачи: для taint-анализа и модификации — DBI; для покрытия fuzzing и посмертного анализа — аппаратная трассировка. Часто их комбинируют: PT собирает трассу, DBI уточняет детали на интересных участках. Frida/QBDI занимают нишу инструментации «в процессе» (attach к уже запущенному), тогда как PIN/DynamoRIO обычно запускают программу заново. Для malware, устойчивого к отладке, DBI предпочтительнее, так как не использует стандартные механизмы отладки и труднее детектируется.

## Практика: покрытие для фаззинга

Для fuzzing собирают покрытие в формате, совместимом с AFL/LibFuzzer — битмап. В pintool:

```cpp
static UINT8 *bitmap;
VOID RecordBB(ADDRINT addr) {
    UINT32 idx = (addr >> 4) ^ (addr << 8);
    bitmap[idx % MAP_SIZE]++;
}
```

Битмап разделяется с фаззером через shared memory (`shmget`/`mmap`), а адрес базового блока хешируется в индекс. Так фаззер видит новое покрытие и мутирует вход. Для DynamoRIO аналогичное делают через `dr_register_bb_event` и запись в общий буфер. Готовые решения: `afl-qemu-trace`, AFL++ с `-Q` (QEMU) или DR-режимом. Покрытие — основа современных фаззеров, и DBI здесь ключевой инструмент.

## Квиз

```quiz
- question: "Что такое DBI?"
  options:
    - "Динамическая бинарная инструментация (перехват кода в рантайме)"
    - "Формат файла"
    - "Тип шифрования"
    - "Пакер"
  answer: 0
  explanation: "DBI транслирует код на лету и позволяет инструментировать."
- question: "Как называется плагин Intel PIN?"
  options:
    - "pintool"
    - "client"
    - "module"
    - "driver"
  answer: 0
  explanation: "Плагины PIN — pintools."
- question: "Что такое taint-анализ?"
  options:
    - "Отслеживание распространения помеченных данных"
    - "Сканирование портов"
    - "Шифрование"
    - "Сжатие"
  answer: 0
  explanation: "Taint отслеживает, куда попадают «загрязнённые» данные."
- question: "Как запустить pintool?"
  options:
    - "pin -t tool.so -- ./target"
    - "gdb ./target"
    - "strace ./target"
    - "objdump ./target"
  answer: 0
  explanation: "PIN запускает target с инструментом через -t."
- question: "Почему DBI замедляет программу?"
  options:
    - "Инструментация каждой инструкции/блока добавляет оверхед"
    - "Он меняет файл"
    - "Он отключает кэш"
    - "Он шифрует память"
  answer: 0
  explanation: "Трансляция и колбэки добавляют накладные расходы."
```

## Где пригодится

- **CTF:** Reversing — трассировка.
- **Malware analysis:** перехват API.
- **Program analysis:** taint/coverage.
- **Работа:** tooling, research.
