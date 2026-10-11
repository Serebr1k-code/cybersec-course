---
id: reversing-qbdi
title: "QBDI: современная DBI-инструментация"
category: reversing
parent: reversing-taint-analysis
difficulty: expert
order: 4
tags: [reversing, qbdi, dbi, instrumentation, frida, taint, callbacks]
prerequisites: [reversing-pin-dbi, reversing-frida-advanced]
useful_for:
  - "CTF Reversing"
  - "Malware analysis"
  - "Tooling development"
estimated_minutes: 55
summary: "QuarkslaB Dynamic Binary Instrumentation: callbacks, VMState, память и интеграция с Frida для трассировки."
---
QBDI (QuarkslaB Dynamic Binary Instrumentation) — современная библиотека **динамической бинарной инструментации**, работающая на x86-64, x86, ARM и AArch64. Она выполняет код в собственной «песочнице» (транслируя базовые блоки), предоставляя колбэки на инструкции, обращения к памяти, вызовы и возвраты, и легко интегрируется с Frida. QBDI — практичная замена Intel PIN там, где нужна инструментация **в процессе** (in-process) или поддержка ARM/embedded. В этом уроке — архитектура QBDI, API, полные примеры трассировки и интеграция с Frida.

## Что такое QBDI и его место среди DBI

QBDI — open-source проект (Apache 2.0), развиваемый Quarkslab. В отличие от PIN/DynamoRIO, которые обычно запускают программу заново под своим рантаймом, QBDI можно встроить **в сам процесс** (как библиотеку) или использовать через Frida (модуль `frida-qbdi`). Это даёт гибкость: инструментация уже запущенного процесса, работа на ARM (Android/iOS), низкий оверхед за счёт JIT-компиляции. QBDI не заменяет отладчик, но отлично подходит для трассировки, покрытия, taint-анализа и деобфускации.

## Установка и сборка

QBDI распространяется как prebuilt-библиотеки и через пакетные менеджеры. Сборка из исходников:

```bash
git clone https://github.com/quarkslab/QBDI.git
cd QBDI
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DQBDI_PLATFORM=linux -DQBDI_ARCH=X86_64
make -j$(nproc)
# библиотека: build/libQBDI.so
```

Для Frida-интеграции устанавливают модуль `frida-qbdi` (Python: `pip install frida-qbdi`). Готовые примеры — в `examples/` репозитория (`trace`, `instr`, `memaccess`).

## Архитектура: VM, callbacks и VMState

Основные компоненты:

- **VM** — объект, управляющий исполнением: `VM vm; vm.run(start, stop);`.
- **Callbacks** — функции, вызываемые при событиях: `vm.addCodeCB`, `vm.addMemAccessCB`, `vm.addVMCallCB`.
- **VMState** — состояние CPU: регистры, память, флаги.
- **Range/ModuleMap** — карта модулей для разрешения адресов.

События: `PREINST`/`POSTINST` (до/после инструкции), `MEMORY_READ`/`MEMORY_WRITE` (доступ к памяти), `EXEC_TRANSFER_CALL`/`EXEC_TRANSFER_RETURN` (вызовы/возвраты), `BASIC_BLOCK_ENTRY`. Колбэк получает `VMInstanceRef` и может читать/писать регистры и память.

## Базовый пример: трассировка

```cpp
#include <QBDI.h>
#include <cstdio>

QBDI::VMAction onInst(QBDI::VMInstanceRef vm, QBDI::GPRState *gpr,
                      QBDI::FPRState *fpr, void *data) {
    QBDI::rword pc = vm->getInstAddress();
    printf("0x%llx\n", (unsigned long long)pc);
    return QBDI::VMAction::CONTINUE;
}

int main() {
    QBDI::VM vm;
    vm.addCodeCB(QBDI::PREINST, onInst, nullptr);
    // запустить функцию по адресу 0x400600 с аргументами
    QBDI::GPRState *gpr = vm.getGPRState();
    gpr->rdi = 0x1234;                       // аргумент
    vm.run(0x400600, 0x400700);              // [start, stop)
    return 0;
}
```

`vm.run(start, stop)` исполняет диапазон под инструментацией. `vm.getGPRState()` даёт доступ к регистрам до запуска — так передают аргументы функции.

## Колбэки на память и инструкции

Для трассировки доступа к памяти:

```cpp
QBDI::VMAction onMem(QBDI::VMInstanceRef vm, QBDI::GPRState *gpr,
                     QBDI::FPRState *fpr, void *data) {
    const QBDI::MemoryAccess *acc = vm->getInstMemoryAccess();
    for (uint32_t i = 0; i < vm->getInstMemoryAccessSize(); i++) {
        printf("%s [0x%llx] size=%u\n",
               acc[i].type == QBDI::MEMORY_WRITE ? "W" : "R",
               (unsigned long long)acc[i].accessAddress,
               (unsigned)acc[i].size);
    }
    return QBDI::VMAction::CONTINUE;
}

vm.addMemAccessCB(QBDI::MEMORY_READ | QBDI::MEMORY_WRITE, onMem, nullptr);
```

Возвращая `VMAction::SKIP_INST` или `SKIP_PATCH`, можно пропустить инструкцию или патч — основа для модификации поведения (например, обхода проверки). `CONTINUE` продолжает исполнение.

## Интеграция с Frida

Модуль `frida-qbdi` позволяет запускать QBDI-инструментацию из Frida-скриптов, комбинируя удобство Frida с точностью QBDI:

```javascript
const QBDI = require("frida-qbdi");
QBDI.init();
const vm = QBDI.newVM();
vm.addCodeCB("PREINST", function (vm) {
    console.log("exec " + vm.getInstAddress());
});
const fn = Module.getExportByName("libtarget.so", "check");
vm.call(fn, [ptr(0x1000)]);     // вызвать под инструментацией
```

Это особенно полезно на Android/ARM, где PIN недоступен. Frida даёт attach и хуки, QBDI — точную инструментацию выбранной функции.

## Инструментация в процессе (in-process)

QBDI можно слинковать в собственное приложение или плагин и инструментировать функции «изнутри». Сценарии: встроенная защита/телеметрия, анализ своих же функций, эмуляция чужого кода. Преимущество — нет внешнего процесса и отладчика, сложнее детектировать. Схема: загрузить `libQBDI.so`, получить адрес функции, вызвать `vm.run`. Для эмуляции конкретной функции без её реального вызова используют `vm.call(fnPtr, args)` — QBDI исполнит её под инструментацией и вернёт результат.

## Отличия от PIN и применение

| Свойство | QBDI | Intel PIN | DynamoRIO |
|---|---|---|---|
| Платформы | x86/x64/ARM/ARM64 | x86/x64 | x86/x64/ARM |
| Режим | in-process / Frida | отдельный запуск | отдельный запуск |
| Язык | C++ (API) | C++ | C |
| Оверхед | низкий | высокий | средний |
| Frida-интеграция | да | нет | нет |
| Лицензия | Apache 2.0 | проприетарная | BSD |

QBDI выбирают для ARM/embedded, для инструментации в процессе и когда нужна связка с Frida. PIN/DynamoRIO — когда нужны зрелые инструменты (pinatrace, drmemtrace) на x86.

## Полный разбор: трассировка функции проверки

**Шаг 1 — сборка QBDI** и подключение к проекту (`-lQBDI -I QBDI/include`). **Шаг 2 — загрузка целевой библиотеки** в процесс (`dlopen`) и получение адреса функции (`dlsym`). **Шаг 3 — инструментация:**

```cpp
QBDI::VM vm;
vm.addCodeCB(QBDI::PREINST, onInst, nullptr);
vm.addMemAccessCB(QBDI::MEMORY_READ, onMem, nullptr);
QBDI::GPRState *g = vm.getGPRState();
g->rdi = (QBDI::rword)input;         // указатель на вход
vm.call((QBDI::rword)checkFn, {});
```

**Шаг 4 — анализ вывода:** по трассе инструкций и обращений к памяти восстанавливаем алгоритм проверки (какие байты сравниваются). **Шаг 5 — проверка:** подставляем найденный вход и убеждаемся, что функция вернула успех.

## Шпаргалка

| Задача | API |
|---|---|
| Создать VM | `QBDI::VM vm;` |
| Колбэк инструкций | `vm.addCodeCB(PREINST, cb, 0)` |
| Колбэк памяти | `vm.addMemAccessCB(READ\|WRITE, cb, 0)` |
| Запуск диапазона | `vm.run(start, stop)` |
| Вызов функции | `vm.call(fn, args)` |
| Регистры | `vm.getGPRState()` |
| Пропустить инструкцию | `return SKIP_INST` |
| Frida | `frida-qbdi` модуль |

## Что дальше / решение

Маршрут: соберите QBDI, подключите к своему инструменту (или Frida), поставьте колбэки на инструкции/память, вызовите целевую функцию под инструментацией и проанализируйте трассу. Для ARM/Android используйте Frida-интеграцию. Дальше изучайте taint-анализ на базе QBDI, деобфускацию через `SKIP_INST`/патчи и покрытие для фаззинга.

## Taint-анализ и деобфускация с QBDI

QBDI предоставляет события памяти и инструкций, на которых строят taint-анализ. Схема: пометить источник (буфер ввода) как «заражённый», затем на каждом `MEMORY_READ`/`MEMORY_WRITE` и инструкции обновлять метки регистров. QBDI не даёт taint «из коробки», но события памяти и доступ к `GPRState` позволяют реализовать его вручную. Для деобфускации удобен возврат `VMAction::SKIP_INST`: если инструкция — часть мёртвого кода (bogus control flow), её можно пропустить; для подмены результата проверки — `SKIP_PATCH` или запись в регистр через `setGPR`. Так «уплощённые» OLLVM-функции можно линеаризовать: отслеживая переменную-состояние и пропуская диспетчер. Комбинация QBDI с символьным решателем (Z3) даёт concolic: конкретное исполнение под QBDI + символьные выражения из трассы.

## QBDI на Android и ARM: практика

На Android QBDI применяют через Frida-модуль или нативную библиотеку, встроенную в приложение. Типичный сценарий: перехватить JNI-функцию и проинструментировать её вызовом `vm.call`. Для ARM64 нужно учитывать соглашение вызовов (X0–X7) и то, что `getGPRState` возвращает `x0..x30`, `sp`, `pc`. Сборка QBDI под Android требует NDK и указания `-DQBDI_ARCH=AARCH64 -DQBDI_PLATFORM=android`. На iOS QBDI работает на джейлбрейкнутых устройствах. Ограничение: на некоторых ARM-платформах часть инструкций не декодируется — QBDI сообщает об ошибке, и участок нужно обрабатывать отдельно. Для embedded (без ОС) QBDI встраивают в прошивку или используют эмулятор.

## Производительность и бенчмарки

QBDI обычно быстрее PIN за счёт JIT-компиляции и меньшего числа переключений контекста, но медленнее «чистой» эмуляции. Оверхед зависит от числа колбэков: инструментировать каждую инструкцию дорого, инструментировать только блоки или память — дешевле. Практические советы: используйте `addCodeCB` только на нужные события (`PREINST` дешевле, чем `POSTINST`), избегайте тяжёлых операций в колбэках (I/O, форматирование), буферизуйте вывод. Для длинных трасс пишите в бинарный буфер и разбирайте офлайн. QBDI поддерживает «инструментировать только диапазон» (`run(start, stop)`) — это резко снижает оверхед, если интересна одна функция.

## Типичные проблемы и их решение

- **Крэш при `run`**: неверный адрес диапазона или отсутствие загрузки модуля; проверяйте `Range`/`ModuleMap`.
- **Мусорные адреса**: неправильная база (ASLR/PIE); используйте реальные адреса из процесса.
- **Пропущенные события**: колбэк зарегистрирован не на то событие или инструкция не декодируется.
- **Неправильные регистры**: забыли учесть соглашение вызовов (rdi/x0 для первого аргумента).
- **Нет вывода**: не сбросили буфер (`fflush`) до завершения.
- **Несовпадение версий**: библиотека QBDI и заголовки из разных версий — пересоберите.
Отладка QBDI-инструмента ведётся под gdb: ставьте bp в колбэках, проверяйте `vm.getInstAddress()`.

## Сравнение с аппаратной трассировкой и эмуляцией

QBDI занимает нишу между эмуляторами (Unicorn/Qiling) и аппаратной трассировкой (Intel PT). Эмуляторы дают полный контроль над памятью и API, но требуют подстановки окружения и медленнее; QBDI исполняет **настоящий** код на CPU, поэтому ведёт себя как оригинал. Аппаратная трассировка (PT) не модифицирует код и почти не замедляет, но не даёт данных и не позволяет вмешиваться. Выбор: для точного контроля над исполнением конкретной функции — QBDI; для покрытия всего процесса — PT; для анализа в изолированной среде без CPU — эмулятор. Часто QBDI используют для верификации находок PT: PT находит путь, QBDI читает данные на этом пути.

## Квиз

```quiz
- question: "Что такое QBDI?"
  options:
    - "Библиотека динамической бинарной инструментации (DBI)"
    - "Формат файла"
    - "Отладчик ядра"
    - "Пакер"
  answer: 0
  explanation: "QBDI инструментирует код в процессе через колбэки."
- question: "Какие архитектуры поддерживает QBDI?"
  options:
    - "x86-64, ARM, AArch64 (и x86)"
    - "Только x86-64"
    - "Только ARM"
    - "Только MIPS"
  answer: 0
  explanation: "QBDI мультиплатформенный (x86/x86-64/ARM/AArch64)."
- question: "Что даёт VMState?"
  options:
    - "Доступ к регистрам и памяти инструментируемого процесса"
    - "Карту портов"
    - "Список файлов"
    - "Формат ELF"
  answer: 0
  explanation: "Через VMState читаются/пишутся регистры и память."
- question: "С чем интегрируется QBDI для JS-скриптов?"
  options:
    - "С Frida (frida-qbdi)"
    - "С gdb"
    - "С nmap"
    - "С IDA"
  answer: 0
  explanation: "frida-qbdi позволяет инструментировать из Frida."
- question: "Какой колбэк нужен для отслеживания записей памяти?"
  options:
    - "addMemAccessCB(MEMORY_WRITE, ...)"
    - "addCodeCB(PREINST, ...)"
    - "addVMEventCB"
    - "readMemory"
  answer: 0
  explanation: "addMemAccessCB с типом MEMORY_WRITE ловит записи."
```

## Где пригодится

- **CTF:** Reversing — трассировка/taint.
- **Malware analysis:** поведение без отладчика.
- **Tooling:** собственные DBI-инструменты.
- **Работа:** program analysis.
