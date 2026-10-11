---
id: reversing-hypervisor
title: "Реверс гипервизоров и VMX"
category: reversing
parent: reversing-kernel-drivers
difficulty: expert
order: 2
tags: [reversing, hypervisor, vmx, intel-vt, amd-svm, hyperjacking, ring-minus-1]
prerequisites: [reversing-kernel-drivers, reversing-architectures]
useful_for:
  - "CTF Reversing (expert)"
  - "Malware analysis (hypervisor rootkits)"
  - "Virtualization security research"
estimated_minutes: 70
summary: "Анализ гипервизоров: Intel VT-x/AMD-V, VMCS, VM-exits, hyperjacking и реверс гипервизор-малвари."
---
Гипервизор — это слой виртуализации, который выполняется на уровне **ring -1** (VMX root mode у Intel, host mode у AMD) и контролирует работу гостевой ОС. Легитимные гипервизоры (KVM, Xen, Hyper-V, VMware) изолируют виртуальные машины, но тот же механизм используют **злонамеренные гипервизоры** (hyperjacking) и анти-читы: они невидимо перехватывают всё, что делает ОС, оставаясь за пределами её контроля. Реверс гипервизорного кода — высшая лига реверса, потому что здесь нет привычных API и сисколлов: логика строится на VM-exits и прямом доступе к VMCS. В этом уроке — аппаратная виртуализация Intel VT-x и AMD-V, инструменты анализа и полный разбор VM-exit обработчика.

## Что такое гипервизор и ring -1

Классическая модель x86 имеет четыре кольца защиты (ring 0–3). Аппаратная виртуализация добавляет ещё одно измерение: режим **VMX root** (где живёт гипервизор) и **VMX non-root** (где живёт гость). Переход из non-root в root называется **VM-exit**, обратно — **VM-entry**. Гипервизор настраивает условия выходов (например, «выходить при доступе к MSR», «при выполнении CPUID», «при записи CR3») и, получив управление, эмулирует или модифицирует поведение. Именно поэтому гипервизор может скрывать файлы, процессы и сетевые соединения от ОС: он перехватывает обращения раньше ядра. Типы гипервизоров: Type 1 (bare-metal: ESXi, Xen), Type 2 (hosted: VirtualBox, VMware Workstation), и **Type 0/rootkit** — злонамеренный, устанавливаемый из ядра.

## Intel VT-x: VMXON, VMCS и VM-exits

Основные инструкции Intel VMX:

- `VMXON` — включить VMX-операции, передав регион VMXON.
- `VMXOFF` — выключить.
- `VMCLEAR` — инициализировать область VMCS.
- `VMPTRLD` — загрузить текущую VMCS.
- `VMREAD`/`VMWRITE` — читать/писать поля VMCS.
- `VMLAUNCH` — запустить гостя впервые.
- `VMRESUME` — продолжить гостя после VM-exit.

**VMCS** (Virtual Machine Control Structure) — структура, описывающая состояние гостя и политику выходов. Ключевые поля: `GUEST_RIP`, `GUEST_RSP`, `GUEST_CR3`, `HOST_RIP` (куда прыгать при выходе), `VM_EXIT_CONTROLS`, `VM_ENTRY_CONTROLS`, `EXECUTIVE_VMCS_POINTER`, `EPTP` (для EPT). Когда гость делает то, что запрещено политикой, CPU сохраняет состояние в VMCS и прыгает на `HOST_RIP` — это и есть VM-exit. Реверс гипервизора = анализ обработчика выходов.

## AMD-V (SVM): VMCB и различия

AMD использует **SVM** (Secure Virtual Machine) с управляющей структурой **VMCB** (Virtual Machine Control Block) вместо VMCS. Инструкции: `VMRUN` (запуск гостя), `VMMCALL` (гость→хост), `VMLOAD`/`VMSAVE` (сохранение состояния), `CLGI`/`STGI` (глобальные прерывания), `SKINIT` (защищённый запуск). Поля VMCB: `intercept` (какие события перехватывать), `EXITCODE`, `EXITINFO1/2`, `RIP` гостя. Отличия от Intel: другой формат структур, другие MSR (`MSR_VM_CR`, `MSR_VM_HSAVE_PA`), поддержка вложенной пагинации (NPT). Реверс SVM-кода распознаётся по `VMRUN` и работе с VMCB.

## Hyperjacking: злонамеренные гипервизоры

Hyperjacking — установка гипервизора «под» работающей ОС без её ведома. Атакующий (обычно уже с ring 0) включает VMX, переносит текущую ОС в гостя и начинает перехватывать события. Типичные цели: сокрытие процессов/файлов/сети (rootkit), перехват ввода (keylogger), обход антивируса, отладка чужой ОС. Malware (например, концепты Blue Pill) и анти-читы используют это. Признаки в анализе: необычные значения `HOST_RIP`, наличие обработчика `VMexit`, MSR-доступы `IA32_VMX_*`, скрытая память под VMCS/VMCB. Обнаружение — по расхождениям между CPUID, MSR и поведением, по таймингам (`RDTSC` растёт на выходах) и по `VMX`-битам в `IA32_FEATURE_CONTROL`.

## Инструменты анализа и специфика VMX-кода

- **Ghidra/IDA**: дизассемблируют VMX-инструкции, если процессор поддерживает их декодирование (в Ghidra включите нужный процессор; в IDA — соответствующие наборы). Иногда инструкции отображаются как `db 0x0f 0x01 ...` — тогда помогают ручные таблицы опкодов.
- **radare2**: `r2 -a x86 -b 64 ./hv`, `pd` показывает инструкции; для новых — `e asm.cpu=`.
- **x64dbg/WinDbg**: отладка загрузки драйвера, брейкпоинты на `VMXON`, `VMLAUNCH`, `VMRESUME`; `!vmx` расширения в WinDbg.
- **Intel SDM** — справочник по полям VMCS и условиям выходов; без него реверс гипервизора почти невозможен.
- **cpuid/cpufeature**: проверка поддержки VMX (`CPUID.1:ECX.VMX[bit 5]`), `MSR_IA32_FEATURE_CONTROL`.

## Дизассемблирование VMX-инструкций

Опкоды VMX начинаются с `0F 01 C1..C4` (VMXON, VMCLEAR, VMPTRLD, VMPTRST, VMREAD, VMWRITE, VMLAUNCH, VMRESUME, VMXOFF). Пример распознавания:

```
0f 01 c1   VMXON  [rax]
0f c7 30   VMPTRLD [rax]
0f 78 c1   VMREAD rcx, rax      ; VMREAD <r/m64>, <r64>
0f 79 c1   VMWRITE rcx, rax
0f 01 c2   VMLAUNCH
0f 01 c3   VMRESUME
0f 01 c4   VMXOFF
```

В дизассемблере ищем `VMXON` (включение), затем `VMPTRLD` (загрузка VMCS), затем `VMLAUNCH`. Между ними — настройка VMCS через `VMWRITE` с номерами полей (например, `0x4000` = `GUEST_ES_SELECTOR`, `0x681E` = `HOST_RIP`). Расшифровка номеров полей — по таблице «VMCS Field Encodings» из SDM.

## Анализ VM-exit обработчика

Обработчик начинается по адресу `HOST_RIP`. Он читает причину выхода из `VM_EXIT_REASON` (VMCS field `0x4402`) и распределяет по switch:

```
VMREAD rax, [VM_EXIT_REASON]   ; 0x4402
and eax, 0xffff
cmp eax, 0x0c                  ; 12 = CPUID
je handle_cpuid
cmp eax, 0x30                  ; 48 = EPT violation
je handle_ept
cmp eax, 0x0a                  ; 10 = CPUID? (см. SDM)
```

Основные причины: `CPUID` (0x0a), `MSR read/write` (0x1f/0x20), `CR access` (0x1c), `EPT violation` (0x30), `external interrupt` (0x01), `VMCALL` (0x12), `I/O instruction` (0x1e). Каждый обработчик эмулирует поведение, скрывает данные или логирует. Именно здесь видно назначение гипервизора: rootkit подменяет результаты `CPUID`, скрывает MSR или перехватывает сеть.

## Обнаружение гипервизора

Гость может заподозрить наличие гипервизора:

- **CPUID timing**: `CPUID` под гипервизором вызывает VM-exit и работает в разы дольше.
- **RDTSC**: разница во времени между инструкциями аномально велика.
- **MSR `IA32_VMX_BASIC`**: если читается и не вызывает #GP в ring 0, гипервизор может быть активен.
- **CPUID leaf 0x40000000**: гипервизоры часто заполняют его своим именем («KVMKVMKVM», «Microsoft Hv», «VMwareVMware»).
- **CR3/IDT/GDT расхождения**, «невидимые» изменения памяти.
- **INVD/WBINVD**, `VMX`-биты в `IA32_FEATURE_CONTROL` при уже включённом VMX.

Анти-анализ со стороны гипервизора: скрывать свои структуры, перехватывать `CPUID` и подменять leaf 0x40000000, маскировать тайминги.

## Полный разбор: реверс простого гипервизора

**Шаг 1 — идентификация.** Открываем драйвер в Ghidra, ищем `VMXON`:

```
grep -oba $'\x0f\x01\xc1' hv.sys
```

**Шаг 2 — настройка VMCS.** Находим последовательность `VMPTRLD` и `VMWRITE`. По номерам полей восстанавливаем, что записывается в `HOST_RIP` — это адрес обработчика.

**Шаг 3 — обработчик.** Идём по `HOST_RIP`, находим `VMREAD` `VM_EXIT_REASON`, восстанавливаем switch. Например, обработчик `CPUID` подменяет leaf 0x40000000 на пустое имя — значит, гипервизор скрывается.

**Шаг 4 — цель.** Ищем перехват `MSR`/`I/O`/`EPT`. EPT-обработчик обычно прячет страницы памяти (rootkit-функция). Составляем карту перехватов.

**Шаг 5 — проверка.** В отладчике ставим брейкпоинт на `VMLAUNCH` и наблюдаем переход в non-root; затем на `HOST_RIP` — попадаем в обработчик при `CPUID`.

## Шпаргалка по VT-x/SVM

| Механизм | Intel VMX | AMD SVM |
|---|---|---|
| Структура | VMCS | VMCB |
| Включение | `VMXON` | `EFER.SVME=1` |
| Запуск гостя | `VMLAUNCH`/`VMRESUME` | `VMRUN` |
| Чтение/запись | `VMREAD`/`VMWRITE` | доступ к VMCB |
| Выход | VM-exit → `HOST_RIP` | #VMEXIT → `EXITCODE` |
| Причина | `VM_EXIT_REASON` (0x4402) | `EXITCODE` в VMCB |
| Память гостя | EPT | NPT |

## Что дальше / решение

Маршрут: найдите `VMXON`/`VMRUN` в драйвере, восстановите загрузку VMCS/VMCB, определите `HOST_RIP` и разберите switch по `VM_EXIT_REASON`, составьте карту перехватов и поймите назначение (rootkit/анти-чит). Используйте Intel SDM для полей и причин выходов, отладчик — для динамической проверки. Дальше изучайте вложенную виртуализацию, EPT-хуки и методы обнаружения гипервизоров (timing, CPUID, MSR), а также защиту от hyperjacking (VBS/HVCI, измеряемая загрузка).

## Вложенная виртуализация и EPT-хуки

Гипервизор может эмулировать сам VMX, позволяя запускать вложенные гипервизоры (nested virtualization). Это используется легитимно (Hyper-V внутри VMware) и злонамеренно (сокрытие). Аппаратно поддерживается через `VMCS shadowing` (Intel) или `nested paging`. Для реверса важно: обработчик `VM-exit` с причиной `VMCALL`/`VMLAUNCH` может эмулировать вложенный VMX, и тогда `VMXON` гостя перехватывается и подменяется. EPT (Extended Page Tables) добавляет второй уровень трансляции адресов гостя; нарушение EPT даёт `EPT violation` (exit 48). Rootkit использует EPT-хуки: делает страницу «отсутствующей», ловит обращение и подменяет содержимое — невидимо для гостя. Анализ: находим в обработчике `EPT violation` доступ к таблицам EPT (`EPTP`, `EPTP_LIST`) и модификацию PTE.

## Защита от гипервизорных руткитов: VBS и HVCI

Современные Windows включают **VBS** (Virtualization-Based Security) и **HVCI** (Hypervisor-enforced Code Integrity): система запускает собственный гипервизор (Hyper-V) и перемещает критические проверки в root mode, недоступный ядру. Это защищает от hyperjacking: обычный драйвер уже не может занять VMX (он занят защищённым гипервизором). Проверка: `systeminfo` (строка «Virtualization-based security»), `msinfo32` (VBS running). Для реверса это значит, что злонамеренный гипервизор на такой системе либо не запустится, либо должен эксплуатировать уязвимость в самом Hyper-V. Анти-читы (Vanguard, EAC) также используют собственные гипервизоры для изоляции проверок.

## Причины VM-exit: расширенная таблица

| Exit | Код | Обработка |
|---|---|---|
| External interrupt | 1 | доставка прерывания |
| Triple fault | 2 | сброс гостя |
| CPUID | 10 | подмена/эмуляция |
| HLT | 12 | остановка/эмуляция |
| VMCALL | 18 | гипервызов |
| CR access | 28 | контроль регистров |
| DR access | 29 | контроль отладки |
| I/O instruction | 30 | эмуляция портов |
| MSR read | 31 | скрытие MSR |
| MSR write | 32 | перехват записи |
| EPT violation | 48 | хук памяти |
| EPT misconfig | 49 | ошибка EPT |
| INVEPT | 50 | инвалидация EPT |

## Что дальше / решение (расширение)

Для практики разберите открытые гипервизорные руткиты (например, учебные PoC Blue Pill, hvpp) и легитимные гипервизоры (KVM, Xen — исходники открыты). Сравните, как KVM обрабатывает CPUID и EPT, и как это делают руткиты, чтобы понять разницу. Инструменты: `cpuid`, `rdmsr/wrmsr` (WinDbg), `!vmx`. Дальше — изучение VBS/HVCI, атак на Hyper-V и методов обнаружения гипервизоров по таймингам и MSR.

## Квиз

```quiz
- question: "На каком уровне работает гипервизор?"
  options:
    - "Ring -1 (ниже ядра)"
    - "Ring 3"
    - "Ring 0"
    - "BIOS"
  answer: 0
  explanation: "Гипервизор контролирует ОС-гостя с уровня ниже ring 0."
- question: "Что такое VMCS?"
  options:
    - "Структура состояния гостя (VM Control Structure)"
    - "Формат файла"
    - "Пакер"
    - "Таблица GOT"
  answer: 0
  explanation: "VMCS хранит состояние/управление гостевой VM."
- question: "Что такое VM-exit?"
  options:
    - "Переход из гостя в гипервизор (перехват события)"
    - "Выход из программы"
    - "Сброс CPU"
    - "Загрузка ОС"
  answer: 0
  explanation: "VM-exit передаёт управление гипервизору для обработки."
- question: "Как обнаружить гипервизор?"
  options:
    - "CPUID hypervisor bit, timing, MSR"
    - "Только strings"
    - "Только nm"
    - "Только ldd"
  answer: 0
  explanation: "CPUID/timing/MSR выявляют виртуализацию."
- question: "Что такое EPT?"
  options:
    - "Вложенные таблицы страниц (второй уровень трансляции)"
    - "Формат прошивки"
    - "Тип шифрования"
    - "Пакер"
  answer: 0
  explanation: "EPT/NPT контролирует доступ гостя к памяти."
```

## Где пригодится

- **CTF:** Reversing (expert) — hypervisor-задачи.
- **Malware analysis:** hypervisor-rootkits.
- **Virtualization security:** анализ.
- **Работа:** research.
