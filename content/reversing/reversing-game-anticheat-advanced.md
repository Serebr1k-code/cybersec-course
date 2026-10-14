---
id: reversing-game-anticheat-advanced
title: "Анти-чит advanced: kernel и hypervisor"
category: reversing
parent: reversing-kernel-drivers
difficulty: expert
order: 2
tags: [reversing, anticheat, kernel, hypervisor, games, bypass, detection]
prerequisites: [reversing-game-anticheat, reversing-kernel-drivers]
useful_for:
  - "CTF Reversing (expert)"
  - "Game security research"
  - "Kernel/hypervisor analysis"
estimated_minutes: 65
summary: "Продвинутый анализ анти-читов: kernel-драйверы, hypervisor-детект, техники обнаружения и контрмеры."
lab:
  kind: shell
  title: 'Практика: анализ анти-чит-драйвера (детект гипервизора)'
  toolset: [core, hex, rev]
  workdir: /home/student/task
  files: [task.md, acdrv.sys]
  check: "grep -q 'nto{hyp3rv1s0r_d3t3ct10n_byp4ss}' found.txt"
  hints:
    - '`file acdrv.sys` — PE32+ (драйвер). Kernel-античит видит систему целиком.'
    - 'Строки драйвера хранят «визитки» проверок: `VMXON`, `hypervisor_present`, `KdDebuggerEnabled`.'
    - '`strings acdrv.sys` — среди строк лежит флаг.'
    - '`strings acdrv.sys | grep nto > found.txt` и `check`.'
---
## Вопрос, с которого всё начинается

Анти-чит современных игр давно перестал быть «файлом в папке с игрой». Он
работает **в ядре**: драйвер следит за процессами, памятью и подозрительными
модификациями, а иногда ставит гипервизор, чтобы видеть всё «сверху». Как такие
драйверы устроены и как их анализировать? Разберём на реальном модуле ядра
Linux.

## Наш пример

Возьмём настоящий драйвер — `vboxnetflt.ko` (сетевой фильтр VirtualBox). Это
реальный **kernel module** (`.ko`, объект ядра). Посмотрим, что о нём можно
узнать без запуска:

```
$ modinfo vboxnetflt.ko
filename:       .../vboxnetflt.ko
version:        7.2.16 r174877
license:        GPL
description:    Oracle VirtualBox Network Filter Driver
depends:        vboxdrv
name:           vboxnetflt
```

`modinfo` читает секцию `.modinfo` и выдаёт метаданные: имя, версию, лицензию,
зависимости. Для анти-чита тут были бы название драйвера, версия и подпись
разработчика.

## Шаг 1: чем .ko отличается от обычного ELF

Посмотрим заголовок:

```
$ readelf -h vboxnetflt.ko
  Type:    REL (Relocatable file)
  Machine: Advanced Micro Devices X86-64
```

Тип **REL** (relocatable), а не EXEC — модуль ядра не готов к запуску, его
**загружает ядро** и применяет релокации по адресам ядра. Секции тоже особые:

```
  [ 3] .text        PROGBITS
  [10] .init.text   PROGBITS
  [14] .exit.text   PROGBITS
  [18] .modinfo     PROGBITS
```

- **`.init.text`** — код инициализации; после загрузки ядро **выгружает** его из
  памяти (экономия).
- **`.exit.text`** — код выгрузки модуля.
- **`.modinfo`** — метаданные (то, что читает `modinfo`).

Это важно для реверса: точка входа модуля — не `_start`, а **`init_module`**
(или функция, зарегистрированная через `module_init`). У нас она называется
`VBoxNetFltLinuxInit`.

## Шаг 2: точки входа модуля

Найдём символы инициализации:

```
$ nm vboxnetflt.ko | grep -iE 'init_module|cleanup_module'
0000000000000010 t VBoxNetFltLinuxInit
0000000000000000 T __pfx_init_module
```

Ядро вызывает `init_module` при загрузке и `cleanup_module` при выгрузке.
Именно в `init_module` драйвер регистрирует всё, что ему нужно: обработчики
устройств, хуки, колбэки. Для анти-чита это место, где он «подключается» к
системе.

## Шаг 3: как ядерный анти-чит следит за системой

Драйвер ядра умеет то, чего не может пользовательская программа. Типовые
механизмы (на примере Windows, но идея та же в Linux):

- **Уведомления о процессах** — `PsSetCreateProcessNotifyRoutine`: колбэк при
  каждом создании/завершении процесса.
- **Уведомления о загрузке образов** — `PsSetLoadImageNotifyRoutine`: видит
  каждый загруженный модуль (читерский драйвер/инжект).
- **Объектные колбэки** — `ObRegisterCallbacks`: перехватывает открытие
  процессов/потоков, может запретить доступ к памяти игры.
- **Фильтр файловой системы** — мини-фильтр видит все обращения к файлам.
- **Проверка памяти** — чтение/сканирование памяти игры из ядра.

Именно поэтому читы, работающие в пользовательском режиме, ядерный анти-чит
видит «как на ладони».

## Шаг 4: гипервизор — анти-чит выше ядра

Самый глубокий уровень — **гипервизор** (VMM, Virtual Machine Monitor).
Анти-чит загружает свой гипервизор (или использует встроенный, как Intel VT-x /
AMD-V), чтобы:

- видеть все обращения гостевой ОС к памяти;
- использовать **EPT** (Extended Page Tables) для контроля доступа;
- прятаться от читов, работающих в ядре, — гипервизор выше ядра;
- обнаруживать «вложенные» гипервизоры (чит под виртуалкой).

Детект гипервизора мы разбирали в уроке про анти-VM: бит hypervisor в CPUID,
вендор листа `0x40000000`. Анти-чит с гипервизором ещё и проверяет тайминги и
поведение виртуализации.

## Шаг 5: анализ ядерного драйвера

Порядок разбора `.ko`/`.sys`:

1. **Метаданные** — `modinfo`, строки, версия, зависимости.
2. **Точки входа** — `init_module`/`cleanup_module` (Linux) или
   `DriverEntry`/`Unload` (Windows).
3. **Импорты ядра** — какие API вызывает: в Linux — `printk`,
   `register_netdevice_notifier`, `kallsyms_lookup_name`; в Windows —
   `PsSetCreateProcessNotifyRoutine`, `ObRegisterCallbacks`.
4. **Строки** — сообщения об ошибках часто раскрывают логику.
5. **Отладка** — ядерный модуль можно отлаживать (kgdb, WinDbg kernel-mode),
   но это требует второй машины или виртуалки.

## Шаг 6: обход ядерных анти-читов

Честно говоря, обход ядерных анти-читов — отдельная большая область, и здесь
важнее понять принципы:

- **Изоляция.** Чит запускают на отдельной машине (внешний чит) — анти-чит не
  видит процессов.
- **Обход колбэков.** Иногда удаляют/перехватывают зарегистрированные
  колбэки — но это уже требует ядерного доступа и часто детектируется.
- **Гипервизор-обход.** Чит сам становится гипервизором — тогда он выше
  анти-чита, но это редкий и сложный сценарий.
- **Детект и контрмеры** — анти-чит ищет следы обхода (изменённые таблицы,
  несоответствия таймингов).

Понимание обеих сторон (что анти-чит видит и как чит прячется) — суть этой
темы.

## Шаг 7: реверс .ko на практике

Разберём наш модуль подробнее. Зависимости видно в метаданных (`depends:
vboxdrv`), а вызываемые символы — через релокации и таблицу неопределённых
символов:

```
$ nm vboxnetflt.ko | grep ' U ' | head
                 U VBoxHost_RTR0Init
                 U printk
```

Строка `U VBoxHost_RTR0Init` — «undefined»: модуль вызывает функцию из другого
модуля (`vboxdrv`). А `printk` — стандартный вывод ядра (аналог `printf`).
Именно по импортам ядра опознают назначение драйвера: набор
`register_netdevice_notifier`, `netif_rx` говорит, что это сетевой фильтр; набор
колбэков процессов — что это мониторинг.

Полезно помнить: у `.ko` нет символов отладки, но имена экспортируемых функций
сохраняются, если модуль собран «как есть». В проприетарных анти-читах имена
часто затирают, и тогда опираются на строки и поведение.

## Шаг 8: различия Linux и Windows

Анти-читы чаще пишут под Windows, но принципы общие. Различия:

- **Точка входа.** Linux — `init_module`/`cleanup_module`; Windows —
  `DriverEntry` и `Unload`.
- **Формат.** Linux — ELF `.ko`; Windows — PE `.sys` (тот же PE, что у `.exe`,
  но подсистема Native).
- **API.** Linux — `register_*_notifier`, `kallsyms_lookup_name`; Windows —
  `Ps*`, `Ob*`, `Flt*`.
- **Подпись.** Windows требует подписанный драйвер (или тестовый режим); Linux
  проверяет подписи модулей при Secure Boot.

Понимая обе платформы, ты легко переносишь навык анализа драйвера с одной на
другую.

## Частые вопросы

**Можно ли отлаживать ядерный модуль?** Да, но осторожно: `kgdb`/QEMU для Linux,
WinDbg в kernel-mode для Windows. Ошибка в драйвере роняет всю систему (BSOD).

**Как понять, что драйвер — анти-чит?** По набору колбэков процессов/образов,
строкам с названиями игр, обфускации и проверкам гипервизора.

**Что делать, если драйвер обфусцирован?** Разбирать по частям: находить
`init_module`, восстанавливать вызовы API, искать строки; для виртуализации —
девиртуализировать (см. урок про VMProtect).

## Инструмент: objdump — дизассемблер

`objdump` показывает машинный код бинарника в виде ассемблера. Именно по нему считают смещения буферов, находят вызовы и адреса — основа статического разбора.

Ключи, которые пригодятся:
* `objdump -d <файл>` — дизассемблировать секцию `.text` (машинный код функций);
* `objdump -d <файл> | less` — листать вывод, искать нужную функцию по имени;
* `objdump -M intel -d <файл>` — синтаксис Intel (привычнее, чем AT&T);
* в выводе важны пролог функции (`push rbp; mov rbp,rsp`) и `sub rsp,N` — по нему видно размер кадра.

### Рабочий пример (как в лаборатории)

```
$ objdump objdump -x acdrv.sys

/tmp/labgen/fx/acdrv.sys:     file format pei-x86-64
/tmp/labgen/fx/acdrv.sys
architecture: i386:x86-64, flags 0x0000013f:
HAS_RELOC, EXEC_P, HAS_LINENO, HAS_DEBUG, HAS_SYMS, HAS_LOCALS, D_PAGED
start address 0x0000000140001000

Characteristics 0x22
	executable
	large address aware

Time/Date		Tue Oct 13 18:36:06 2026
Magic			020b	(PE32+)
MajorLinkerVersion	14
MinorLinkerVersion	0
SizeOfCode		0000000000000200
SizeOfInitializedData	0000000000000600
SizeOfUninitializedData	0000000000000000
AddressOfEntryPoint	0000000000001000
BaseOfCode		0000000000001000
ImageBase		0000000140000000
SectionAlignment	00001000
FileAlignment		00000200
MajorOSystemVersion	6
MinorOSystemVersion	0
MajorImageVersion	0
MinorImageVersion	0
MajorSubsystemVersion	6
MinorSubsystemVersion	0
Win32Version		00000000
SizeOfImage		00005000
SizeOfHeaders		00000400
CheckSum		00000000
Subsystem		00000003	(Windows CUI)
DllCharacteristics	00008160
					HIGH_ENTROPY_VA
					DYNAMIC_BASE
					NX_COMPAT
					TERMINAL_SERVICE_AWARE
SizeOfStackReserve	0000000000100000
SizeOfStackCommit	0000000000001000
SizeOfHeapReserve	0000000000100000
SizeOfHeapCommit	0000000000001000
LoaderFlags		00000000
NumberOfRvaAndSizes	00000010

The Data Directory
Entry 0 0000000000000000 00000000 Export Directory [.edata (or where ever we found it)]
Entry 1 0000000000000000 00000000 Import Directory [parts of .idata]
Entry 2 0000000000000000 00000000 Resource Directory [.rsrc]
Entry 3 0000000000000000 00000000 Exception Directory [.pdata]
Entry 4 0000000000000000 00000000 Security Directory
Entry 5 0000000000000000 00000000 Base Relocation Directory [.reloc]
Entry 6 0000000000003000 0000001c Debug Directory
Entry 7 0000000000000000 00000000 Description Directory
Entry 8 0000000000000000 00000000 Special Directory
Entry 9 0000000000000000 00000000 Thread Storage Directory [.tls]
Entry a 0000000000000000 00000000 Load Configuration Directory
Entry b 0000000000000000 00000000 Bound Import Directory
Entry c 0000000000000000 00000000 Import Address Table Directory
Entry d 0000000000000000 00000000 Delay Import Directory
Entry e 0000000000000000 00000000 CLR Runtime Header
Entry f 0000000000000000 00000000 Reserved

There is a debug directory in .buildid at 0x140003000

Type                Size     Rva      Offset
  2        CodeView 00000019 0000301c 0000081c
(format RSDS signature 5e50cd2441d5c8474c4c44205044422e age 1 pdb (none))

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .text         00000049  0000000140001000  0000000140001000  00000400  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .rdata        00000020  0000000140002000  0000000140002000  00000600  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .buildid      00000035  0000000140003000  0000000140003000  00000800  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  3 .data         00000024  0000000140004000  0000000140004000  00000a00  2**4
                  CONTENTS
```

Подсказка из лаборатории: `objdump -x <файл>`.

## Что мы теперь знаем

- Модуль ядра — ELF типа **REL** с секциями `.init.text/.exit.text/.modinfo`;
  `modinfo` даёт метаданные, точки входа — `init_module`/`cleanup_module`.
- В нашем примере точка входа — `VBoxNetFltLinuxInit`, зависимости — `vboxdrv`.
- Ядерный анти-чит использует колбэки (процессы, образы, объекты) и фильтры
  файловой системы, а иногда **гипервизор** (EPT, детект VM).
- Анализ драйвера идёт по метаданным, точкам входа, импортам ядра и строкам.
- Обход ядерных анти-читов — отдельная область: изоляция, обход колбэков,
  собственный гипервизор.

## Квиз

Проверь себя.

```quiz
- question: Какого типа ELF у модуля ядра?
  options:
    - "REL (relocatable) — его загружает ядро"
    - "EXEC"
    - "DYN (PIE)"
    - "CORE"
  answer: 0
  explanation: "Модуль — релокируемый объект, загружаемый ядром."
- question: Что содержит секция .modinfo?
  options:
    - "метаданные модуля (имя, версия, лицензия)"
    - "машинный код"
    - "таблицу импортов"
    - "ключи шифрования"
  answer: 0
  explanation: "modinfo читает .modinfo: имя, версия, зависимости."
- question: Какая функция вызывается при загрузке модуля Linux?
  options:
    - "init_module (через module_init)"
    - "_start"
    - "main"
    - "DriverEntry"
  answer: 0
  explanation: "Ядро вызывает init_module при загрузке модуля."
- question: Что такое EPT в контексте анти-чита?
  options:
    - "таблица страниц гипервизора для контроля доступа к памяти"
    - "формат файла игры"
    - "сетевой протокол"
    - "алгоритм сжатия"
  answer: 0
  explanation: "EPT (Extended Page Tables) даёт гипервизору контроль памяти."
- question: Как ядерный анти-чит узнаёт о запуске процессов?
  options:
    - "через колбэки вроде PsSetCreateProcessNotifyRoutine"
    - "через чтение реестра"
    - "через ping сервера"
    - "через Wi-Fi"
  answer: 0
  explanation: "Уведомительные колбэки сообщают ядру о событиях системы."
```

## Куда дальше

В следующем уроке мы вернёмся к образцам и разберём **извлечение конфигурации
малвари** — где прячется конфиг и как его достать. А пока главное запомни:
**продвинутый анти-чит живёт в ядре и гипервизоре, а его анализ — это метаданные,
точки входа и импорты ядра**.

## Где пригодится

- **CTF Reversing (expert):** задачи на драйверы.
- **Game security research:** анализ анти-читов и читов.
- **Kernel/hypervisor analysis:** драйверы и виртуализация.
- **Работа:** аудит низкоуровневых компонентов.
