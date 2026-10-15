---
id: reversing-kernel-drivers
title: "Реверс драйверов ядра"
category: reversing
parent: reversing-static-targets
difficulty: expert
order: 4
tags: [reversing, kernel, driver, rootkit, windows-kernel, linux-module, ioctl]
prerequisites: [reversing-anti-vm, reversing-architectures]
useful_for:
  - "CTF Reversing (expert)"
  - "Malware analysis (rootkits)"
  - "Anti-cheat / kernel research"
estimated_minutes: 70
summary: "Анализ kernel-драйверов Windows и модулей Linux: точки входа, IOCTL, хуки, rootkit-техники и безопасный разбор."
lab:
  kind: shell
  title: "Практика: паспорт и строки kernel-модуля"
  toolset: [core, hex]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Начни с `file vboxnetflt.ko` — это ELF. Исполняемый или объектный?"
    - "`readelf -h` покажет `Type: REL (Relocatable file)` — не готовая программа, а объектный файл."
    - "`strings -n 6 vboxnetflt.ko` даёт карту функциональности и подсказки-символы."
    - "Сохрани строки: `strings -n 6 vboxnetflt.ko > found.txt`, затем `check`."
---

## Задача

У тебя есть файл `vboxnetflt.ko` — **модуль ядра Linux**. Такой код исполняется в ring 0, с
полным доступом к памяти и устройствам. Реверс драйверов нужен для анализа rootkit'ов,
анти-читов и уязвимостей, через которые получают права ядра. Задача: понять, что модуль
делает, какие интерфейсы предоставляет и где может быть опасно.

**Важно:** драйвер может сломать всю систему. Работаем только статически или в изолированной
VM. Никакой загрузки на рабочей машине.

## Данные: метаданные модуля

Первое — `file` и `modinfo`. Второй показывает «паспорт» модуля:

```bash
$ file vboxnetflt.ko
vboxnetflt.ko: ELF 64-bit LSB relocatable, x86-64, ...

$ modinfo vboxnetflt.ko
name:           vboxnetflt
version:        7.2.16 r174877 ((0xA2CDe001U))
license:        GPL
description:    Oracle VirtualBox Network Filter Driver
depends:        vboxdrv
vermagic:       6.19.11-arch1-1 SMP preempt mod_unload
sig_id:         PKCS#7
signer:         DKMS module signing key
```

Читаем: `name` — имя модуля, `depends: vboxdrv` — от какого модуля он зависит (грузится после
него), `vermagic` — под какое ядро собран (с несовпадающим ядром не загрузится), `signer` —
модуль **подписан**. Подпись важна: в современных системах неподписанные модули не грузятся
(аналог DSE в Windows).

## Шаг 1: это не исполняемый файл

```bash
$ readelf -h vboxnetflt.ko | grep -E 'Type|Entry|Machine'
  Type:                              REL (Relocatable file)
  Machine:                           Advanced Micro Devices X86-64
  Entry point address:               0x0
```

`Type: REL` (relocatable) и точка входа `0x0` — перед нами **не** готовая программа, а
объектный файл. Ядро само размещает его в памяти и применяет релокации. Это принципиальное
отличие `.ko` от обычного ELF: у него нет фиксированной точки входа, есть `init`/`exit`-функции.

## Шаг 2: секции и точки входа

Смотрим секции — у модулей они говорящие:

```bash
$ readelf -S vboxnetflt.ko | grep -E '\.text|\.init|\.exit|\.modinfo|__ksymtab'
  [ 3] .text      PROGBITS  ...
  [10] .init.text PROGBITS  ...      # код инициализации (выгружается после загрузки)
  [14] .exit.text PROGBITS  ...      # код выгрузки
  [18] .modinfo  PROGBITS  ...       # метаданные (то, что показал modinfo)
```

Символы дают реальные точки входа:

```bash
$ nm vboxnetflt.ko | grep -iE 'init_module|cleanup_module|LinuxInit'
0000000000000010 t VBoxNetFltLinuxInit
0000000000000000 T __pfx_init_module
0000000000000000 T __pfx_cleanup_module
```

`init_module` — что вызывается при загрузке (`module_init`), `cleanup_module` — при выгрузке
(`module_exit`). В нашем случае инициализация реализована в `VBoxNetFltLinuxInit`. Всё, что
делает модуль при старте (регистрация интерфейсов, хуков), — здесь.

## Шаг 3: строки — карта функциональности

```bash
$ strings -n 6 vboxnetflt.ko | grep -iE 'VBox|netflt|device|failed' | head
vboxNetFltLinuxStartXmitFilter
vboxNetFltLinuxHookDev
vboxNetFltLinuxUnhookDev
vboxnetflt/VBoxNetFlt.c
VBoxNetFlt: Successfully started.
VBoxNetFlt: failed to initialize device extension (rc=%d)
```

Строки называют **источник** (`VBoxNetFlt.c`), функции (`HookDev`/`UnhookDev`) и сообщения.
`Hook`/`Unhook` — намёк на перехват сетевых операций (это сетевой фильтр). Для rootkit'а здесь
ты бы искал строки вида `kallsyms_lookup_name`, `sys_call_table`, `hide`, `hide_pid`.

## Шаг 4: импорты — что модуль умеет

`nm -u` показывает **неразрешённые** символы — то есть функции, которые модуль берёт у ядра
или других модулей. Это «декларация возможностей»:

```bash
$ nm -u vboxnetflt.ko | head
                 U SUPDrvLinuxIDC
                 U VBoxHost_RTMemAllocTag
                 U VBoxHost_RTMemFree
                 U VBoxHost_RTNetIPv4FinalizeChecksum
                 U VBoxHost_RTNetIPv6PseudoChecksumEx
```

Видно, что модуль работает с памятью (`RTMemAlloc`/`RTMemFree`) и сетевыми пакетами
(`RTNetIPv4*Checksum`) — согласуется с «Network Filter Driver». Импорты сразу говорят, какие
системные возможности задействованы.

Для Linux-модуля особое внимание на **границу с пользователем**: `copy_from_user`/`copy_to_user`,
`register_chrdev`/`misc_register`, `unlocked_ioctl`. Это места, где в модуль попадает ввод из
userspace — и где чаще всего живут уязвимости.

## Шаг 5: Windows-драйверы (.sys) — что иначе

Windows-драйвер — это PE-файл, и точка входа у него называется `DriverEntry`:

```c
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    drv->MajorFunction[IRP_MJ_CREATE]         = DrvCreate;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIoctl;   // сюда идут IOCTL
    IoCreateDevice(drv, 0, &dev, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_Dev);
    IoCreateSymbolicLink(&sym, &dev);                       // доступ из userland
    return STATUS_SUCCESS;
}
```

Логика такая же, как у `.ko`: в `DriverEntry` регистрируются обработчики, а основной
функционал — в **IRP-обработчиках**. Ключевое — `IRP_MJ_DEVICE_CONTROL`: через него
пользовательский процесс шлёт драйверу команды **IOCTL** (I/O Control), несущие буфер с
данными. `IoCreateSymbolicLink` создаёт симлинк `\DosDevices\...` — это и есть «вход» для
атакующего.

## Шаг 6: где искать уязвимости

Драйверы — популярная цель привилегированной эксплуатации:

- **Невалидированный ввод IOCTL.** Обработчик получает буфер из userland; без проверки
  размера/типа — переполнение.
- **Отсутствие проверки прав.** Устройство доступно любому пользователю → привилегированные
  операции вызываются из непривилегированного процесса.
- **Arbitrary write/read.** Драйвер пишет/читает по адресу из ввода → локальное повышение прав.
- **BYOVD.** Загрузка уязвимого, но **подписанного** драйвера для получения ring 0 в обход
  защиты от неподписанных драйверов.

Для каждого IOCTL-кода проверяй, валидируются ли `InputBufferLength`/`OutputBufferLength` и
права. Отсутствие проверок — классический путь к повышению привилегий.

## Шаг 7: rootkit-техники (по признакам)

Если модуль вредоносный, он будет прятаться. Ищи в дизассемблере и строках:

- `kallsyms_lookup_name` — резолвинг символов ядра в обход экспортов (rootkit-техника).
- Прямая запись в `sys_call_table` со снятием write-protection (`write_cr0`, CR0.WP) — SSDT-хуки.
- `kprobe`/`ftrace` — перехват функций ядра.
- **DKOM** — прямая модификация структур ядра (удаление процесса из списка `ActiveProcessLinks`).

Наличие таких конструкций — сильный индикатор вредоносности. Детект строится на сравнении с
эталоном: сверяют списки процессов/драйверов и таблицы системных вызовов с «чистой» системой
и ищут расхождения (пропавшие записи, подменённые указатели).

## Если не сработало

- **Дизасм непонятен** — нужны kernel-типы: импортируй `BTF`/`vmlinux` (Linux) или `PDB`
  (Windows) в Ghidra/IDA; без структур смещения полей — «магия».
- **Модуль не грузится** — `vermagic` не совпадает с ядром или подпись не принята.
- **Смещения «плывут»** — структуры ядра зависят от версии; сверяй с точной версией (`uname -r`).
- **Стриппленный модуль** — опирайся на `modinfo`, секции и строки; `init`/`exit` ищи по
  секциям `.init.text`/`.exit.text`.

## Что мы теперь знаем

- `.ko` — это **relocatable** ELF без точки входа; ядро само размещает его и зовёт `init`/`exit`.
- `modinfo` даёт паспорт модуля (имя, `depends`, `vermagic`, подпись) — первый шаг триажа.
- Секции `.init.text`/`.exit.text` и символы `init_module`/`cleanup_module` — точки входа.
- Неразрешённые символы (`nm -u`) — карта возможностей модуля.
- Windows-драйвер: `DriverEntry` + обработчики IRP; IOCTL — главный канал ввода из userland.
- Уязвимости драйверов — невалидированный IOCTL, отсутствие прав, arbitrary write/read, BYOVD.

## Декодирование IOCTL-кода

Код IOCTL — не случайное число, а упакованная структура. В Windows его собирают макросом `CTL_CODE`:

```c
#define CTL_CODE(DeviceType, Function, Method, Access) \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)
```

Поля читаются так: `DeviceType` (тип устройства, старшие 16 бит), `Access` (права доступа), `Function` (номер функции), `Method` (способ передачи буфера: `METHOD_BUFFERED`, `METHOD_IN_DIRECT`, `METHOD_OUT_DIRECT`, `METHOD_NEITHER`). Разберём конкретный код:

```text
IOCTL 0x0022E004
  DeviceType = 0x0022   (FILE_DEVICE_UNKNOWN)
  Access     = 0x3      (FILE_READ_DATA | FILE_WRITE_DATA)
  Function   = 0x801
  Method     = 0x0      (METHOD_BUFFERED)
```

`Method` критичен для поиска уязвимостей: `METHOD_BUFFERED` — буфер копируется ядром (безопаснее), а `METHOD_NEITHER` передаёт **сырые пользовательские указатели** прямо в драйвер — классический источник arbitrary read/write, если драйвер не валидирует адрес через `ProbeForRead`/`ProbeForWrite`. Поэтому в дизассемблере обработчика IOCTL первым делом ищите разбор кода (обычно `switch` по `Parameters.DeviceIoControl.IoControlCode`) и смотрите, какой `Method` у интересующей команды.

## Граница с userspace в Linux-модуле

В Linux-модулях точка входа из userland — файловые операции. Ищите регистрацию и обработчики:

```c
static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    struct req r;
    if (copy_from_user(&r, (void __user *)arg, sizeof(r)))   // <-- граница
        return -EFAULT;
    switch (cmd) {
        case SET_ADDR:  g_addr = r.addr;  break;   // <-- нет валидации = arbitrary
        case WRITE32:   *(u32 *)g_addr = r.val; break;
    }
    return 0;
}
```

Красные флаги: `copy_from_user` без проверки размера, `unlocked_ioctl` без проверки `cmd` по белому списку, использование пользовательского указателя напрямую (`(void __user *)arg` без копирования). В сочетании с `misc_register` (устройство доступно всем) это даёт локальное повышение привилегий. При реверсе выписывайте каждый `case` и проверяйте, валидируются ли аргументы и есть ли проверка прав (`capable(CAP_SYS_ADMIN)`).

## Динамический анализ в изолированной VM

Статики хватает не всегда — иногда нужно запустить драйвер и посмотреть в отладчике. Безопасный маршрут:

- **Linux:** QEMU с `-s -S` (gdb-стаб на порту 1234), `vmlinux` с символами, загрузка модуля в гостя и `target remote :1234` из gdb. Ставьте точки на `my_ioctl` и наблюдайте входные данные.
- **Windows:** WinDbg с **kernel debugging** через виртуальный COM-порт (`\\\\.\\pipe\\...`) или сетевой транспорт; `!drvobj`, `!devobj`, `!irp` показывают драйверы, устройства и IRP в реальном времени.
- **Обязательно:** снапшот VM перед загрузкой, отдельная сеть (host-only), отсутствие доступа к реальным данным. Драйвер в ring 0 может затереть диск, сеть, зашифровать файлы — VM изолирует последствия.

Динамика дополняет статику: вы видите, **какой** IOCTL вызывается, **какие** данные приходят и **где** драйвер обращается к памяти — это подтверждает гипотезы из дизассемблера.

## Квиз

Проверь себя.

```quiz
- question: "Почему `.ko` имеет `Type: REL` и точку входа 0x0?"
  options:
    - "Это relocatable-объект: ядро само размещает его в памяти и применяет релокации"
    - "Файл повреждён"
    - "Это исполняемый ELF"
    - "Так задумано для Windows"
  answer: 0
  explanation: "Модуль ядра — не готовая программа; точки входа — init/exit-функции."
- question: "Что показывает `modinfo module.ko`?"
  options:
    - "Паспорт модуля: имя, license, depends, vermagic, подпись"
    - "Дизассемблированный код"
    - "Список IOCTL"
    - "Дамп памяти"
  answer: 0
  explanation: "`modinfo` читает секцию `.modinfo` с метаданными."
- question: "Какая точка входа у Windows-драйвера?"
  options:
    - "DriverEntry"
    - "main"
    - "module_init"
    - "_start"
  answer: 0
  explanation: "`DriverEntry` — аналог `main`; регистрирует IRP-обработчики."
- question: "Что такое IOCTL?"
  options:
    - "Код команды, которую userland шлёт драйверу через DeviceIoControl"
    - "Формат PE-файла"
    - "Тип шифрования"
    - "Сетевой пакет"
  answer: 0
  explanation: "IOCTL кодирует функцию/устройство/метод/доступ и несёт буфер данных."
- question: "Как безопасно анализировать драйвер?"
  options:
    - "Статически или в изолированной VM с kernel-отладкой"
    - "Загрузить на рабочей системе"
    - "Без изоляции и снапшотов"
    - "Сразу выполнить"
  answer: 0
  explanation: "Драйвер в ring 0 может всё сломать; изоляция и снапшоты обязательны."
```

## Куда дальше

Мы разобрали модуль ядра и его опасные места. Но многие современные вредоносы вообще не
трогают ядро — они живут в **памяти процесса** и прячутся от статических инструментов. Дальше
мы перейдём к символьному исполнению — технике, которая автоматически находит ввод,
удовлетворяющий условиям проверки. А пока главное запомни: **у `.ko` нет точки входа —
есть `init`/`exit`; уязвимости живут на границе с userland.**

## Где пригодится

- **CTF Reversing (expert):** kernel-задачи и разбор драйверов.
- **Malware analysis:** rootkit'ы и DKOM-техники.
- **Anti-cheat / kernel research:** анализ драйверов защиты.
- **Работа (kernel security):** аудит драйверов, поиск LPE-уязвимостей.
