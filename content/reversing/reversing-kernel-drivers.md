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
---
**Kernel-драйверы** — код, исполняемый в ring 0, с полным доступом к памяти, устройствам и системным структурам. Их реверс нужен для анализа rootkit'ов, анти-читов, эксплойтов и уязвимостей драйверов (частая точка входа в привилегированную эксплуатацию). Windows-драйверы (`.sys`, WDM/KMDF) и Linux-модули (`.ko`) имеют свои конвенции, точки входа и API. Этот урок — практический разбор kernel-драйверов от идентификации до поиска уязвимостей.

## Точки входа

| ОС | Точка входа | Примечание |
|----|-------------|------------|
| Windows (WDM) | `DriverEntry` | регистрирует `DriverObject->MajorFunction[]` |
| Windows (KMDF) | `EvtDriverDeviceAdd` | фреймворк, WDF-объекты |
| Linux (LKM) | `module_init`/`init_module` | `module_exit` для выгрузки |
| macOS | `kmod_start` | kext |

Windows-драйвер получает `PDRIVER_OBJECT` и `PUNICODE_STRING` (путь реестра). В `DriverEntry` регистрируются обработчики IRP (`IRP_MJ_CREATE`, `IRP_MJ_DEVICE_CONTROL`, ...) — основной функционал живёт в них.

## Windows: реверс .sys

```bash
file driver.sys
# Импорты — что драйвер умеет
objdump -p driver.sys | grep -iE "DLL Name" -A2
# или pefile
python3 -c "import pefile; pe=pefile.PE('driver.sys'); [print(e.dll) for e in pe.DIRECTORY_ENTRY_IMPORT]"
# Строки
strings -a driver.sys | grep -iE "Device|\\\\Device\\\\|ioctl|Symbolic"
```

Ключевые API и их смысл:

| API | Значение |
|-----|----------|
| `IoCreateDevice`/`IoCreateSymbolicLink` | создание устройства/симлинка (доступ из userland) |
| `ObRegisterCallbacks` | перехват доступа к процессам (античит/защита) |
| `PsSetCreateProcessNotifyRoutine` | уведомление о создании процессов |
| `PsSetLoadImageNotifyRoutine` | уведомление о загрузке образов |
| `MmCopyVirtualMemory` | копирование памяти между процессами |
| `KeStackAttachProcess` | доступ к адресному пространству другого процесса |
| `ZwOpenProcess`/`ZwProtectVirtualMemory` | операции с процессами/памятью |
| `IoCreateDriver`/`ZwLoadDriver` | (динамическая) загрузка драйвера |

## Linux: реверс .ko

```bash
file module.ko
modinfo module.ko                       # метаданные (author, license, params)
readelf -s module.ko | grep -iE "init|exit"
# Символы (если не stripped)
nm module.ko | grep -iE "init|exit|register"
objdump -d -M intel module.ko | less
```

Linux-модуль использует `module_init`/`module_exit`; регистрирует `file_operations` (для char/block device), `proc`/`sysfs`-интерфейсы, сетевые хуки. Ищите:

- `register_chrdev`/`misc_register` — интерфейс из userland.
- `copy_from_user`/`copy_to_user` — граница с пользователем (частая зона уязвимостей).
- `kallsyms_lookup_name` — динамический резолвинг символов ядра (rootkit-техника).
- Хуки syscall'ов / ftrace / kprobes — перехват.

## Уязвимости драйверов

Драйверы — популярная цель привилегированной эксплуатации:

- **Невалидированный ввод IOCTL.** `IRP_MJ_DEVICE_CONTROL` получает буфер из userland; без проверки размера/типа — переполнение.
- **Отсутствие проверки прав.** Устройство доступно любому пользователю (`GENERIC_WRITE`) — можно вызвать привилегированные операции.
- **Arbitrary write/read.** Драйверы, дающие произвольное чтение/запись физической/виртуальной памяти (часто «читерские»), эксплуатируются для повышения привилегий.
- **BYOVD.** Загрузка уязвимого, но подписанного драйвера для получения ring 0 в обход DSE.
- **TOCTOU/гонки.** Обработка буфера с проверкой и последующим использованием без блокировки.

## Инструменты

| Инструмент | Роль |
|------------|------|
| Ghidra/IDA + kernel-типы | статический разбор |
| WinDbg (kernel) | отладка Windows-драйвера |
| `objdump`/`nm`/`readelf` | разбор ELF/PE |
| `pefile`/`lief` | разбор из Python |
| Volatility | анализ дампов памяти |
| `modinfo`/`modprobe` | Linux-модули |
| `chipsec` | платформенный аудит |

## Разобранный пример: анализ .sys

```text
1) strings: найти \Device\ и IOCTL-коды.
2) DriverEntry: регистрация MajorFunction (CREATE/DEVICE_CONTROL).
3) Обработчик IRP_MJ_DEVICE_CONTROL: switch по IOCTL.
4) Для каждого IOCTL: проверить валидацию буфера (размер, адрес).
5) Найти arbitrary write (MmCopyVirtualMemory/KeStackAttachProcess).
6) Оценить: уязвимость / rootkit-техника.
```

```bash
strings -a driver.sys | grep -iE '\\\\Device\\\\|IOCTL'
objdump -d driver.sys | grep -iE "IoCreateDevice|IoCreateSymbolicLink|MmCopyVirtualMemory"
```

## Rootkit-техники

- **Сокрытие процессов/файлов** — перехват `ZwQuerySystemInformation`/`NtQueryDirectoryFile` или удаление из списков (`ActiveProcessLinks`).
- **DKOM** — прямая модификация структур ядра (манипуляция списками).
- **SSDT/inline-хуки** — перехват системных вызовов.
- **Callback-сокрытие** — перехват уведомлений для фильтрации.
- **Детект** — сравнение с эталоном (списки, таблицы), поиск несоответствий, проверка целостности.

## Пошаговый разбор Linux-модуля

```bash
# 1) Метаданные и точка входа
modinfo module.ko
readelf -s module.ko | grep -iE "init_module|cleanup_module|init|exit"

# 2) Дизасм инициализации
objdump -d -M intel module.ko | sed -n '/init_module/,/ret/p' | head -60

# 3) Какие интерфейсы регистрирует
objdump -d module.ko | grep -iE "register_chrdev|misc_register|proc_create|kallsyms_lookup_name"

# 4) Граница с пользователем
objdump -d module.ko | grep -iE "copy_from_user|copy_to_user"

# 5) Хуки (rootkit-признаки)
objdump -d module.ko | grep -iE "kprobe|ftrace|sys_call_table|write_cr0"
```

В `file_operations` ищите `unlocked_ioctl`/`write`/`read` — там ввод из userland. Проверяйте, валидируется ли длина и копируется ли корректно (`copy_from_user` с проверкой возврата и размера). Классический баг — `copy_from_user` в фиксированный буфер без проверки `count` (переполнение ядерного стека/кучи).

Rootkit-признаки: `kallsyms_lookup_name` (резолвинг символов в обход экспортов), прямая запись в `sys_call_table` (снятие write-protection через `write_cr0`/CR0.WP), регистрация kprobe/ftrace-хуков. Их наличие — сильный индикатор вредоносности.

## Практика: разбор Windows DriverEntry

```c
// Псевдокод типичного DriverEntry
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    drv->DriverUnload = DrvUnload;
    drv->MajorFunction[IRP_MJ_CREATE]         = DrvCreate;
    drv->MajorFunction[IRP_MJ_CLOSE]          = DrvClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIoctl;
    UNICODE_STRING dev = RTL_CONSTANT_STRING(L"\\Device\\MyDrv");
    IoCreateDevice(drv, 0, &dev, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_Dev);
    UNICODE_STRING sym = RTL_CONSTANT_STRING(L"\\DosDevices\\MyDrv");
    IoCreateSymbolicLink(&sym, &dev);
    return STATUS_SUCCESS;
}
```

Шаги разбора:

```text
1) Найти DriverEntry (по ссылке в PE-заголовке/символам или по строкам \Device\).
2) Выписать регистрацию MajorFunction — какие IRP обрабатываются.
3) Найти обработчик IRP_MJ_DEVICE_CONTROL: switch по IoControlCode.
4) Для каждого кода — проверить валидацию InputBufferLength/OutputBufferLength
   и доступность устройства из userland (права на \DosDevices\...).
5) Искать arbitrary write (MmCopyVirtualMemory, KeStackAttachProcess, запись по
   user-controlled адресу).
```

Наличие симлинка `\DosDevices\...` означает доступ из userland — потенциальная точка атаки. Если IOCTL не проверяет длину буфера и пишет по адресу из ввода — это локальное повышение привилегий.

## Частые ошибки

- **Анализ без kernel-типов.** Без структур (`EPROCESS`, `DRIVER_OBJECT`) дизасм малопонятен — импортируйте типы.
- **Пропуск IOCTL.** Основной функционал — в обработчике IOCTL, а не в DriverEntry.
- **Не проверить подпись.** Неподписанные драйверы не грузятся (DSE); для теста — test-signing.
- **Запуск драйвера на хосте.** Только изолированная VM (драйвер может всё сломать).
- **Игнорирование версии ядра.** Смещения структур зависят от версии — сверяйте с PDB/BTF.
- **Нет дампа памяти.** Для rootkit-анализа сравнение с эталоном критично.

## Настройка исследовательского окружения

- **Windows**: изолированная VM со включённой kernel-отладкой (WinDbg через named pipe/network), test-signing для загрузки своих драйверов, снапшоты. Не работайте с драйверами на хосте.
- **Linux**: модуль собирается под точную версию ядра (`uname -r`); загрузка в VM с тем же ядром; `dmesg` для логов; `rmmod` для выгрузки.
- **Типы ядра**: для Ghidra/IDA импортируйте PDB (Windows) или BTF/`vmlinux` (Linux) — без них структуры непонятны.
- **Изоляция**: драйвер в ring 0 может всё; никогда не тестируйте на рабочей системе.

## Linux vs Windows: различия

| Аспект | Windows | Linux |
|--------|---------|-------|
| Формат | PE (.sys) | ELF (.ko) |
| Точка входа | DriverEntry/EvtDriverDeviceAdd | module_init |
| Интерфейс userland | Device + IOCTL | char device/ioctl, proc/sysfs |
| Граница | `METHOD_BUFFERED`/`_IN_DIRECT` | `copy_from_user`/`copy_to_user` |
| Загрузка | `sc create`/`ZwLoadDriver`, DSE | `insmod`/`modprobe` |
| Типы | PDB | BTF/vmlinux |

## Пример IOCTL-уязвимости

```c
// уязвимый обработчик (псевдокод)
NTSTATUS DrvIoctl(PDEVICE_OBJECT dev, PIRP irp) {
    PIO_STACK_LOCATION st = IoGetCurrentIrpStackLocation(irp);
    ULONG inlen  = st->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outlen = st->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = irp->AssociatedIrp.SystemBuffer;
    switch (st->Parameters.DeviceIoControl.IoControlCode) {
    case 0x80002000:                       // без проверки длины!
        memcpy(user_ptr, buf, *(ULONG*)buf); // переполнение / arbitrary write
        break;
    }
    ...
}
```

Анализ: для каждого IOCTL-кода проверьте, валидируются ли `InputBufferLength`/`OutputBufferLength`, есть ли проверка адресов (`ProbeForRead`/`ProbeForWrite`) и прав доступа. Отсутствие проверок → переполнение/arbitrary write → локальное повышение привилегий.

## Что делать дальше / решение

1. Идентифицируйте тип драйвера и точку входа.
2. Снимите импорты/строки — карта возможностей.
3. Разберите DriverEntry и обработчики IRP/файловых операций.
4. Для каждого IOCTL/интерфейса проверьте валидацию буфера и права доступа.
5. Ищите arbitrary read/write, хуки, DKOM-техники.
6. Подтвердите на изолированной VM; оформите отчёт (уязвимость/техника, IOC).

## Квиз

```quiz
- question: "Какая точка входа у Windows-драйвера?"
  options:
    - "DriverEntry"
    - "main"
    - "module_init"
    - "_start"
  answer: 0
  explanation: "DriverEntry — аналог main для драйверов Windows."
- question: "Что такое IOCTL?"
  options:
    - "Код команды для драйвера через DeviceIoControl"
    - "Формат файла"
    - "Тип шифрования"
    - "Сетевой пакет"
  answer: 0
  explanation: "IOCTL кодирует функцию/устройство/метод/доступ."
- question: "Что такое SSDT hook?"
  options:
    - "Подмена записей System Service Descriptor Table"
    - "Сканирование портов"
    - "Шифрование диска"
    - "Сжатие памяти"
  answer: 0
  explanation: "SSDT-хук перехватывает системные сервисы."
- question: "Как безопасно анализировать драйвер?"
  options:
    - "В изолированной VM с kernel-отладкой"
    - "На рабочей системе"
    - "Без изоляции"
    - "Сразу загрузить"
  answer: 0
  explanation: "Изоляция и снапшоты защищают от последствий."
- question: "Какая точка входа у Linux-модуля?"
  options:
    - "module_init"
    - "DriverEntry"
    - "main"
    - "DllMain"
  answer: 0
  explanation: "Linux-модули используют module_init/module_exit."
```

## Где пригодится

- **CTF:** Reversing (expert) — kernel-задачи.
- **Malware analysis:** rootkits.
- **Anti-cheat/kernel research:** анализ драйверов.
- **Работа:** kernel security.
