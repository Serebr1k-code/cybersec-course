---
id: pwn-windows-kernel
title: "Windows kernel pwn (pool, SMEP bypass)"
category: pwn
parent: pwn-windows-intro
difficulty: expert
order: 2
tags: [pwn, windows, kernel, driver, pool, token]
prerequisites: [pwn-windows-intro, pwn-windows-heap]
useful_for:
  - "CTF Pwn — Windows kernel"
  - "Разработка эксплойтов"
estimated_minutes: 65
summary: "Эксплуатация уязвимых драйверов Windows: pool-коррупция, IOCTL, подмена токена и обход SMEP/KASLR в ring 0."
lab:
  kind: shell
  title: "Практика: IOCTL-код из клиента HEVD"
  toolset: [core, elf]
  workdir: /home/student/task
  files: [task.md, hevd.exe, hevd.objdump.txt]
  check: "grep -q 'ioctl=0x222003' answer.txt"
  hints:
    - "Драйвер общается с userland через `DeviceIoControl(h, IOCTL, ...)`."
    - "Путь устройства — строка `\\.\HackSysExtremeVulnerableDriver`."
    - "Код команды кладётся в стек как 32-битная константа — её видно в дизассемблере."
    - "Запиши `ioctl=0x222003`."
---

## Вопрос, с которого всё начинается

Ты нашёл уязвимый драйвер `.sys`. Из обычного пользовательского процесса ты можешь отправлять ему команды — и если драйвер доверчив, ты получишь доступ к памяти **ядра**. Успех здесь означает SYSTEM.

Но ядро Windows — не то же самое, что userland: вместо кучи работает **пул**, а главная защита — токен процесса. Разберём один конкретный баг и путь от него до SYSTEM.

## Наш пример: HEVD с произвольной записью

Возьмём учебный драйвер **HEVD** (HackSys Extreme Vulnerable Driver). Он предоставляет команду `IOCTL_HEVD_ARBITRARY_WRITE`, которая принимает структуру `{ void* Address; ULONG Value; }` и записывает `Value` по адресу `Address` — **без проверки**. Это готовый примитив произвольной записи в ядро.

Открывается драйвер как файл:

```c
HANDLE h = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
                       GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, 0, NULL);
```

А команда отправляется через `DeviceIoControl` — это стандартный способ общения с драйвером из userland (аналог `ioctl` на Linux):

```c
DeviceIoControl(h, IOCTL_HEVD_ARBITRARY_WRITE, &input, sizeof(input),
                NULL, 0, &bytes, NULL);
```

`IOCTL` — код команды; `input` содержит адрес и значение. Драйвер запишет по указанному ядерному адресу. Осталось решить: **что** и **куда** писать.

## Шаг 1. Куда целиться: структура _EPROCESS

Ядро описывает каждый процесс структурой `_EPROCESS`. В ней есть поле `Token` — указатель на структуру `_TOKEN` с привилегиями процесса. Процесс SYSTEM (PID 4) имеет «полный» токен.

Идея проста: если записать адрес SYSTEM-токена в `Token` **нашего** процесса, мы мгновенно получим его привилегии. Это называют **token stealing** — «кража токена».

## Шаг 2. Находим наш процесс и токен

В WinDbg (kernel-отладка) смотрим список процессов:

```text
kd> !process 0 0
PROCESS ffff9a0b0c1a5080  Image: exp.exe
    ...
```

Дальше разбираем структуру и находим смещение `Token` (оно зависит от версии Windows — определяй в отладчике, не «по памяти»):

```text
kd> dt nt!_EPROCESS ffff9a0b0c1a5080 Token
   +0x4b8 Token : 0xffffa10c6a3f9060
```

Здесь `Token` нашего процесса лежит по смещению `0x4b8`. Теперь найдём токен SYSTEM (PID 4):

```text
kd> dt nt!_EPROCESS <addr_of_pid4> Token
   +0x4b8 Token : 0xffffa10c6a3f9a80
```

## Шаг 3. Пишем токен

Теперь через примитив произвольной записи кладём SYSTEM-токен в наш `Token`:

```c
input.Address = (PVOID)(our_eprocess + 0x4b8);
input.Value   = (ULONG)system_token_low;   // и старшие 4 байта отдельным запросом
DeviceIoControl(h, IOCTL_HEVD_ARBITRARY_WRITE, &input, sizeof(input),
                NULL, 0, &bytes, NULL);
```

После этого наш процесс — SYSTEM. Запускаем `cmd.exe` и видим:

```text
C:\> whoami
nt authority\system
```

## Шаг 4. Почему data-only важен

Заметь: мы ни разу не исполняли свой код в ядре. Мы только **изменили данные**. Это критично, потому что современные Windows включают **HVCI** (Hypervisor-enforced Code Integrity) — гипервизор запрещает ядру исполнять невалидный код. При HVCI ни shellcode, ни ROP в ядре не сработают. А перезапись токена — **data-only** атака: она обходит и HVCI, и CFG, потому что не выполняет новый код.

## Шаг 5. Если примитива записи нет

Часто баг — это не готовая запись, а **pool overflow** или **UAF**. Тогда:

- **Pool overflow** — переполнение блока в пуле портит заголовок `_POOL_HEADER` соседа.
- **UAF** — освобождённый объект переиспользуется с контролируемым содержимым.
- **Type confusion** — user-данные интерпретируются как другой тип.

Каждый из этих багов сначала превращают в примитив чтения/записи, а затем — в перезапись токена.

## Шаг 6. Обход SMEP/SMAP/KASLR

Если всё же нужен control-flow hijack (например, target — не токен), придётся обходить защиты:

- **SMEP** запрещает ядру исполнять страницы userland. Наивный переход на shellcode в userland упадёт. Обход — ROP-цепочка из гаджетов ядра.
- **SMAP** запрещает ядру читать/писать userland-память напрямую.
- **KASLR** рандомизирует базу ядра. Нужна утечка (например, адрес `ntoskrnl` из структур `_EPROCESS`/`_KTHREAD` или через `NtQuerySystemInformation`).
- **Отключение SMEP** делается записью в регистр `cr4` гаджетом `mov cr4, rcx; ret`.

Практический алгоритм:

```text
1) Проанализировать драйвер (IOCTL, баг).
2) Настроить kernel-отладку (WinDbg + VM).
3) Получить примитив произвольной записи / переполнения.
4) Перезаписать _EPROCESS.Token на SYSTEM-токен (data-only).
5) Если нужен control-flow — обойти SMEP/KASLR через ROP.
6) Получить SYSTEM.
```

## Сравнение с Linux kernel pwn

Ядро Windows устроено иначе, чем Linux: пулы (`_POOL_HEADER`) вместо SLUB, `_EPROCESS`/`_TOKEN` вместо `task_struct`/`cred`, IOCTL вместо `ioctl` и `/dev`. Митигации похожи (SMEP/SMAP/KASLR), но добавляется HVCI. Классическая цель — перезапись токена, то есть data-only атака, которая не требует ROP и обходит HVCI. Из-за этого финальный шаг в Windows часто **проще**, чем в Linux, но разведка сложнее: нужна двухмашинная отладка и символы Microsoft. Смещения структур меняются между версиями, поэтому их определяют в WinDbg, а не «по памяти». Начни с HEVD, отработай arbitrary write → token, затем переходи к pool overflow и UAF.

## Аудит драйверов

В реальной задаче бинаря HEVD не будет — будет чужой `.sys`. Его анализируют так: `!dh driver.sys` для заголовков, затем IDA/Ghidra и поиск обработчиков IOCTL. Обращай внимание на `METHOD_NEITHER` (непроверенные user-указатели), отсутствие `ProbeForRead`/`ProbeForWrite`, переполнения в `memcpy`/`strcpy` и UAF объектов. Инструменты: `IOCTLpus` для генерации запросов, `DriverBuddy` (плагин IDA), `winchecksec` для митигаций. Аудит драйверов — востребованный навык: большинство реальных LPE-уязвимостей Windows живёт именно в сторонних драйверах, а не в самом ядре.

## Инструменты

- **WinDbg** (`kd`): `!process 0 0`, `!pool <addr>`, `!poolval <addr>`, `dt _EPROCESS <addr>`, `dt _TOKEN <addr>`.
- **OSR Loader** / `sc create` — загрузка драйвера.
- **IOCTLpus** — генерация IOCTL-запросов.
- **IDA/Ghidra** — анализ драйвера; **winchecksec** — его митигации.
- **HEVD** — учебный драйвер для практики.

## На что смотреть дальше

- **Неверный IOCTL-код** — функция просто не вызовется. Проверь код по заголовкам драйвера.
- **`METHOD_NEITHER`** передаёт user-указатель в ядро напрямую; без `ProbeForRead`/`ProbeForWrite` это дыра — но её надо использовать аккуратно.
- **Смещения зависят от версии Windows.** Всегда определяй `_EPROCESS.Token` в WinDbg.
- **Отладка требует двух машин** (host + target VM). Подготовь окружение заранее.
- **HVCI включён?** Тогда только data-only атаки вроде перезаписи токена.

## Что мы теперь знаем

- Драйверы Windows общаются с userland через IOCTL (`DeviceIoControl`).
- Ядро использует пул (`_POOL_HEADER`), а не кучу пользователя.
- Token stealing — перезапись `_EPROCESS.Token` на SYSTEM-токен.
- Это data-only атака: обходит HVCI и CFG, не исполняя новый код.
- SMEP/SMAP/KASLR обходятся ROP и утечками базы ядра.

## Квиз

Проверь себя.

```quiz
- question: "Какой интерфейс обычно использует уязвимый драйвер для приёма запросов из userspace?"
  options:
    - "DeviceIoControl (IOCTL)"
    - "io_uring"
    - "syscall read"
    - "mmap"
  answer: 0
  explanation: "Драйверы Windows общаются с userspace через IOCTL-коды DeviceIoControl."
- question: "Как обычно получают SYSTEM в Windows kernel pwn?"
  options:
    - "Подменой Token текущего _EPROCESS на System-токен"
    - "Вызовом execve"
    - "Отключением ASLR"
    - "Заполнением tcache"
  answer: 0
  explanation: "Token stealing — стандартный финальный шаг: копируем System-токен в свой процесс."
- question: "Что защищает SMEP?"
  options:
    - "Запрещает исполнение userspace-кода из ring 0"
    - "Шифрует память"
    - "Рандомизирует ядро"
    - "Ограничивает syscalls"
  answer: 0
  explanation: "SMEP не даёт ядру исполнять страницы userspace, ломая наивный переход на shellcode."
- question: "Что нужно, чтобы обойти KASLR в ядре Windows?"
  options:
    - "Утечка базы ядра (например, через чтение указателей)"
    - "Отключение seccomp"
    - "Заполнение fastbin"
    - "mmap PROT_EXEC"
  answer: 0
  explanation: "Без утечки базы адреса ядра неизвестны; leak обходит KASLR."
- question: "Почему token stealing часто предпочтительнее kernel ROP?"
  options:
    - "Он не требует исполнения кода в ring 0, только произвольной записи"
    - "Он быстрее компилируется"
    - "Он обходит SMEP автоматически"
    - "Он не требует багов"
  answer: 0
  explanation: "Имея AAR/AAW, можно повысить привилегии без control-flow hijack."
```

## Куда дальше

Мы закончили Windows-ветку и возвращаемся в userland. В `pwn-unicorn-emulation` научимся исполнять код без запуска бинаря — эмулировать отдельную функцию и забирать результат. А пока главное: **уязвимый драйвер + примитив записи = перезапись `_EPROCESS.Token` и SYSTEM, без единой строки исполняемого кода в ядре.**

## Где пригодится

- **CTF:** Pwn — Windows kernel-задачи с уязвимыми драйверами.
- **Bug bounty:** драйверы вендоров, LPE.
- **Пентест:** локальное повышение привилегий на Windows.
- **Работа:** security research, аудит драйверов.
