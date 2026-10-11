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
---
Windows kernel pwn — это эксплуатация драйверов режима ядра Windows (`.sys`), которые принимают ввод от непривилегированных пользователей через `DeviceIoControl` и имеют баги (переполнения, произвольная запись, UAF). Успешная атака даёт SYSTEM. Особенности: ядро Windows использует пул (pool) вместо кучи, имеет собственные структуры (`_POOL_HEADER`, `_OBJECT_TYPE`), а также защиты (SMEP, SMAP, KASLR, HVCI). Типичные цели — перезапись токена процесса (`_TOKEN`) или `PreviousMode`. В этом уроке — устройство Windows-ядра, пул, типовые баги и приёмы эксплуатации.

## Модель угроз и доступ

Драйвер создаёт символьное устройство (`\Device\Vuln`), к которому обращаются через `CreateFile`/`DeviceIoControl`. IOCTL-коды передают команды и буферы. Баг — в обработчике IOCTL: неверная проверка длины, `METHOD_NEITHER` (прямая передача user-указателя в ядро без проверки), отсутствие `ProbeForRead`/`ProbeForWrite`. Это открывает произвольное чтение/запись ядерной памяти.

## Пул (pool) ядра

Ядро Windows аллоцирует память из пулов: `NonPagedPool` (не выгружаемый), `PagedPool` (выгружаемый). Каждый блок имеет `_POOL_HEADER` с полями `PreviousSize`, `PoolIndex`, `BlockSize`, `PoolType`. Переполнение блока портит заголовок соседа — основа эксплуатации. С Windows 10 появились сегментированные пулы (Segment Heap в ядре), усложняющие атаки.

## Перезапись токена

Классический приём: найти структуру `_EPROCESS` текущего процесса (через `PsGetCurrentProcess` или список `ActiveProcessLinks`), затем перезаписать указатель `Token` на токен процесса SYSTEM (или скопировать поля привилегий). Если у вас есть произвольная запись, это даёт мгновенное повышение до SYSTEM. Альтернатива — перезаписать `PreviousMode` или флаги привилегий в токене.

## Типовые баги

- **Arbitrary write через IOCTL.** Отсутствие проверки user-указателя позволяет писать в ядро.
- **Pool overflow.** Переполнение буфера пула.
- **UAF.** Объект освобождён, но используется.
- **Type confusion.** Неверная интерпретация user-данных.
- **NULL pointer dereference.** Иногда эксплуатируется через отображение NULL-страницы (старые версии).

## Инструменты

- **WinDbg** с kernel-отладкой (`kd`), команды `!process`, `!pool`, `!poolval`, `dt _EPROCESS`.
- **OSR Loader** / `sc create` — загрузка драйвера.
- **IOCTLpus** — генерация IOCTL-запросов.
- **IDA/Ghidra** — анализ драйвера.
- **HEVD** (HackSys Extreme Vulnerable Driver) — учебный драйвер.

## Разобранный пример: arbitrary write → token

```c
// открыть устройство
HANDLE h = CreateFileA("\\\\.\\Vuln", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
// IOCTL с произвольным адресом
DeviceIoControl(h, IOCTL_WRITE, &input, sizeof(input), NULL, 0, &bytes, NULL);
// input содержит kernel-адрес и значение -> запись
```

Далее: найти `_EPROCESS` текущего процесса, вычислить смещение `Token`, записать адрес SYSTEM-токена.

## Проверка митигаций

```text
!dh ntoskrnl             # защиты ядра
winchecksec driver.sys   # митигации драйвера
!process 0 0             # список процессов и их _EPROCESS
```

Современные Windows включают SMEP/SMAP, KASLR, HVCI (Hypervisor-enforced Code Integrity), блокирующие исполнение невалидного кода. Обход требует ROP в ядре и легитимных целей.

## Частые ошибки

- **Неверный IOCTL-код.** Функция не вызывается.
- **Не учтён `METHOD_NEITHER`.** User-указатель требует `ProbeForRead`.
- **CFG/HVCI.** Косвенные вызовы и исполнение данных заблокированы.
- **KASLR.** Адреса ядра рандомизированы.
- **Отладка без двух машин.** Kernel-отладка Windows требует host+target (или VM).

## Справочные таблицы

| Пул | Особенность |
|---|---|
| NonPagedPool | не выгружается |
| PagedPool | выгружается |
| Segment | новый формат |

| Команда | Назначение |
|---|---|
| `!process 0 0` | процессы |
| `dt _EPROCESS addr` | структура |
| `!pool addr` | заголовок пула |
| `!poolval addr` | валидация |

## Что дальше / решение

Дальше: `pwn-windows-intro`, `pwn-windows-heap`, `pwn-kernel-intro`, `pwn-kernel-rop`. Практический алгоритм: (1) проанализируйте драйвер (IOCTL, баг); (2) настройте kernel-отладку (WinDbg); (3) найдите произвольную запись/переполнение; (4) перезапишите `_EPROCESS.Token`; (5) обойдите SMEP/KASLR; (6) получите SYSTEM. Windows kernel pwn — востребованная область; начните с HEVD для практики.
## Полный разбор HEVD-эксплойта

HackSys Extreme Vulnerable Driver (HEVD) — учебный драйвер с набором уязвимостей, идеальный для практики. Разберём arbitrary write через IOCTL. HEVD предоставляет `IOCTL_HEVD_ARBITRARY_WRITE`, который принимает структуру `{ void* Address; ULONG Value; }` и записывает `Value` по `Address` без проверки. Эксплойт: (1) открыть `\\.\HackSysExtremeVulnerableDriver`; (2) найти `_EPROCESS` текущего процесса (через `PsGetCurrentProcess`/список `ActiveProcessLinks`); (3) вычислить смещение поля `Token` (зависит от версии Windows, ~0x4b8 на Win10 x64); (4) прочитать адрес SYSTEM-токена (процесс 4) или обнулить привилегии; (5) записать SYSTEM-токен в наш `_EPROCESS.Token` через arbitrary write; (6) получить SYSTEM-шелл (`cmd.exe`). Проверяем в WinDbg: `!process 0 0`, `dt _EPROCESS <addr>`, `dt _TOKEN <addr>`.

## Поиск _EPROCESS и токена

Структура `_EPROCESS` описывает процесс. Полезные поля: `UniqueProcessId` (PID), `ActiveProcessLinks` (двусвязный список), `Token` (указатель на `_TOKEN`). Смещения зависят от версии Windows — определяйте через WinDbg (`dt _EPROCESS`). Алгоритм: (1) получить адрес нашего `_EPROCESS` (например, через `PsGetCurrentProcess` или по PID в списке); (2) найти `_EPROCESS` процесса SYSTEM (PID 4); (3) прочитать его `Token`; (4) записать этот указатель в наш `Token`. После этого наш процесс имеет привилегии SYSTEM. Это классический приём, работающий при наличии произвольной записи. Альтернатива — перезаписать `_TOKEN.Privileges` для включения всех привилегий.

## Обход SMEP/SMAP/KASLR в Windows

Windows-ядро включает SMEP/SMAP на современных процессорах. Для обхода: (1) найти гаджеты в `ntoskrnl.exe` (через `!mona` или ROPgadget); (2) отключить SMEP/SMAP, записав `cr4` (гаджет `mov cr4, rcx; ret`); (3) построить ROP для `commit`-аналога (в Windows — манипуляция токеном или вызов `ZwOpenProcess`). KASLR обходится через утечки (например, адрес `ntoskrnl` из `_EPROCESS`/`_KTHREAD` или через `NtQuerySystemInformation`). HVCI (если включён) блокирует исполнение невалидного кода — тогда используйте data-only атаки (перезапись токена), не требующие исполнения кода.

## Настройка отладки ядра

Kernel-отладка Windows: настройте виртуальную машину с target Windows, включите kernel debugging (`bcdedit /debug on`, `bcdedit /dbgsettings net ...`), на host запустите WinDbg с `kd -k net:port=...,key=...`. Установите символы (`_NT_SYMBOL_PATH=srv*C:\symbols*https://msdl.microsoft.com/download/symbols`). Полезные команды: `!process 0 0` (все процессы), `dt nt!_EPROCESS <addr>`, `!pool <addr>`, `bp nt!NtDeviceIoControlFile`. Логируйте всё — kernel-эксплуатация требует точности.

## Практические рекомендации

Начните с HEVD на Windows 10 x64 (без HVCI), отработайте arbitrary write → token. Затем переходите к pool overflow и UAF. Всегда проверяйте митигации (`!dh ntoskrnl`, `winchecksec`). Помните, что смещения структур зависят от версии Windows — определяйте их в WinDbg, а не «по памяти». Kernel-отладка требует двух машин (или VM), поэтому подготовьте окружение заранее. Windows kernel pwn — востребованный навык, особенно для driver-аудита.

## Сравнение с Linux kernel pwn

Windows-ядро отличается от Linux: пулы вместо SLUB, `_EPROCESS`/`_TOKEN` вместо `task_struct`/`cred`, IOCTL вместо `ioctl`/`/dev`. Митигации похожи (SMEP/SMAP/KASLR), но есть HVCI. Классическая цель — перезапись токена (data-only), что не требует ROP и обходит HVCI. Это делает Windows kernel pwn часто «проще» в финальном шаге, но сложнее в разведке (двухмашинная отладка, символы). Изучите HEVD для практики и постепенно переходите к реальным драйверам. Помните, что смещения структур зависят от версии — определяйте их в WinDbg.

## Аудит драйверов

В реальных задачах вы анализируете драйвер: `!dh driver.sys`, IDA/Ghidra, поиск IOCTL-обработчиков. Обращайте внимание на `METHOD_NEITHER` (непроверенные user-указатели), отсутствие `ProbeForRead`/`ProbeForWrite`, переполнения в `memcpy`/`strcpy`, UAF объектов. Инструменты: `IOCTLpus`, `DriverBuddy` (плагин IDA), `winchecksec`. Практикуйтесь на HEVD и уязвимых драйверах из CTF. Аудит драйверов — востребованный навык в реальной безопасности.

## Data-only атаки против HVCI

HVCI (Hypervisor-enforced Code Integrity) запрещает исполнение невалидного кода в ядре, поэтому ROP/шеллкод не работают. В таких условиях применяют **data-only** атаки: изменяют данные, а не код. Классика — перезапись `_EPROCESS.Token` на SYSTEM-токен (без исполнения кода). Также используют перезапись `_TOKEN.Privileges` для включения всех привилегий, изменение `_EPROCESS.Protection` или `PreviousMode`. Data-only атаки обходят HVCI и CFG, потому что не выполняют новый код. Это делает перезапись токена особенно ценной целью в современном Windows kernel pwn.

## Итоговая мысль

Windows kernel pwn — востребованная и сложная область. Ключевые навыки: анализ драйверов, kernel-отладка (WinDbg), поиск `_EPROCESS`/`_TOKEN`, обход SMEP/KASLR/HVCI. Начните с HEVD, отработайте data-only перезапись токена, затем переходите к pool overflow и UAF. Помните, что data-only атаки обходят HVCI и CFG, что делает их предпочтительными. Практикуйтесь на уязвимых драйверах и CTF, и вы освоите эту область.

## Дополнительные ресурсы

Изучайте публичные writeup'ы по Windows kernel CVE (например, в драйверах `afd.sys`, `win32k.sys`, `clfs.sys`), блоги исследователей и материалы с конференций. HEVD и другие учебные драйверы — лучшая площадка для практики. Помните, что Windows kernel меняется с каждой версией, поэтому навык адаптации и отладки важнее знания конкретных смещений.

## Финальный совет

Настройте отладочное окружение заранее: виртуальная машина с target Windows, символы Microsoft, WinDbg на host. Это экономит часы при отладке эксплойта. Начните с HEVD arbitrary write, затем pool overflow, затем UAF. Двигайтесь от простого к сложному и всегда проверяйте каждый шаг в отладчике.


## Практика: HEVD и data-only

Настройте kernel-отладку (WinDbg + VM). Загрузите HEVD (`sc create`). Отработайте arbitrary write → перезапись `_EPROCESS.Token` на SYSTEM-токен (data-only, обходит HVCI). Затем pool overflow и UAF. Используйте `!process 0 0`, `dt _EPROCESS`, `dt _TOKEN`. Практикуйтесь и изучайте публичные CVE в драйверах. Windows kernel pwn востребован для driver-аудита. Помните, что смещения структур зависят от версии — определяйте в WinDbg.

## Квиз

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
    - "Подменой Token текущего EPROCESS на System-токен"
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
  explanation: "SMEP не даёт ядру исполнять страницы userspace, ломая наивный shellcode-переход."
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

## Где пригодится

- **CTF:** Pwn — Windows kernel-задачи с уязвимыми драйверами.
- **Bug bounty:** драйверы вендоров, LPE.
- **Пентест:** локальное повышение привилегий на Windows.
- **Работа:** security research, аудит драйверов.
