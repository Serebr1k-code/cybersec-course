---
id: pwn-unicorn-emulation
title: "Unicorn: эмуляция кода для pwn и обхода anti-debug"
category: pwn
parent: pwn-emulation
difficulty: hard
order: 1
tags: [unicorn, emulation, cpu, hooks, anti-debug, python]
prerequisites: [pwn-emulation]
useful_for:
  - "CTF Pwn категория"
  - "Malware analysis"
  - "Reverse engineering"
estimated_minutes: 50
summary: "Полный разбор Unicorn: API, память, регистры, хуки и практические примеры эмуляции функций, обхода anti-debug и расчёта значений."
---

Unicorn — лёгкий фреймворк CPU-эмуляции, который позволяет исполнять машинный код в программной модели процессора, без реальной ОС. Для pwn это мощный инструмент: вы можете вызвать отдельную функцию с произвольными аргументами, не запуская бинарь целиком; обойти анти-отладочные проверки; посчитать результат крипто-рутины; или проэмулировать шелл-код до первого `syscall`, чтобы убедиться в корректности.

В этом уроке мы разберём API Unicorn, работу с памятью и регистрами, хуки, и соберём несколько практических примеров — от эмуляции функции проверки до обхода anti-debug. Материал открывает модуль `pwn-emulation`.

## Что такое Unicorn и зачем он в pwn

Unicorn основан на QEMU и поддерживает множество архитектур: x86, x86-64, ARM, ARM64, MIPS, PPC, SPARC. Он не эмулирует ОС: нет загрузчика, нет системных вызовов, нет файловой системы. Всё, что у вас есть, — память и регистры. Это одновременно и ограничение, и преимущество: вы полностью контролируете окружение.

Где это полезно в pwn:

- **Вызов одной функции.** Не нужно доводить программу до нужного состояния — просто эмулируйте функцию.
- **Обход anti-debug.** Проверки на `ptrace`/`rdtsc` не видят эмулятор.
- **Брутфорс проверок.** Гоняйте крипто-рутину миллионы раз за секунды.
- **Проверка шелл-кода.** Исполняйте до `syscall` и смотрите, что в регистрах.
- **Декомпиляция «на лету».** Логируйте каждый шаг и восстанавливайте алгоритм.

Важно понимать границу применимости: Unicorn не «понимает» программу, он просто исполняет байты. Если код обращается к неразмеченной памяти или делает syscall, эмуляция прервётся исключением. Поэтому перед запуском нужно замапить все регионы, к которым код будет обращаться, и перехватить внешние вызовы. Это ручная работа, но именно она даёт полный контроль над окружением — то, чего не бывает при обычном запуске.

## Установка и базовый API

```bash
pip install unicorn capstone
python3 -c "import unicorn; print(unicorn.__version__)"
# 2.0.1
```

Минимальный пример — исполнить две инструкции x86-64:

```python
from unicorn import *
from unicorn.x86_const import *

CODE = 0x1000000
STACK = 0x2000000
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE, 0x1000)
mu.mem_map(STACK, 0x1000)
mu.mem_write(CODE, b"\x48\xc7\xc0\x2a\x00\x00\x00")  # mov rax, 42
mu.reg_write(UC_X86_REG_RSP, STACK + 0x800)
mu.emu_start(CODE, CODE + 7)
print(hex(mu.reg_read(UC_X86_REG_RAX)))
# 0x2a
```

Ключевые вызовы: `Uc(arch, mode)` создаёт эмулятор, `mem_map` выделяет регион, `mem_write`/`mem_read` работают с памятью, `reg_write`/`reg_read` — с регистрами, `emu_start(begin, end)` запускает исполнение.

## Работа с памятью и регистрами

Память маппится страницами по 4 КБ (минимум `0x1000`). Частая ошибка — забыть замапить стек: тогда первая же `push`/`call` упадёт. Регистры адресуются константами вроде `UC_X86_REG_RDI`, `UC_X86_REG_RAX`, `UC_X86_REG_RIP`.

| Операция | Метод |
|---|---|
| замапить регион | `mu.mem_map(addr, size)` |
| записать код/данные | `mu.mem_write(addr, bytes)` |
| прочитать память | `mu.mem_read(addr, size)` |
| записать регистр | `mu.reg_write(REG, val)` |
| прочитать регистр | `mu.reg_read(REG)` |
| исполнить | `mu.emu_start(begin, until)` |

Для доступа к регистрам x86-64 импортируйте `from unicorn.x86_const import *`. Для ARM — `arm_const`, для ARM64 — `arm64_const`, и так далее.

## Хуки: код, память, прерывания

Хуки — сердце Unicorn. Они позволяют вмешаться в исполнение:

```python
def hook_code(mu, address, size, user_data):
    print(f"exec @ {address:#x} size={size}")

def hook_mem_write(mu, access, address, size, value, user_data):
    print(f"write {value:#x} -> {address:#x}")

def hook_intr(mu, intno, user_data):
    # перехват syscall/sysenter
    print(f"intr {intno:#x}")

mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
mu.hook_add(UC_HOOK_INTR, hook_intr)
```

`UC_HOOK_CODE` вызывается на каждую инструкцию — это трассировка. `UC_HOOK_MEM_WRITE`/`UC_HOOK_MEM_READ` ловят обращения к памяти. `UC_HOOK_INTR` перехватывает прерывания и `syscall` (в x86-64 `syscall` приходит как interrupt).

## Разобранный пример: эмуляция функции проверки

Пусть есть функция, которая принимает строку и возвращает 1 при верном пароле. Мы эмулируем её для брутфорса:

```python
from unicorn import *
from unicorn.x86_const import *
from pwn import ELF, context
context.arch = 'amd64'

elf = ELF('./chall')
CODE = 0x400000
DATA = 0x600000

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE, 0x1000)
mu.mem_map(DATA, 0x1000)
mu.mem_write(CODE, elf.read(elf.sym['check'], 0x200))
mu.mem_write(DATA + 0x100, b"guess\x00")

# аргумент — указатель на строку в rdi
mu.reg_write(UC_X86_REG_RDI, DATA + 0x100)
mu.reg_write(UC_X86_REG_RSP, DATA + 0x800)

# останавливаемся на ret
ret_addr = elf.sym['check'] + 0x200
mu.emu_start(elf.sym['check'], ret_addr)
print("result:", mu.reg_read(UC_X86_REG_RAX))
```

Перебирая кандидатов, можно найти верный пароль без запуска бинаря. Если функция вызывает внешние функции (`strcmp`, `malloc`), их нужно либо тоже замапить, либо перехватить хуком и вернуть нужное значение.

## Полный пример: обход anti-debug

Anti-debug проверки вроде `ptrace(PTRACE_TRACEME)` или чтения `/proc/self/status` под эмулятором бессмысленны — их можно перехватить и вернуть «как надо»:

```python
def hook_intr(mu, intno, user_data):
    if intno == 0x80:                       # int 0x80 (32-bit)
        rax = mu.reg_read(UC_X86_REG_EAX)
        if rax == 101:                       # ptrace
            mu.reg_write(UC_X86_REG_EAX, 0)  # вернуть успех
            # пропустить инструкцию int 0x80
```

Для x86-64 `syscall` обрабатывается через `UC_HOOK_INSN` с `UC_X86_INS_SYSCALL`:

```python
def hook_syscall(mu, user_data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    if rax == 101:                           # ptrace
        mu.reg_write(UC_X86_REG_RAX, 0)
    elif rax == 0:                           # read -> вернуть 1 байт
        mu.reg_write(UC_X86_REG_RAX, 1)
mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
```

Так вы «проходите» проверки, не реализуя реальный `ptrace`.

## Эмуляция syscall и «внешних» вызовов

Unicorn не эмулирует syscall. Стратегии:

- **Перехват и подмена возврата.** Хук на `syscall`, выставить `rax` вручную.
- **Эмуляция библиотечных вызовов.** Для `strcmp`/`memcpy` можно вызвать Python-реализацию и записать результат в память.
- **«Склейка» с реальным libc.** Иногда проще замапить нужный участок libc и эмулировать его тоже.

## Эмуляция ARM/ARM64 и смена режимов

Unicorn одинаково хорош для не-x86 архитектур. Для ARM нужно выбрать режим (`UC_MODE_ARM`, `UC_MODE_THUMB`, `UC_MODE_MCLASS`) и использовать соответствующие константы регистров. Пример для ARM64:

```python
from unicorn import *
from unicorn.arm64_const import *

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mu.mem_map(0x1000, 0x1000)
# mov x0, #0x41 ; ret
mu.mem_write(0x1000, b"\x20\x08\x80\xd2\xc0\x03\x5f\xd6")
mu.reg_write(UC_ARM64_REG_SP, 0x1800)
mu.emu_start(0x1000, 0x1000 + 8)
print(hex(mu.reg_read(UC_ARM64_REG_X0)))
# 0x41
```

Для ARM важно правильно выставить режим: код Thumb отличается от ARM, и неверный режим приведёт к мусорному исполнению. Для MIPS учитывайте `UC_MODE_MIPS32`/`UC_MODE_MIPS64` и endianness (`UC_MODE_LITTLE_ENDIAN`/`BIG_ENDIAN`). Это особенно ценно для IoT-прошивок и router-задач, где бинарь под MIPS.

## Практика: трассировка и восстановление алгоритма

Один из сильнейших приёмов — использовать Unicorn как «медленный отладчик» и восстанавливать алгоритм по трассе. Хук на код печатает адрес и инструкцию (через Capstone), хук на память — обращения. Из этого восстанавливается логика проверки:

```python
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)

def hook_code(mu, address, size, user_data):
    code = mu.mem_read(address, size)
    for insn in md.disasm(bytes(code), address):
        print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")

mu.hook_add(UC_HOOK_CODE, hook_code)
```

Если функция читает ввод и сравнивает побайтово, трасса покажет сравнения и позволит восстановить ожидаемые значения. Для больших функций ограничьте диапазон хука (`hook_add(..., begin, end)`), чтобы не захлебнуться выводом.

Ещё один практический приём — «эмуляция с конца». Если у вас есть целевое значение (например, ожидаемый хеш), можно эмулировать функцию и подбирать вход, пока выход не совпадёт. При скорости миллионов инструкций в секунду это быстрее, чем запускать бинарь целиком.

## Unicorn в связке с pwntools и шелл-кодом

Очень удобный сценарий — проверять шелл-код до того, как отправлять его на цель. Соберите шелл-код через `pwntools.asm`, замапьте его в Unicorn и исполните до первого `syscall`. Вы увидите, что оказалось в регистрах, и поймёте, корректен ли код:

```python
from pwn import *
from unicorn import *
from unicorn.x86_const import *
context.arch = 'amd64'

sc = asm(shellcraft.sh())
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x100000, 0x1000)
mu.mem_write(0x100000, sc)
mu.reg_write(UC_X86_REG_RSP, 0x101000)

stop = False
def on_syscall(mu, user_data):
    global stop
    print("syscall:", mu.reg_read(UC_X86_REG_RAX))
    stop = True
mu.hook_add(UC_HOOK_INSN, on_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
mu.emu_start(0x100000, 0x101000, count=100000)
```

Это ловит банальные ошибки — неверный регистр, забытый `execve`, неверное смещение строки. Особенно полезно для алфавитно-цифрового или кодированного шелл-кода, где ошибка кодирования видна только при исполнении.

## Частые ошибки

- **Не замапить стек.** Первый `push`/`call` даст ошибку маппинга.
- **Неверный `until`.** `emu_start` идёт до адреса `until` включительно или до исключения; убедитесь, что не ушли за пределы кода.
- **Забыть про выравнивание.** Некоторые инструкции (`movaps`) требуют выравненного `rsp`.
- **Игнорировать endianness.** Для ARM/MIPS настройте режим (`UC_MODE_ARM`/`UC_MODE_THUMB`).
- **Пытаться эмулировать весь бинарь.** Unicorn хорош для функций, а не для программ с syscall и загрузчиком.

## Что дальше / решение

- Освойте трассировку через `UC_HOOK_CODE` — это база для автоматического реверса.
- Перейдите к `pwn-qiling-emulation` — там эмуляция ОС и syscall «из коробки».
- Изучите `pwn-emulation-hooks` — продвинутые хуки и подмена состояния.
- Свяжите с `pwn-symbolic-angr` для гибридного подхода.

## Справочные таблицы

| Константа | Регистр |
|---|---|
| UC_X86_REG_RAX | rax |
| UC_X86_REG_RDI | rdi |
| UC_X86_REG_RSP | rsp |
| UC_X86_REG_RIP | rip |

| Хук | Событие |
|---|---|
| UC_HOOK_CODE | инструкция |
| UC_HOOK_MEM_READ | чтение памяти |
| UC_HOOK_MEM_WRITE | запись памяти |
| UC_HOOK_INTR | прерывание/syscall |

## Квиз

```quiz
- question: "Чем Unicorn отличается от Qiling?"
  options:
    - "Unicorn эмулирует CPU без ОС, Qiling добавляет эмуляцию ОС и syscall"
    - "Unicorn работает только с Windows"
    - "Qiling не поддерживает x86"
    - "Они идентичны"
  answer: 0
  explanation: "Unicorn — чистый CPU-эмулятор; Qiling надстраивает эмуляцию ОС."
- question: "Какой хук ловит syscall в x86-64?"
  options:
    - "UC_HOOK_CODE"
    - "UC_HOOK_INSN с UC_X86_INS_SYSCALL"
    - "UC_HOOK_MEM_READ"
    - "UC_HOOK_BLOCK"
  answer: 1
  explanation: "Syscall перехватывается инструкционным хуком на UC_X86_INS_SYSCALL."
- question: "Зачем мапить стек в Unicorn?"
  options:
    - "Чтобы ускорить эмуляцию"
    - "Иначе push/call вызовут ошибку обращения к памяти"
    - "Чтобы включить ASLR"
    - "Чтобы создать поток"
  answer: 1
  explanation: "Стек нужен для корректной работы инструкций push/call/ret."
```

## Где пригодится

- **CTF:** задачи с анти-отладкой, крипто-рутинами и «посчитай флаг».
- **Bug bounty:** эмуляция парсеров для поиска багов.
- **Пентест:** анализ чужой архитектуры без реального устройства.
- **Работа:** malware analysis и автоматизация реверса.
