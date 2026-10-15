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
lab:
  kind: shell
  title: "Практика: эмуляция блоба (Unicorn)"
  toolset: [core, hex]
  workdir: /home/student/task
  files: [task.md, blob.bin, emu.log]
  check: "grep -q 'eax=0x26' answer.txt"
  hints:
    - "`emu.log` содержит итоговый EAX после emu_start."
    - "Код: `mov eax,5; imul eax,eax,7; add eax,3`."
    - "5*7+3 = 38 = 0x26."
---

## Вопрос, с которого всё начинается

В бинаре есть функция `check`, которая принимает строку и возвращает `1`, если пароль верный. Запускать бинарь целиком неудобно: он читает ввод, что-то печатает, делает `exit`. А хочется просто **вызвать `check` миллион раз с разными строками** и найти ту, что даёт `1`.

Обычный запуск это не позволяет — нужен контроль над CPU. Его даёт **Unicorn**: библиотека, которая исполняет машинный код в программной модели процессора, без операционной системы.

## Наш пример: функция проверки пароля

Пусть у нас есть бинарь `chall`, внутри — функция `check(const char* s)`:

```text
0x401126 <check>:
  401126: push rbp
  401127: mov  rbp, rsp
  40112a: ...            # побайтовое сравнение с зашитым паролем
  401140: mov  eax, 1     # вернуть 1 при совпадении
  401145: ret
```

Мы хотим вызывать её из Python. Установим Unicorn:

```bash
$ pip install unicorn capstone
$ python3 -c "import unicorn; print(unicorn.__version__)"
2.0.1
```

## Шаг 1. Минимальный запуск: «голый CPU»

Сначала простейшее — исполнить одну инструкцию `mov rax, 42`:

```python
from unicorn import *
from unicorn.x86_const import *

CODE, STACK = 0x1000000, 0x2000000
mu = Uc(UC_ARCH_X86, UC_MODE_64)   # эмулятор x86-64
mu.mem_map(CODE, 0x1000)           # страница памяти под код
mu.mem_map(STACK, 0x1000)          # страница под стек
mu.mem_write(CODE, b"\x48\xc7\xc0\x2a\x00\x00\x00")  # mov rax, 42
mu.reg_write(UC_X86_REG_RSP, STACK + 0x800)
mu.emu_start(CODE, CODE + 7)
print(hex(mu.reg_read(UC_X86_REG_RAX)))
```

```text
0x2a
```

Разберём ключевые вызовы. `Uc(arch, mode)` создаёт эмулятор для конкретной архитектуры. `mem_map(addr, size)` выделяет регион памяти — **минимум `0x1000`**, одна страница. `mem_write` кладёт туда байты, `reg_write`/`reg_read` работают с регистрами (их имена — константы вида `UC_X86_REG_RAX`), а `emu_start(begin, until)` исполняет код от `begin` до `until`.

Важно: **Unicorn не эмулирует ОС**. Нет загрузчика, нет syscall, нет файлов. Всё, что есть, — память и регистры. Это ограничение, но одновременно и сила: мы полностью контролируем окружение.

## Шаг 2. Обязательно замапить стек

Самая частая ошибка новичка — забыть про стек. Тогда первая же `push` или `call` упадёт с ошибкой доступа к памяти. Поэтому рядом с кодом всегда мапят отдельный регион и выставляют `rsp` в его середину:

```python
mu.mem_map(STACK, 0x1000)
mu.reg_write(UC_X86_REG_RSP, STACK + 0x800)
```

## Шаг 3. Вызываем функцию check

Теперь по-настоящему: скопируем код функции `check` из ELF и вызовем её с аргументом. По соглашению вызовов x86-64 первый аргумент функции лежит в `rdi` — это тот же факт, что мы использовали в ROP.

```python
from unicorn import *
from unicorn.x86_const import *
from pwn import ELF, context
context.arch = 'amd64'

elf = ELF('./chall')
CODE, DATA = 0x400000, 0x600000

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(CODE, 0x1000)
mu.mem_map(DATA, 0x1000)
mu.mem_write(CODE, elf.read(elf.sym['check'], 0x200))   # код функции
mu.mem_write(DATA + 0x100, b"guess\x00")                # строка-аргумент

mu.reg_write(UC_X86_REG_RDI, DATA + 0x100)   # rdi -> указатель на строку
mu.reg_write(UC_X86_REG_RSP, DATA + 0x800)

mu.emu_start(elf.sym['check'], elf.sym['check'] + 0x200)
print("result:", mu.reg_read(UC_X86_REG_RAX))
```

Функция отработала, и мы читаем её результат из `rax`. Перебирая кандидатов в цикле, можно найти верный пароль — без единого запуска бинаря.

## Шаг 4. Хуки: перехватываем всё

Проблема: если `check` внутри вызывает `strcmp` или `malloc`, они обратятся к памяти, которой у нас нет, и эмуляция упадёт. Решение — **хуки**: функции-обработчики, которые Unicorn вызывает в нужный момент.

```python
def hook_code(mu, address, size, user_data):
    print(f"exec @ {address:#x} size={size}")

def hook_mem_write(mu, access, address, size, value, user_data):
    print(f"write {value:#x} -> {address:#x}")

mu.hook_add(UC_HOOK_CODE, hook_code)           # на каждую инструкцию
mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write) # на запись в память
```

`UC_HOOK_CODE` вызывается на каждую инструкцию — это трассировка. `UC_HOOK_MEM_READ`/`WRITE` ловят обращения к памяти. С их помощью можно подменять состояние прямо в процессе: например, когда функция дойдёт до вызова `strcmp`, вернуть нужное значение.

## Шаг 5. Обходим anti-debug

Анти-отладочные проверки (`ptrace`, чтение `/proc/self/status`, `rdtsc`) под эмулятором бессмысленны — их можно перехватить. В x86-64 системный вызов приходит как инструкция `syscall`, и её ловит инструкционный хук:

```python
def hook_syscall(mu, user_data):
    rax = mu.reg_read(UC_X86_REG_RAX)
    if rax == 101:                        # ptrace
        mu.reg_write(UC_X86_REG_RAX, 0)   # «трассировки нет»
    elif rax == 0:                        # read -> будто прочитали 1 байт
        mu.reg_write(UC_X86_REG_RAX, 1)

mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
```

Так мы «проходим» проверки, вообще не реализуя настоящий `ptrace`.

## Шаг 6. Проверяем shellcode перед отправкой

Отличный сценарий — прогнать shellcode до первого `syscall` и увидеть, что в регистрах. Соберём его через pwntools, замапим и остановим на `syscall`:

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

def on_syscall(mu, user_data):
    print("syscall:", mu.reg_read(UC_X86_REG_RAX))   # 59 = execve
mu.hook_add(UC_HOOK_INSN, on_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
mu.emu_start(0x100000, 0x101000, count=100000)
```

Это ловит банальные ошибки — забытый `execve`, неверный регистр, сбитое смещение строки. Особенно полезно для закодированного shellcode, где ошибка видна только при исполнении. Такой «прогон до syscall» стоит секунды и спасает от долгой отладки на реальной цели.

## Другие архитектуры

Unicorn одинаково работает с ARM, ARM64, MIPS, PPC. Меняется только архитектура и константы регистров. Это особенно ценно для IoT: бинарь прошивки под MIPS исполняется прямо на x86-хосте, без эмуляции всей ОС.

```python
from unicorn.arm64_const import *
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mu.mem_map(0x1000, 0x1000)
mu.mem_write(0x1000, b"\x20\x08\x80\xd2\xc0\x03\x5f\xd6")  # mov x0,#0x41; ret
mu.reg_write(UC_ARM64_REG_SP, 0x1800)
mu.emu_start(0x1000, 0x1008)
print(hex(mu.reg_read(UC_ARM64_REG_X0)))
```

```text
0x41
```

Для ARM важно выбрать верный режим (`UC_MODE_ARM` против `UC_MODE_THUMB`), для MIPS — endianness. Это бесценно для IoT-прошивок под MIPS.

## На что смотреть дальше

- **Не замапил стек** — первая же `push`/`call` упадёт. Мапь стек всегда.
- **Неверный `until`** — убедись, что не выходишь за пределы замапленного кода.
- **Выравнивание** — некоторые инструкции (`movaps`) требуют выровненного `rsp`.
- **Endianness и режим** — для ARM/MIPS настрой правильно, иначе исполнится мусор.
- **Не пытайся эмулировать весь бинарь** — Unicorn хорош для функций; для целой программы бери Qiling.

## Что мы теперь знаем

- Unicorn эмулирует «голый CPU»: только память и регистры, без ОС.
- `mem_map`/`mem_write`/`reg_write`/`emu_start` — базовый API.
- Стек мапить обязательно, иначе `push`/`call` падают.
- Хуки (`UC_HOOK_CODE`, `_MEM_*`, `UC_HOOK_INSN` для syscall) позволяют вмешаться.
- Эмуляция вызова функции даёт брутфорс и обход anti-debug.

## Брутфорс под Unicorn: ускоряем перебор

Одно из главных применений Unicorn — быстрый перебор, когда проверка зависит от нескольких байт ввода. Вместо запуска процесса на каждую догадку эмулируем функцию внутри процесса-скрипта: это в сотни раз быстрее.

```python
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
from unicorn.x86_const import UC_X86_REG_RDI, UC_X86_REG_RAX

CODE_BASE, STACK = 0x1000000, 0x2000000
CODE = bytes.fromhex("554889e5...c3")     # тело check()
uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(CODE_BASE, 0x1000)
uc.mem_map(STACK, 0x1000)
uc.mem_write(CODE_BASE, CODE)

def check(buf):
    uc.reg_write(UC_X86_REG_RSP, STACK + 0x800)
    uc.mem_map(0x3000000, 0x1000)
    uc.mem_write(0x3000000, buf)
    uc.reg_write(UC_X86_REG_RDI, 0x3000000)
    try:
        uc.emu_start(CODE_BASE, CODE_BASE + len(CODE), timeout=100000)
    except UcError:
        return False
    return uc.reg_read(UC_X86_REG_RAX) == 1

# побайтовый перебор: на каждом шаге фиксируем найденный префикс
flag = b""
for i in range(16):
    for c in range(256):
        if check(flag + bytes([c])):
            flag += bytes([c]); break
print(flag)
```

Ключевой приём — **сохранять и восстанавливать контекст**. Если проверка «дорогая», можно прогнать её один раз до интересующей точки и затем `context_save`/`context_restore`:

```python
uc.emu_start(CODE_BASE, CHECKPOINT)      # доходим до места проверки
saved = uc.context_save()
for c in range(256):
    uc.mem_write(INPUT, bytes([c]))
    uc.context_restore(saved)            # мгновенный откат
    uc.emu_start(CHECKPOINT, CODE_BASE + len(CODE))
```

Это даёт возможность перебирать миллионы вариантов в секунду — то, что на реальном процессе заняло бы часы.

## Хуки: тонкая настройка

Хуки Unicorn позволяют перехватывать события без правки кода и часто заменяют целые сценарии отладки.

| Хук | Событие | Типичное применение |
|---|---|---|
| `UC_HOOK_CODE` | перед каждой инструкцией | трассировка, пропуск `ptrace`/`rdtsc` |
| `UC_HOOK_MEM_READ` | чтение памяти | перехват доступа к буферу ввода |
| `UC_HOOK_MEM_WRITE` | запись памяти | детект самодекодирующегося кода |
| `UC_HOOK_MEM_INVALID` | доступ к незамапленной памяти | «ленивое» замапливание по требованию |
| `UC_HOOK_INTR` | инструкция `syscall`/`int` | эмуляция нужных системных вызовов |

Например, `UC_HOOK_MEM_INVALID` с колбэком, который на лету делает `mem_map` нужной страницы, снимает необходимость заранее знать всю карту памяти бинарника.

## Unicorn против альтернатив

| Инструмент | Сильная сторона | Слабость |
|---|---|---|
| Unicorn | скорость, точный контроль, встраивается в скрипт | нет ОС и syscalls «из коробки» |
| Qiling | эмуляция ОС (syscalls, ELF) поверх Unicorn | медленнее, сложнее настройка |
| angr | символьное исполнение, поиск пути | тяжелее, не для простого брутфорса |
| GDB + QEMU | полноценная отладка | медленно для массового перебора |

Правило выбора: нужен **быстрый массовый перебор** одной функции — Unicorn; нужна **эмуляция целого бинарника с syscalls** — Qiling; нужно **решить задачу «найти вход, приводящий к цели»** без перебора — angr. Часто их комбинируют: Unicorn для разведки конкретной функции, angr для поиска пути.

## Краевые случаи

- **Незамапленный стек.** Первое, что забывают — `mem_map` под стек; без него эмуляция падает на первом `push`.
- **Отсутствующие внешние функции.** Вызовы `printf`/`memcmp` надо либо эмулировать хуком, либо подменять своей реализацией через `UC_HOOK_CODE`.
- **Проверка на анти-эмуляцию.** Некоторые бинарники считают `rdtsc` и падают при «слишком быстром» времени; подменяйте значение через хук регистра.
- **Конечный адрес `emu_start`.** Если не указать `until`, эмуляция идёт до `ret` на пустом стеке и падает; ставьте точку останова по адресу.
- **Endianness.** На ARM/MIPS байты в памяти читаются иначе; при записи строк учитывайте порядок.

## Квиз

Проверь себя.

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
- question: "Где лежит первый аргумент функции при вызове в x86-64?"
  options:
    - "В rdi"
    - "В rax"
    - "В rsp"
    - "В rbx"
  answer: 0
  explanation: "Первый аргумент функции — в rdi, поэтому его и выставляют перед эмуляцией."
- question: "Почему Unicorn не подходит для запуска целого бинаря?"
  options:
    - "Он не эмулирует загрузчик, syscall и файловую систему"
    - "Он слишком медленный"
    - "Он только для ARM"
    - "Он требует Windows"
  answer: 0
  explanation: "Для целой программы нужна эмуляция ОС — это уже Qiling."
```

## Куда дальше

В `pwn-qiling-emulation` мы добавим к «голому CPU» эмуляцию операционной системы — загрузчик, `rootfs` и syscall, — чтобы запускать бинарь целиком, в том числе чужой архитектуры. А пока главное: **Unicorn исполняет машинный код без ОС, и этого достаточно, чтобы вызвать одну функцию, обойти anti-debug и проверить shellcode.**

## Где пригодится

- **CTF:** задачи с анти-отладкой, крипто-рутинами и «посчитай флаг».
- **Bug bounty:** эмуляция парсеров для поиска багов.
- **Пентест:** анализ чужой архитектуры без реального устройства.
- **Работа:** malware analysis и автоматизация реверса.
