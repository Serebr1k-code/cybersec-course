---
id: reversing-unicorn-emulation
title: "Эмуляция: Unicorn и Qiling для деобфускации"
category: reversing
parent: reversing-deobfuscation
difficulty: hard
order: 1
tags: [reversing, unicorn, qiling, emulation, deobfuscation, unpacking]
prerequisites: [reversing-deobfuscation, reversing-dynamic-debug]
useful_for:
  - "CTF Reversing"
  - "Malware analysis"
  - "Automated deobfuscation"
estimated_minutes: 60
summary: "Фрагментная и системная эмуляция: Unicorn для функций, Qiling для процессов, распаковка и обход анти-анализа."
---
**Эмуляция** позволяет исполнить фрагмент кода (или целый процесс) без реальной машины: Unicorn эмулирует инструкции CPU, Qiling добавляет уровень ОС (syscalls, файловая система, загрузка ELF/PE). Это ключевой инструмент деобфускации: можно выполнить расшифровку/декодирование и снять результат, полностью обходя анти-анализ, отладчик-детект и необходимость реальной среды. Эмуляция особенно полезна против SMC, строковой обфускации и виртуализации. Этот урок — практика Unicorn и Qiling от базового API до сквозной распаковки.

## Зачем эмуляция, а не отладчик

Отладчик исполняет код на реальном CPU: быстро, но с реальным окружением. Эмулятор исполняет код «виртуально»:

| Критерий | Отладчик | Эмулятор (Unicorn/Qiling) |
|----------|----------|---------------------------|
| Анти-отладка | ломает/детектится | не видит «настоящей» среды |
| Реальные syscalls | да | эмулируются (Qiling) |
| Изоляция | слабая (образец может вредить) | полная (ничего не исполняется) |
| Скорость | быстрее | медленнее |
| Автоматизация | сложнее | идеальна (Python API) |
| Фрагментность | сложно | легко (одна функция) |

Для **фрагмента** логики (декодер строк, дешифратор конфига) эмуляция незаменима: вы загружаете только нужные байты и не запускаете вредоносный код целиком.

## Unicorn: API и ключевые концепции

Unicorn — лёгкий multi-arch движок (x86, ARM, MIPS, SPARC, RISC-V). Базовый скелет:

```python
from unicorn import *
from unicorn.x86_const import *

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x400000, 0x10000)          # маппинг памяти (обязательно)
mu.mem_write(0x400000, code)           # загрузка кода
mu.reg_write(UC_X86_REG_RSP, 0x410000) # стек
mu.reg_write(UC_X86_REG_RDI, 0x101000) # 1-й аргумент (SysV)
# Колбэки
mu.hook_add(UC_HOOK_CODE, lambda mu, addr, size, user: print(hex(addr)))
mu.hook_add(UC_HOOK_MEM_WRITE, mem_write_cb)
mu.emu_start(0x400000, 0x400000 + len(code), timeout=10*1000*1000)
print(mu.mem_read(0x101000, 0x20))
```

Ключевые возможности:

- `mem_map`/`mem_write`/`mem_read` — управление памятью.
- `reg_write`/`reg_read` — регистры (имена через `unicorn.x86_const`).
- `emu_start(begin, until)` — исполнение до адреса.
- Хуки: `UC_HOOK_CODE` (каждая инструкция), `UC_HOOK_MEM_READ/WRITE`, `UC_HOOK_MEM_INVALID`, `UC_HOOK_INTR`.
- `emu_stop()` из колбэка — остановка по условию.

Обязательно маппите **и код, и стек, и любую память**, к которой обращается код — иначе `UC_ERR_READ_UNMAPPED`. Стек обычно размещают выше кода.

## Qiling: системная эмуляция

Qiling надстраивается над Unicorn и добавляет эмуляцию ОС: загрузку ELF/PE/Mach-O, syscalls, виртуальную ФС, реестр (Windows).

```python
from qiling import Qiling
from qiling.const import QL_VERBOSE

ql = Qiling(['./binary'], rootfs='./rootfs', verbose=QL_VERBOSE.DEFAULT)
ql.run()

# Хуки по адресу, по имени API, на syscall
@ql.hook_address
def on_call(ql, addr):
    print('call', hex(addr))

def on_write(ql, fd, buf, count):
    print('write:', ql.mem.read(buf, count))
ql.os.set_syscall('write', on_write)

# Перехват Windows API
@ql.set_api("CreateFileW")
def hook_CreateFileW(ql, address, params):
    print('CreateFileW', params['lpFileName'])
```

Qiling даёт **пропуск syscalls** (можно вернуть фиктивный результат), эмуляцию файлов/реестра и API — удобно для malware и прошивок. Есть режимы user-mode и full-system (с ядром).

## Speakeasy и другие эмуляторы

| Инструмент | Уровень | Применение |
|------------|---------|------------|
| Unicorn | CPU | фрагменты, дешифраторы |
| Qiling | OS (ELF/PE/Mach-O) | malware, прошивки |
| Speakeasy (FireEye) | Windows API | эмуляция malware без Windows |
| Miasm | IR + эмуляция | кастомная эмуляция |
| angr | OS + символьное | symbolic execution |
| qemu-user | полный user-mode | запуск чужой архитектуры |
| Frida | живой процесс | динамика на реальном CPU |

## Деобфускация через эмуляцию

Основные сценарии:

- **Фрагментная эмуляция**: выполнить функцию-декодер и снять результат (строки, конфиг, буфер).
- **Пропуск анти-анализа**: эмулятор не «настоящая» среда; проверки можно игнорировать или подменить.
- **Автоматический обход**: hook'ать проверки (`IsDebuggerPresent`, timing) и возвращать «правильные» значения.
- **Распаковка**: эмулировать стаб, поймать запись в код, снять дамп.
- **Расшифровка строк**: вызвать декодер для каждой зашифрованной строки — массово и автоматически.

## Разобранный пример 1: расшифровка строк

**Шаг 1. Найти функцию-декодер.** В Ghidra определите адрес `decrypt` и её сигнатуру (вход — указатель на зашифрованную строку, выход — расшифрованная in-place).

```python
from unicorn import *
from unicorn.x86_const import *

CODE = open('decrypt.bin','rb').read()   # байты функции-декодера

def decrypt(enc: bytes) -> bytes:
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(0x100000, 0x10000)
    mu.mem_write(0x100000, CODE)
    mu.mem_write(0x101000, enc)
    mu.reg_write(UC_X86_REG_RDI, 0x101000)      # 1-й аргумент — указатель
    mu.reg_write(UC_X86_REG_RSI, len(enc))      # 2-й аргумент — длина
    mu.reg_write(UC_X86_REG_RSP, 0x102000)
    mu.emu_start(0x100000, 0x100000 + len(CODE), timeout=2*1000*1000)
    return mu.mem_read(0x101000, len(enc))

for s in encrypted_strings:
    print(decrypt(s))
```

Так вы восстанавливаете все строки, не запуская образец. Если декодер вызывает `malloc`/`memcpy` — либо добавьте их реализацию-заглушку через `UC_HOOK_CODE` на их адрес, либо перейдите на Qiling.

## Разобранный пример 2: распаковка через эмуляцию стаба

```python
mu = Uc(UC_ARCH_X86, UC_MODE_64)
BASE = 0x400000
mu.mem_map(BASE, 0x200000)
mu.mem_write(BASE, open('stage1.bin','rb').read())
mu.reg_write(UC_X86_REG_RSP, BASE + 0x1F0000)

writes = []
def on_write(mu, access, addr, size, value, user):
    writes.append((addr, size))
mu.hook_add(UC_HOOK_MEM_WRITE, on_write)

# Останавливаемся, когда управление уходит в расшифрованный регион
def on_code(mu, addr, size, user):
    if addr not in original_range:
        mu.emu_stop()
mu.hook_add(UC_HOOK_CODE, on_code)

mu.emu_start(BASE, BASE + 0x10000, timeout=30*1000*1000)
dump = mu.mem_read(BASE, 0x10000)          # расшифрованный код
open('unpacked.bin','wb').write(bytes(dump))
```

Дальше `unpacked.bin` дизассемблируется как обычный код (см. `reversing-self-modifying`).

## Обход анти-анализа

- **Проверки среды** (`IsDebuggerPresent`, `ptrace`, проверки `cpuid`/таймингов) в эмуляторе не срабатывают — вы сами управляете результатами.
- **Хуки на «вредные» вызовы**: вместо реального `CreateFile` верните фиктивный хендл; вместо `connect` — успех.
- **Пропуск бесконечных циклов**: ограничивайте `timeout` и `count`, ставьте `emu_stop` по адресу.
- **Маскировка**: эмулируйте на уровне IR (Miasm), если Unicorn спотыкается об экзотические инструкции.

## Отладка эмуляции: диагностика проблем

```text
UC_ERR_READ_UNMAPPED / WRITE_UNMAPPED -> не замаплена память (добавьте mem_map)
UC_ERR_FETCH_UNMAPPED                 -> код вне замапленного региона
UC_ERR_INSN_INVALID                   -> неверный режим/архитектура
emu_start сразу падает                -> не задан стек/регистры, или до-адрес неверный
"висит"                               -> бесконечный цикл: timeout/count или emu_stop
```

Полезно логировать инструкции (`UC_HOOK_CODE`) и сравнивать с трассой отладчика, чтобы найти расхождение (например, необработанный syscall).

## Практические рецепты и справочник

| Задача | Инструмент | Приём |
|--------|-----------|-------|
| Расшифровать строку | Unicorn | загрузить декодер, задать RDI/RSI, снять буфер |
| Распаковать стаб | Unicorn | hook на `UC_HOOK_MEM_WRITE` в код + `emu_stop` |
| Обойти `IsDebuggerPresent` | Unicorn/Qiling | hook на API, вернуть 0 |
| Запустить ELF без ОС | Qiling | `Qiling(['./bin'], rootfs=...)` |
| Перехватить syscall | Qiling | `ql.os.set_syscall('open', cb)` |
| Эмулировать Windows API | Speakeasy | загрузка PE, отчёт о поведении |
| Найти базовый адрес | Unicorn | `mu.mem_read` + сравнение с файлом |
| Ограничить исполнение | Unicorn | `timeout`, `count`, `emu_stop` |

Частые архитектурные константы: `UC_ARCH_X86/UC_MODE_64`, `UC_ARCH_ARM/UC_MODE_THUMB`, `UC_ARCH_MIPS/UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN`, `UC_ARCH_ARM64`. Для SysV x86-64 аргументы: RDI, RSI, RDX, RCX, R8, R9; возврат — RAX. Для Windows x64: RCX, RDX, R8, R9. Для ARM: R0–R3 (ARM32) или X0–X7 (AArch64).

## Когда эмуляция, а когда отладчик

- **Эмуляция** — когда нужна изоляция, автоматизация, обход анти-анализа, или код нельзя запускать (malware, прошивка под чужую ISA).
- **Отладчик** — когда нужна скорость, реальное окружение, сложные syscalls/драйверы, или нужно наблюдать реальное поведение.
- **Комбинирование** — эмуляция для деобфускации «холодного» кода, отладчик для «горячего» (после расшифровки).

## Производительность и масштабирование

Эмуляция медленнее реального исполнения в десятки раз, поэтому:

- **Эмулируйте только нужный фрагмент** (функцию-декодер), а не весь процесс.
- **Останавливайтесь рано**: `emu_start(begin, until)` и `emu_stop()` из колбэка по достижении результата.
- **Кешируйте** результат: для тысяч строк создавайте эмулятор один раз и сбрасывайте память, а не `Uc()` заново.
- **Ограничивайте** `timeout`/`count`, чтобы бесконечный цикл не съел CPU.
- **Параллелизация**: для массовых задач запускайте несколько процессов эмуляции.

## Частые ошибки

- **Не замапить нужную память/стек.** Эмуляция падает с `UNMAPPED`; маппите код, стек и все буферы.
- **Не установить регистры.** Аргументы и указатели нужно задать до `emu_start` (SysV: RDI/RSI/RDX).
- **Игнорировать syscalls.** Unicorn не эмулирует ОС — для syscalls используйте Qiling/Speakeasy.
- **Эмулировать весь процесс.** Дорого и хрупко; эмулируйте фрагмент (функцию-декодер).
- **Не обработать исключения/хуки.** Без колбэков не понять, где сбой.
- **Забыть про архитектуру/режим.** Укажите правильные `UC_ARCH`/`UC_MODE` (x86-64, ARM Thumb).
- **Не учесть вызовы libc.** `malloc`/`memcpy` внутри декодера нужно эмулировать или перехватывать.

## Что делать дальше / решение

1. Определите цель: расшифровка строк, распаковка стаба, деобфускация конфига.
2. Выберите уровень: Unicorn (фрагмент, без ОС) или Qiling (нужны syscalls/ФС/API).
3. Замапьте память и стек, задайте регистры-аргументы.
4. Добавьте хуки: логирование инструкций, перехват записи в код, подмена проверок.
5. Снимите результат (расшифрованный буфер/дамп кода) и переходите к анализу.
6. Для массовых задач (тысячи строк) оберните эмуляцию в цикл — это быстрее отладчика.

## Квиз

```quiz
- question: "Чем Unicorn отличается от Qiling?"
  options:
    - "Unicorn — CPU-эмуляция; Qiling добавляет ОС/syscalls"
    - "Ничем"
    - "Qiling только для ARM"
    - "Unicorn — отладчик"
  answer: 0
  explanation: "Qiling надстраивает системную эмуляцию над Unicorn."
- question: "Что нужно задать перед эмуляцией функции в Unicorn?"
  options:
    - "Регистры (аргументы/стек) и память"
    - "Только строки"
    - "Только секции"
    - "Только GOT"
  answer: 0
  explanation: "Без регистров/стека эмуляция упадёт или даст неверный результат."
- question: "Для чего эмуляция полезна при деобфускации?"
  options:
    - "Выполнить декодер/распаковку без реальной машины"
    - "Ускорить сеть"
    - "Сканировать порты"
    - "Собрать бинарь"
  answer: 0
  explanation: "Эмулятор исполняет расшифровку и снимает результат."
- question: "Как обойти анти-анализ через эмуляцию?"
  options:
    - "Пропустить/подменить проверки в эмуляторе"
    - "Отключить ASLR"
    - "Снять canary"
    - "Расширить tcache"
  answer: 0
  explanation: "Хуки позволяют игнорировать проверки среды."
- question: "Какой инструмент эмулирует Windows API для malware?"
  options:
    - "Speakeasy"
    - "Qiling только"
    - "nm"
    - "objdump"
  answer: 0
  explanation: "Speakeasy эмулирует Windows API для анализа образцов."
```

## Где пригодится

- **CTF:** Reversing — деобфускация.
- **Malware analysis:** распаковка/расшифровка.
- **Automated deobfuscation:** массовый анализ.
- **Работа:** malware research.
