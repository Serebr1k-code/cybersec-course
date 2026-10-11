---
id: reversing-shellcode-analysis
title: "Анализ и реверс shellcode"
category: reversing
parent: reversing-static-targets
difficulty: hard
order: 3
tags: [reversing, shellcode, malware, decoder, stager, metasploit]
prerequisites: [reversing-static-analysis, reversing-asm]
useful_for:
  - "CTF Reversing / Pwn"
  - "Malware analysis"
  - "Exploit triage"
estimated_minutes: 55
summary: "Разбор shellcode: позиционно-независимый код, декодеры, API-резолвинг, анализ стейджеров и статический разбор blob."
---
Shellcode — позиционно-независимый машинный код, используемый в эксплойтах (pwn) и как первый этап malware (**stager**). Он не имеет заголовка, секций и абсолютных адресов: это «сырой» blob байтов, который должен исполниться, где бы он ни оказался. Его анализ нужен для triage эксплойтов, разбора полезной нагрузки и понимания C2. Shellcode часто закодирован (XOR, alpha) и резолвит API вручную. Этот урок — полный статический и динамический разбор shellcode.

## Особенности shellcode

- **Позиционная независимость.** Нет абсолютных адресов; адрес кода получают через `call/pop` или `lea reg, [rip+...]`.
- **Нет заголовка/секций.** Это blob байтов; дизассемблеру нужно указать архитектуру и точку начала.
- **API-резолвинг.** `LoadLibrary`/`GetProcAddress` или обход PEB (`fs:[0x30]` → `Ldr` → модули) для поиска функций без импортов.
- **Кодирование.** XOR-стаб, alphanumeric (только «печатные» байты), самораспаковка — чтобы обойти фильтры и `strcpy`-ограничения.
- **Stager.** Короткий код, который скачивает/расшифровывает основной payload (второй этап) и передаёт ему управление.

## Статический разбор: дизассемблирование blob

```bash
# Дизассемблировать сырой blob (64-бит)
ndisasm -b64 shellcode.bin
# или через objdump
objdump -D -b binary -m i386:x86-64 shellcode.bin
```

Скриптом через Capstone (рекурсивное следование, можно обходить только достижимые инструкции):

```python
from capstone import *
code = open('sc.bin','rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(code, 0):
    print('%x: %s %s' % (i.address, i.mnemonic, i.op_str))
```

Начните с начала blob, но помните: shellcode может начинаться с данных или прыжка — ищите реальную точку входа (например, `jmp` вперёд или `call`).

## Декодирование обфускации

```python
# XOR-декодер: найти ключ и распаковать
data = open('sc.bin','rb').read()
decoded = bytes(b ^ 0xAA for b in data)     # предположим, ключ 0xAA
open('decoded.bin','wb').write(decoded)
```

Ключ обычно находится рядом с циклом декодирования в дизасме (константа, загружаемая в регистр). Alpha-кодирование (alphanumeric) декодируется сложнее — нужен эмулятор (см. ниже), который выполнит стаб и выдаст расшифрованный буфер.

## API-резолвинг

- **PEB walk.** Shellcode идёт по `PEB->Ldr->InMemoryOrderModuleList`, находит `kernel32.dll`, затем `GetProcAddress` и нужные функции. В дизасме это доступ к `fs:[0x30]` (x64) / `fs:[0x30]` через `gs` в x86.
- **Хеширование имён.** Вместо строк сравнивается хеш имени функции (часто `ROR13` + сумма). Восстановление: посчитать хеши известных функций и сопоставить.
- **Анализ.** Восстановите таблицу хешей → имён (скрипт на Python) — это раскроет реальные действия (connect, recv, exec).

```python
# ROR13-хеш имени (для сопоставления)
def ror13(s):
    h = 0
    for c in s.encode():
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + c) & 0xFFFFFFFF
    return h
```

## Эмуляция shellcode

```python
from unicorn import *
from unicorn.x86_const import *
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x1000, 0x10000)
mu.mem_write(0x1000, code)
mu.reg_write(UC_X86_REG_RSP, 0x11000)
mu.hook_add(UC_HOOK_CODE, lambda mu,a,s,u: print(hex(a)))
mu.emu_start(0x1000, 0)
```

Эмуляция безопасно исполняет shellcode и логирует поведение/расшифровку. Для API-вызовов (Windows) используйте **Speakeasy**, который эмулирует `LoadLibrary`/`GetProcAddress` и логирует вызовы — идеально для stager'ов.

## Stager'ы и многоэтапные payload'ы

```text
Этап 1 (stager): декодирует/скачивает второй этап.
Этап 2 (payload): реальная нагрузка (shell, beacon, miner).
```

- **Reverse stager** — `connect` обратно на C2, `recv`, `exec` в память.
- **Download stager** — `URLDownloadToFile`/`WinINet`/`WinHTTP`, затем запуск.
- **Многослойность** — бывает 2–3 этапа; каждый надо разобрать отдельно.

## Разобранный пример: Metasploit stager end-to-end

```text
1) Статически: ndisasm -> видим цикл декодирования (XOR-стаб).
2) Извлекаем XOR-ключ и длину.
3) Декодируем -> второй этап.
4) Эмулируем/анализируем второй этап: connect/recv/exec.
```

```bash
# Шаг 1: дизасм
ndisasm -b64 stager.bin | head -40
# Ищем: xor al, imm / mov dl, imm / loop -> декодер

# Шаг 2-3: декодирование (ключ найден в дизасме)
python3 - <<'EOF'
data = open('stager.bin','rb').read()
key = 0xAA
off = 0x20          # смещение закодированной части
decoded = bytes(b ^ key for b in data[off:])
open('stage2.bin','wb').write(decoded)
EOF

# Шаг 4: анализ второго этапа (эмуляция)
python3 - <<'EOF'
from unicorn import *; from unicorn.x86_const import *
code = open('stage2.bin','rb').read()
mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x1000, 0x10000); mu.mem_write(0x1000, code)
mu.reg_write(UC_X86_REG_RSP, 0x11000)
seen = set()
def hook(mu, a, s, u):
    seen.add(a)
    if len(seen) > 5000: mu.emu_stop()
mu.hook_add(UC_HOOK_CODE, hook)
try: mu.emu_start(0x1000, 0, timeout=5*1000*1000)
except UcError as e: print('stop', e)
print('instrs executed:', len(seen))
EOF
```

Второй этап обычно содержит `call` на резолвинг (`GetProcAddress`), `connect`/`send`/`recv` — то есть это reverse shell.

## Инструменты

| Инструмент | Назначение |
|------------|------------|
| `ndisasm`/`objdump -b binary` | быстрый дизасм blob |
| Capstone (Python) | программируемый дизасм |
| `scdbg` | эмуляция shellcode с логом API (Windows) |
| Speakeasy | эмуляция Windows API |
| Unicorn/Qiling | эмуляция произвольного кода |
| `shellcode2exe` | обернуть blob в exe для отладки |
| x64dbg | отладка (в обёртке) |

## Обёртка blob в исполняемый файл и отладка

Чтобы отлаживать shellcode удобнее, его «заворачивают» в exe-загрузчик (stub), который выделяет RWX-память, копирует blob и передаёт управление:

```c
// stub.c: загрузчик shellcode для отладки в x64dbg
#include <windows.h>
int main(void) {
    unsigned char sc[] = { /* байты shellcode */ };
    void *mem = VirtualAlloc(0, sizeof(sc), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(mem, sc, sizeof(sc));
    ((void(*)())mem)();
    return 0;
}
```

```bash
# или готовым инструментом
shellcode2exe shellcode.bin      # оборачивает blob в exe
```

После этого можно ставить breakpoints в x64dbg и пошагово идти. **Внимание:** запуск shellcode даже в обёртке опасен — делайте это только в изолированной VM без сети.

## Типичные семейства shellcode

- **Reverse shell.** `connect` на C2, дублирование сокета на stdin/stdout/stderr, `execve("/bin/sh")` (Linux) или `CreateProcess` (Windows).
- **Bind shell.** `bind`+`listen`+`accept`, затем shell.
- **Download-and-execute.** Скачивание второго этапа и исполнение в памяти (fileless).
- **Meterpreter stager.** `recv` зашифрованного payload, расшифровка, прыжок в него.
- **Cobalt Strike stager.** Иногда с API-хешами и обфускацией; требует восстановления хешей.
- **Alpha/printable shellcode.** Ограничен печатными символами — обходит фильтры; декодируется эмуляцией.

Распознавание семейства по структуре (резолвинг → connect/recv → exec) ускоряет triage.

## Безопасность

- **Никогда не запускайте shellcode напрямую.** Только эмуляция (Unicorn/Speakeasy/scdbg) или изолированная VM без сети.
- **Не подключайте сеть** — stager может установить обратное соединение с C2.
- **Хешируйте** образцы (SHA-256) и работайте с копиями.

## Частые ошибки

- **Дизассемблировать с неверного смещения.** Shellcode может начинаться с данных/прыжка.
- **Игнорировать кодирование.** Сначала снять слой XOR/alpha — иначе виден «мусор».
- **Путать 32/64-бит.** ISA влияет на дизассемблер и API-резолвинг (`fs` vs `gs`).
- **Запускать shellcode без эмуляции.** Опасно; используйте Unicorn/Speakeasy.
- **Пропустить API-резолвинг.** Реальные действия скрыты за хешами/PEB — восстановите их.
- **Не обработать несколько этапов.** Stager загружает второй payload — разберите и его.
- **Не учесть позиционную независимость.** Абсолютные адреса в дизасме — это rip-relative смещения, не «реальные» адреса.

## Пример: восстановление API-таблицы по хешам

Если shellcode резолвит функции по хешам, восстановите таблицу сопоставлением с экспортами DLL:

```python
def ror13(s):
    h = 0
    for c in s.encode():
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + c) & 0xFFFFFFFF
    return h

# Хеши, найденные в дизасме shellcode
targets = {0xEC0E4E8E: 'LoadLibraryA', 0x7C0DFCAA: 'GetProcAddress'}
for name in ['LoadLibraryA','GetProcAddress','WinExec','CreateProcessA','connect','recv','send']:
    h = ror13(name)
    if h in targets or True:
        print(hex(h), name)
```

Собрав соответствие хеш→имя для нужных DLL, вы переводите «непонятные» `call` в понятные вызовы (резолвинг, сеть, запуск процесса). Это ключ к пониманию назначения shellcode.

## Что делать дальше / решение

1. Определите архитектуру (x86/x64) и точку входа; дизассемблируйте blob.
2. Найдите и снимите слой кодирования (XOR/alpha) — получите реальные инструкции.
3. Разберите API-резолвинг (PEB walk, хеши имён) и восстановите таблицу функций.
4. Эмулируйте (Unicorn/Speakeasy), залогируйте поведение и расшифровку.
5. Для stager'а — извлеките и проанализируйте второй этап.
6. Соберите IOC (C2, URL, ключи) и оформите отчёт.

## Квиз

```quiz
- question: "Что такое stager в контексте shellcode?"
  options:
    - "Короткий код, скачивающий/расшифровывающий основной payload"
    - "Тип ELF"
    - "Пакер"
    - "Отладчик"
  answer: 0
  explanation: "Stager — первый этап, подгружающий основной shellcode."
- question: "Как дизассемблировать сырой blob?"
  options:
    - "ndisasm/objdump -b binary или Capstone"
    - "nm"
    - "ldd"
    - "strings"
  answer: 0
  explanation: "Для raw-данных нужен дизассемблер с явной архитектурой."
- question: "Что такое PEB walk?"
  options:
    - "Поиск функций через PEB/Ldr без импортов"
    - "Сканирование портов"
    - "Шифрование"
    - "Сборка"
  answer: 0
  explanation: "Shellcode резолвит API через PEB, чтобы не зависеть от импортов."
- question: "Как безопасно исполнить shellcode?"
  options:
    - "Эмуляция (Unicorn/Speakeasy)"
    - "Запустить напрямую"
    - "Открыть в браузере"
    - "Отправить в сеть"
  answer: 0
  explanation: "Эмуляция изолирует исполнение shellcode."
- question: "Что делать перед анализом закодированного shellcode?"
  options:
    - "Снять слой XOR/alpha-кодирования"
    - "Отключить ASLR"
    - "Снять canary"
    - "Расширить tcache"
  answer: 0
  explanation: "Декодирование раскрывает реальные инструкции."
```

## Где пригодится

- **CTF:** Reversing/Pwn — анализ эксплойтов.
- **Malware analysis:** stager/полезная нагрузка.
- **Exploit triage:** быстрый разбор.
- **Работа:** incident response, threat intel.
