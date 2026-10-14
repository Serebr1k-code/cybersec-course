---
id: pwn-mips64
title: "MIPS64: delay slot, регистр ra и эксплуатация"
category: pwn
parent: pwn-arch-modern
difficulty: medium
order: 3
tags: [pwn, mips64, mips, delay-slot, ra, rop, big-endian]
prerequisites: [pwn-mips, pwn-gadget-hunting]
useful_for:
  - "Эксплуатация MIPS64-устройств (сетевое оборудование)"
  - "Разбор прошивок роутеров"
estimated_minutes: 55
summary: "Углубляем MIPS до 64 бит: регистр ra, delay slot, jr $ra и особенности построения ROP на big-endian MIPS64."
lab:
  kind: shell
  title: "Практика: порядок байт MIPS64"
  toolset: [core, elf]
  workdir: /home/student/task
  files: [task.md, mips64.s, mips64.readelf.txt]
  check: "grep -q 'endianness=big' answer.txt"
  hints:
    - "MIPS традиционно big-endian (как и многие embedded-ядра)."
    - "`readelf --file-header` печатает `Data:` — порядок байт."
    - "В строке `Data:` написано `big endian`."
    - "Запиши `endianness=big`."
---

## Вопрос, с которого всё начинается

MIPS ты уже встречал в 32-битном варианте. Но современное сетевое оборудование
всё чаще 64-битное (MIPS64), а соглашения и особенности остаются узнаваемыми:
регистр возврата `ra`, delay slot, big-endian. Разберём, что меняется при переходе
к 64 битам.

## Наш пример

```
$ file mips64.elf
mips64.elf: ELF 64-bit MSB relocatable, MIPS, MIPS64 rel2
$ readelf --file-header mips64.elf
  Class:                             ELF64
  Data:                              2's complement, big endian
  Machine:                           MIPS R3000
```

64 бита, big-endian. Листинг (`mips64.s`):

```
f:
	daddiu	$sp, $sp, -32
	sd	$ra, 24($sp)
	sd	$fp, 16($sp)
	move	$fp, $sp
	...
	ld	$ra, 24($sp)
	jr	$ra
	nop
```

## Шаг 1: регистр ra

Возврат MIPS — инструкция **`jr $ra`** (Jump Register to `$ra`). Адрес возврата
лежит в регистре **`$ra`** (`$31`). Инструкция `jal` при вызове кладёт в `$ra`
адрес возврата — как `bl` на ARM или `jal` на RISC-V.

В листинге видно `sd $ra, 24($sp)` — сохранение `$ra` на стек в прологе. **Точка
перезаписи** — этот слот: переполнив буфер, добираемся до него.

## Шаг 2: delay slot

MIPS — классическая delay-slot архитектура: инструкция сразу после ветвления
выполняется до перехода. В листинге:

```
	jr	$ra
	nop        <-- delay slot
```

Компилятор ставит `nop`, потому что полезной инструкции нет. При построении ROP
и шеллкода в delay slot надо ставить либо `nop`, либо безопасную инструкцию.
Если оставить там «мусор», он исполнится.

## Шаг 3: 32 vs 64 бита

На MIPS64 меняются размеры: указатели 8 байт, инструкции `daddiu`/`sd`/`ld`
(64-битные версии). Стек-кадры больше, а `$ra` занимает 8 байт. Соглашение
передачи аргументов (`o32`/`n32`/`n64`) зависит от ABI: в `n64` первые
аргументы идут в `$a0`..`$a7`, возврат — в `$v0`.

## Шаг 4: гаджеты MIPS

Ищем последовательности, заканчивающиеся `jr $ra` или `jr $t9`. Помни про delay
slot: полезная инструкция может стоять **после** `jr`. Хорошо работают
инструменты `ROPgadget --rawArch=mips64` и Ghidra с модулем MIPS.

Типичный гаджет для загрузки аргумента:

```
lw $a0, N($sp) ; jr $ra ; nop
```

## Шаг 5: собираем эксплойт

```python
from pwn import *
context.arch = 'mips64'
context.endian = 'big'
p = process('./challenge')
offset = 40
payload  = b'A' * offset
payload += p64(ret2win_addr)   # перезаписанный $ra
p.sendline(payload)
p.interactive()
```

Big-endian: адреса упаковываются старшим байтом вперёд. Ошибка с endianness —
самая частая причина «не работает».

## Шаг 6: где встречается

MIPS64 живёт в сетевом оборудовании (коммутаторы, маршрутизаторы), NAS и
промышленных контроллерах. Прошивки часто содержат бинари MIPS64 с большими
объёмами кода, где удобно искать гаджеты и целые функции для ret2win.

## Шаг 7: инструменты и отладка

Кросс-тулчейн `mips64-linux-gnuabi64-*` даёт `objdump`/`gdb`. Эмуляция —
`qemu-mips64`/`qemu-mips64el`. Для прошивок — `binwalk`, `firmware-mod-kit`,
Ghidra. Отладка «в живом» устройстве часто недоступна, поэтому много работы
ведётся статически.

## Что мы теперь знаем

- Возврат MIPS — `jr $ra`; адрес возврата в `$ra`.
- Не-leaf функции сохраняют `$ra` на стек (`sd $ra, N($sp)`).
- Delay slot после `jr` исполняется до перехода.
- MIPS64 — big-endian, адреса 8 байт, ABI `n64`.
- Инструменты: кросс-binutils, qemu, Ghidra.

## Квиз

Проверь себя.

```quiz
- question: В каком регистре MIPS лежит адрес возврата?
  options:
    - "$sp"
    - "$ra"
    - "$a0"
    - "$v0"
  answer: 1
  explanation: jr $ra возвращается по адресу в $ra (регистр 31).
- question: Что такое delay slot в MIPS?
  options:
    - "Пустой кадр"
    - "Инструкция после ветвления, исполняющаяся до перехода"
    - "Регистр"
    - "Кэш"
  answer: 1
  explanation: Как у SPARC и SH, инструкция после ветвления выполняется до него.
- question: Какой порядок байт у MIPS64 в нашем примере?
  options:
    - "little-endian"
    - "big-endian"
    - "смешанный"
    - "нет порядка"
  answer: 1
  explanation: readelf показывает `big endian`; адреса упаковываем старшим байтом.
- question: Какая инструкция загружает первый аргумент в MIPS64 (n64)?
  options:
    - "lw $a0, N($sp)"
    - "sd $ra, N($sp)"
    - "jr $ra"
    - "daddiu $sp, $sp, -32"
  answer: 0
  explanation: Первый аргумент идёт в $a0; lw/lwu загружает его со стека.
```

## Куда дальше

Дальше — **WASM**: эксплойтация модулей WebAssembly и побег из песочницы. А пока
запомни: **на MIPS64 адрес возврата — `$ra`, а delay slot нельзя игнорировать**.

## Где пригодится

- Эксплуатация MIPS64 сетевого оборудования.
- Разбор прошивок роутеров и NAS.
- Понимание delay-slot-архитектур.
