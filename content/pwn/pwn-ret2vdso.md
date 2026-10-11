---
id: pwn-ret2vdso
title: "ret2vDSO и vsyscall: гаджеты без libc-утечки"
category: pwn
parent: pwn-rop-exotic
difficulty: medium
order: 1
tags: [ret2vdso, vsyscall, rop, aslr, gadgets, syscall]
prerequisites: [pwn-rop, pwn-mitigations, pwn-ret2libc]
useful_for:
  - "CTF Pwn категория"
  - "Vulnerability research"
estimated_minutes: 55
summary: "Как использовать vDSO и vsyscall-страницу для получения syscall-гаджета и утечки/вызова без известного адреса libc; особенности ASLR и shadow-маппинга."
---
ret2vDSO и vsyscall — это приёмы получения гаджетов без утечки libc, используя страницы `vDSO` и `vsyscall`, отображаемые ядром. `vDSO` (virtual dynamic shared object) — небольшая область в адресном пространстве процесса, содержащая реализации быстрых syscall'ов (`gettimeofday`, `clock_gettime` и др.). `vsyscall` — legacy-страница на фиксированном адресе `0xffffffffff600000`. Если у вас есть контроль потока, но нет libc-утечки, эти страницы дают фиксированные гаджеты (например, `syscall; ret`). В этом уроке — устройство vDSO/vsyscall, поиск гаджетов, приёмы эксплуатации и ограничения.

## Что такое vDSO

`vDSO` отображается ядром в каждый процесс для ускорения syscall'ов, которые не требуют переключения в ring 0 (например, `gettimeofday`). Это ELF-образ с кодом. Его адрес рандомизирован (ASLR), но в некоторых случаях можно вычислить/утечь. В `vDSO` есть инструкции `syscall`/`ret`, которые могут служить гаджетами. Если ASLR vDSO предсказуем или есть утечка, вы получаете гаджет без libc.

## vsyscall и фиксированный адрес

`vsyscall` — старая механизм, отображаемый по **фиксированному** адресу `0xffffffffff600000`. Он содержит три функции: `gettimeofday` (0xffffffffff600000), `time` (0xffffffffff600400), `getcpu` (0xffffffffff600800). Каждая — `mov rax, N; syscall; ret` (в режиме `vsyscall=emulate`) или прямой переход. Используя `0xffffffffff600000` как гаджет, можно выполнить `syscall` с контролируемым `rax` (если вы можете установить `rax`). Это даёт syscall-примитив без libc. В современных ядрах `vsyscall` часто отключён или в режиме `emulate`/`none`.

## Использование vDSO/vsyscall

```python
from pwn import *
context.binary = elf = ELF('./chall')
# vsyscall фиксирован
vsyscall = 0xffffffffff600000
# если нужен syscall-гаджет:
payload = flat(b'A'*offset, pop_rax, 59, pop_rdi, binsh, vsyscall)
```

Для `execve`: установить `rax=59`, `rdi=binsh`, `rsi=rdx=0`, затем прыгнуть на `vsyscall`, который выполнит `syscall`. Так вы обходитесь без libc.

## Ограничения

- **vsyscall отключён.** В современных ядрах (`vsyscall=none`) страница недоступна.
- **Режим emulate.** Выполняется эмуляция, ограничивающая набор инструкций.
- **vDSO ASLR.** Адрес рандомизирован; нужна утечка.
- **SMEP/SMAP.** Не влияет на переход в vsyscall (он в kernel-адресах, но исполняется в user-режиме).
- **KPTI.** Может влиять на доступность.

## Проверка

```bash
cat /proc/self/maps | grep -E "vdso|vsyscall"
```

Покажет, отображены ли страницы и по каким адресам. В gdb: `info proc mappings`.

## Разобранный пример: ret2vsyscall

```python
from pwn import *
context.binary = elf = ELF('./chall')
p = process('./chall')
# строим ROP с vsyscall как syscall-гаджетом
rop = ROP(elf)
pop_rax = rop.find_gadget(['pop rax','ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi','ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx','ret'])[0]
vsyscall = 0xffffffffff600000
chain  = flat(pop_rax, 59, pop_rdi, binsh, pop_rsi, 0, pop_rdx, 0, vsyscall)
p.sendline(flat(b'A'*offset, chain))
p.interactive()
```

## Частые ошибки

- **vsyscall отключён.** Проверьте `/proc/self/maps`.
- **Неверный адрес.** Фиксированные адреса — только для vsyscall.
- **Режим emulate.** Может ограничивать.
- **Нет гаджетов на rax.** Нужен способ установить `rax`.
- **KPTI/SMEP.** Учитывайте при возврате.

## Справочные таблицы

| Страница | Адрес | Содержимое |
|---|---|---|
| vsyscall | 0xffffffffff600000 | gettimeofday |
| vsyscall | 0xffffffffff600400 | time |
| vsyscall | 0xffffffffff600800 | getcpu |
| vDSO | случайный | быстрые syscall'ы |

| Приём | Когда |
|---|---|
| ret2vsyscall | есть rax-гаджет |
| ret2vdso | есть утечка vDSO |
| ret2syscall | есть `syscall` в бинаре |

## Что дальше / решение

Дальше: `pwn-static-no-libc`, `pwn-rop`, `pwn-seccomp-srop`, `pwn-ret2csu`. Практический алгоритм: (1) проверьте наличие vDSO/vsyscall (`/proc/self/maps`); (2) если vsyscall доступен — используйте как syscall-гаджет; (3) если нет — ищите `syscall` в бинаре/vDSO; (4) постройте ORW/execve; (5) обойдите ASLR. ret2vDSO/vsyscall — элегантный способ получить гаджеты без libc; полезен, когда утечка невозможна.
## Полный разбор ret2vdso

Разберём сквозной пример. Дано: 64-битный бинарь с переполнением, PIE off, но libc-утечки нет (или libc недоступна). Цель — выполнить `execve("/bin/sh")` без libc. Шаги: (1) проверить `/proc/self/maps` — есть ли `vsyscall` и `vDSO`; (2) если `vsyscall` доступен (`0xffffffffff600000`), использовать его как `syscall`-гаджет; (3) найти гаджеты `pop rax`, `pop rdi`, `pop rsi`, `pop rdx` в бинаре; (4) найти/записать строку `"/bin/sh"` (например, в `.bss` через `read`); (5) собрать цепочку: `pop rax, 59; pop rdi, binsh; pop rsi, 0; pop rdx, 0; vsyscall`; (6) отправить. `vsyscall` выполнит `syscall` с нашими регистрами, вызвав `execve`. Если `vsyscall` в режиме `emulate`, он всё равно выполнит syscall (эмуляция ограничена, но `gettimeofday`-код содержит `syscall; ret`).

## vDSO: поиск гаджетов

`vDSO` содержит код для быстрых syscall'ов. Его адрес рандомизирован, но если у вас есть утечка (например, через неинициализированную память или формат-строку), вы можете вычислить базу vDSO и найти там гаджеты `syscall; ret`. Также vDSO содержит функции вроде `__vdso_gettimeofday`, которые можно использовать как трамплины. В gdb: `info proc mappings` покажет диапазон `[vdso]`. Дампните его (`dump memory vdso.bin <start> <end>`) и ищите `syscall` через ROPgadget. Это даёт дополнительные гаджеты, когда бинарь беден на них.

## Ограничения и современные системы

На современных системах `vsyscall` часто отключён (`vsyscall=none`) или работает в режиме `emulate`/`xonly`. Проверьте `/proc/self/maps`: строка `vsyscall` покажет режим. Если отключён, используйте `vDSO` (если есть утечка) или `syscall`-гаджеты в бинаре/статической libc. Также KPTI может влиять на доступность некоторых страниц. Учитывайте, что в контейнерах/песочницах `vsyscall` может быть недоступен. Всегда проверяйте окружение перед выбором приёма.

## Практические рекомендации

Начните с проверки `/proc/self/maps` на наличие `vdso`/`vsyscall`. Если `vsyscall` доступен — это самый простой путь к syscall-гаджету. Если нет — ищите `syscall` в бинаре (часто есть в статических) или в vDSO (нужна утечка). Комбинируйте с SROP для установки всех регистров. Помните, что ret2vDSO/vsyscall — не замена ROP, а источник гаджетов, когда их не хватает. Практикуйтесь на задачах без libc и с ограниченными гаджетами. Этот приём редко встречается в современных системах, но полезен для понимания устройства адресного пространства.
## Разбор vDSO-гаджетов на практике

Чтобы найти гаджеты в vDSO: (1) в gdb выполните `info proc mappings` и найдите диапазон `[vdso]`; (2) `dump memory vdso.bin <start> <end>`; (3) `ROPgadget --binary vdso.bin | grep syscall`; (4) вычислите смещения гаджетов от базы vDSO. При утечке базы vDSO (например, через `gettimeofday`-указатель в libc или неинициализированную память) вы получаете `syscall; ret`-гаджет. Это особенно полезно, когда бинарь беден на гаджеты, а libc недоступна. vDSO также содержит функции, которые можно использовать как трамплины для syscall'ов. Изучите `__vdso_gettimeofday` и другие — они содержат `syscall`-инструкции. Практикуйтесь на задачах без libc.

## Сравнение vsyscall и vDSO

`vsyscall` — фиксированный адрес, но часто отключён. `vDSO` — рандомизирован, но всегда присутствует и содержит код. `vsyscall` проще (адрес известен), но менее доступен. `vDSO` требует утечки, но надёжнее. В современных системах предпочитайте `vDSO` с утечкой или `syscall`-гаджеты в бинаре. Также учитывайте, что в некоторых конфигурациях (`vsyscall=xonly`) страница исполняема, но не читаема — тогда вы можете прыгнуть на неё, но не дизассемблировать. Проверяйте режим в `/proc/self/maps`. Выбор зависит от доступных гаджетов и утечек.

## Практические рекомендации

Проверьте `/proc/self/maps` на `vdso`/`vsyscall`. Если `vsyscall` доступен — используйте как syscall-гаджет (проще всего). Если нет — ищите `syscall` в бинаре или vDSO (с утечкой). Комбинируйте с SROP для установки регистров. Помните, что ret2vDSO/vsyscall — источник гаджетов, а не замена ROP. Практикуйтесь на задачах без libc и с ограниченными гаджетами. Изучайте устройство адресного пространства Linux — это база для понимания митигаций и техник.


## vDSO: практический поиск и использование

Для vDSO: в gdb `info proc mappings` покажет диапазон `[vdso]`; `dump memory vdso.bin <start> <end>` сохранит его; `ROPgadget --binary vdso.bin | grep syscall` найдёт гаджеты. С утечкой базы vDSO вы получаете `syscall; ret`. Это дополняет гаджеты бинаря и полезно, когда их мало. Также vDSO-функции (`__vdso_gettimeofday`) можно использовать как трамплины. На современных системах `vsyscall` часто отключён (`vsyscall=none`), поэтому проверяйте режим в `/proc/self/maps`. Комбинируйте с SROP для установки регистров. Практикуйтесь на задачах без libc.


## Практика: поиск гаджетов в vDSO

Шаги: (1) в gdb `info proc mappings`, найдите `[vdso]`; (2) `dump memory vdso.bin <start> <end>`; (3) `ROPgadget --binary vdso.bin | grep syscall`; (4) вычислите смещение гаджета от базы; (5) с утечкой базы — используйте. Проверьте режим `vsyscall` в `/proc/self/maps`. Для ORW/SROP комбинируйте с гаджетами бинаря. Практикуйтесь на задачах без libc. ret2vDSO — элегантный источник гаджетов; полезен при их нехватке. Изучайте устройство адресного пространства Linux.


## Заключение по ret2vDSO/vsyscall

vDSO/vsyscall дают гаджеты (`syscall`) без libc. vsyscall — фиксированный адрес (часто отключён), vDSO — рандомизирован (нужна утечка). Проверяйте `/proc/self/maps`. Комбинируйте с SROP. Практикуйтесь на задачах без libc и с ограниченными гаджетами. Понимание адресного пространства Linux — база для многих техник.


## Финальные рекомендации

Проверяйте `/proc/self/maps` на vDSO/vsyscall. Используйте vsyscall (фиксированный) как syscall-гаджет, vDSO — с утечкой. Комбинируйте с SROP. Практикуйтесь на задачах без libc. ret2vDSO расширяет арсенал гаджетов и углубляет понимание адресного пространства.

## Квиз

```quiz
- question: "Что такое vDSO?"
  options:
    - "Отображение кода ядра в userspace, содержащее syscall-гаджет"
    - "Виртуальный диск"
    - "Таблица GOT"
    - "Раздел ELF"
  answer: 0
  explanation: "vDSO (linux-vdso.so.1) всегда замаплен и содержит syscall; ret."
- question: "Чем vsyscall отличается от vDSO?"
  options:
    - "vsyscall имеет фиксированный адрес (на старых ядрах)"
    - "vsyscall в куче"
    - "vsyscall только для ARM"
    - "Ничем"
  answer: 0
  explanation: "Классический vsyscall по адресу 0xffffffffff600000 не рандомизируется."
- question: "Что даёт vDSO в ROP?"
  options:
    - "Гаджет syscall; ret без libc"
    - "Утечку canary"
    - "Отключение ASLR"
    - "Расширение tcache"
  answer: 0
  explanation: "vDSO содержит syscall; ret, полезный без libc-утечки."
- question: "Какие регистры нужны для syscall в x86-64?"
  options:
    - "rax (номер), rdi, rsi, rdx (аргументы)"
    - "rbx, rcx, r8"
    - "только rax"
    - "x0, x1, x2"
  answer: 0
  explanation: "Syscall: номер в rax, аргументы в rdi/rsi/rdx/r10/r8/r9."
- question: "Почему на новых ядрах vsyscall может не работать?"
  options:
    - "Он эмулируется или отключён (vsyscall=none/emulate)"
    - "Его нет в 32-бит"
    - "Он только для Windows"
    - "Он требует libc"
  answer: 0
  explanation: "Современные ядра ограничивают vsyscall, поэтому проверяйте maps."
```

## Где пригодится

- **CTF:** Pwn — задачи без libc-утечки, статические бинари.
- **Bug bounty:** построение цепочек в ограниченных условиях.
- **Пентест:** разработка эксплойтов.
- **Работа:** exploit development.
