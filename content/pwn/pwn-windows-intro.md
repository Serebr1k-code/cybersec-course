---
id: pwn-windows-intro
title: "Введение в Windows pwn: стек, SEH, DEP и ROP"
category: pwn
parent: pwn-rop
difficulty: hard
order: 4
tags: [windows, seh, dep, aslr, rop, pwn]
prerequisites: [pwn-rop, pwn-gadget-hunting]
useful_for:
  - "CTF Pwn категория"
  - "Windows exploit development"
  - "Vulnerability research"
estimated_minutes: 60
summary: "Знакомимся с эксплуатацией Windows-приложений: стек и адрес возврата, SEH, защиты DEP/ASLR/GS, построение ROP и запуск эксплойта через pwntools/WinDbg."
---
Введение в Windows pwn — это переход от Linux-эксплуатации к особенностям Windows: иной ABI, защита стека через SEH/GS, DEP, ASLR, CFG и специфические механизмы кучи. Хотя базовые принципы (переполнение, ROP, утечки) те же, детали сильно отличаются: соглашение о вызовах x64 (Microsoft x64), структура стека с «shadow space», обработка исключений через SEH, защита `__security_cookie`. В этом уроке — фундамент Windows-эксплуатации: ABI, стек, SEH, DEP, ASLR, ROP и практические инструменты (WinDbg, IDA, Ghidra, mona.py).

## Соглашение о вызовах Microsoft x64

Windows x64 использует собственное соглашение о вызовах, отличное от System V. Первые четыре целочисленных аргумента передаются в `rcx`, `rdx`, `r8`, `r9` (а не `rdi`, `rsi`, `rdx`, `rcx`). Остальные — на стек, начиная со смещения `rsp+0x20` (первые 0x20 байт стека — «shadow space»/home space, зарезервированы под spill регистров). Возврат — в `rax`. Caller-saved: `rax`, `rcx`, `rdx`, `r8`–`r11`; callee-saved: `rbx`, `rbp`, `rdi`, `rsi`, `r12`–`r15`. Знание этого критично: для вызова `WinExec("calc", 1)` нужен `rcx` = указатель на строку, `rdx` = 1.

| Аргумент | Регистр |
|---|---|
| 1 | `rcx` |
| 2 | `rdx` |
| 3 | `r8` |
| 4 | `r9` |
| 5+ | стек |

## Стек и shadow space

При вызове функции Windows резервирует «shadow space» — 0x20 байт на стеке для сохранения `rcx`, `rdx`, `r8`, `r9` вызываемой функцией. Это означает, что при переполнении стека смещение до сохранённого адреса возврата может отличаться от Linux. Также функции часто используют `rbp` как frame pointer, а прологи выглядят как `push rbp; mov rbp, rsp; sub rsp, N`. Учитывайте это при поиске offset.

## SEH и защита стека

Windows использует Structured Exception Handling (SEH) — цепочку обработчиков исключений, хранимую на стеке. На x86 (32-бит) SEH-записи (`EXCEPTION_REGISTRATION_RECORD`) связаны в список через `fs:[0]`, и переполнение стека может перезаписать обработчик — классическая атака (SEH overwrite). На x64 SEH реализован иначе (таблицы в `.pdata`, без указателей на стек), поэтому перезапись SEH не работает; вместо этого используются другие цели. Дополнительно включён `/GS` — защита стека через `__security_cookie` (аналог canary), размещаемый между локальными переменными и адресом возврата.

## DEP, ASLR, CFG

**DEP** (Data Execution Prevention) — аналог NX: запрещает исполнение данных. Обход — ROP/ret2libc. **ASLR** — рандомизация баз модулей (DLL/EXE); обход — утечки адресов. **CFG** (Control Flow Guard) — проверка косвенных вызовов: перед `call [reg]` проверяется, что цель — валидная функция. Обход — использовать легитимные цели (например, `LoadLibrary`/`WinExec` через ROP) или гаджеты внутри валидных функций. Проверка: `winchecksec` или `!dh` в WinDbg.

## Инструменты Windows-эксплуатации

- **WinDbg** — отладчик с командами `!analyze -v`, `!dh`, `!peb`, `!teb`.
- **x64dbg** — GUI-отладчик, удобен для динамического анализа.
- **IDA Pro / Ghidra** — декомпиляция.
- **mona.py** — плагин ImmDbg/WinDbg для поиска ROP-гаджетов и построения цепочек.
- **ROPgadget/ropper** — работают и с PE-файлами.
- **winchecksec** — проверка митигаций.

## Поиск offset и гаджетов

```text
1) Найти уязвимую функцию (strcpy, gets, memcpy без границ).
2) Определить offset до сохранённого RIP (cyclic pattern).
3) Найти гаджеты: pop rcx; ret, pop rdx; ret, ret.
4) Собрать ROP: VirtualProtect (сделать стек исполняемым) или WinExec.
5) Учесть shadow space и выравнивание (rsp % 16 == 8 при вызове).
```

Для вызова `WinExec("calc", SW_SHOW)`:

```python
rop  = flat(
    pop_rcx, addr_of_calc_string,
    pop_rdx, 1,
    ret,                      # выравнивание
    win_exec_addr
)
```

## Разобранный пример: ret2win в Windows

```python
from pwn import *
context.binary = elf = ELF('./vuln.exe')
p = process('./vuln.exe')
offset = cyclic_find(0x6161616c)      # из WinDbg/cyclic
win = elf.symbols['win']
p.sendline(flat(b'A'*offset, win))
p.interactive()
```

В Windows-бинарях адреса часто не рандомизированы для EXE (ASLR может быть отключён), что упрощает ret2win.

## SEH overwrite (32-бит)

На x86 при переполнении можно перезаписать SEH-запись: `next` (указатель на следующий обработчик) и `handler` (адрес обработчика). При исключении Windows вызовет `handler`. Атака: перезаписать `handler` на `pop pop ret`-гаджет, чтобы перейти к `next`, где лежит shellcode/ROP. Защита **SafeSEH** проверяет, что handler в валидном модуле, — тогда ищут модули без SafeSEH.

## Частые ошибки

- **Путаница ABI.** `rcx/rdx/r8/r9`, а не `rdi/rsi/rdx/rcx`.
- **Shadow space.** Забыли зарезервировать 0x20 байт.
- **Выравнивание стека.** `rsp % 16 == 8` при вызове.
- **CFG.** Косвенный вызов на невалидную цель заблокирован.
- **SafeSEH.** SEH overwrite не сработает на защищённых модулях.

## Справочные таблицы

| Защита | Аналог в Linux |
|---|---|
| DEP | NX |
| ASLR | ASLR |
| /GS | Canary |
| CFG | CFI |
| SafeSEH | (нет прямого) |

| Команда WinDbg | Назначение |
|---|---|
| `!analyze -v` | анализ падения |
| `!dh module` | заголовки PE |
| `!peb` | PEB |
| `x module!symbol` | адрес символа |

## Что дальше / решение

Дальше: `pwn-windows-heap`, `pwn-windows-kernel`, `pwn-macos`, `pwn-rop`, `pwn-gadget-hunting`. Практический алгоритм: (1) определите митигации (`winchecksec`); (2) найдите уязвимую функцию; (3) вычислите offset; (4) найдите гаджеты (mona/ROPgadget); (5) соберите ROP с учётом Microsoft ABI; (6) обойдите DEP/ASLR/CFG. Windows pwn требует знания специфики ABI и SEH, но базовые принципы те же.
## Полный разбор ROP-цепочки в Windows x64

Разберём сквозной пример: 64-битный PE с переполнением стека, DEP включён, ASLR для модуля отключён (типично для CTF). Цель — вызвать `WinExec("calc.exe", SW_SHOW)`. Шаги: (1) определить offset до сохранённого RIP через cyclic-паттерн; (2) найти гаджеты `pop rcx; ret` и `pop rdx; ret` (или `pop rdx; pop r8; ret`); (3) разместить строку `"calc.exe"` в записываемой памяти (например, в `__DATA` или на стеке, если он writable); (4) собрать цепочку: `pop rcx` → адрес строки, `pop rdx` → 1 (SW_SHOW), лишний `ret` для выравнивания, затем адрес `WinExec`; (5) отправить payload. Важно: при вызове функции стек должен быть выровнен так, чтобы `rsp % 16 == 8`; иначе `WinExec` упадёт. Также помните про shadow space — вызванная функция ожидает 0x20 байт зарезервированного стека, но для простых вызовов это обычно не критично, если вы не затираете её область.

## Обход DEP через VirtualProtect

Если нужно выполнить shellcode, а не вызвать функцию, используйте `VirtualProtect` для снятия защиты со страницы: `VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old)`. Цепочка: `pop rcx` → addr (адрес страницы с shellcode), `pop rdx` → size, `pop r8` → 0x40 (PAGE_EXECUTE_READWRITE), `pop r9` → указатель на old (записываемая память), `VirtualProtect`, затем прыжок на shellcode. Четыре аргумента требуют гаджетов на `rcx`, `rdx`, `r8`, `r9` — их ищите через mona.py (`!mona rop`) или ROPgadget. Альтернатива — `VirtualAlloc` для выделения новой исполняемой страницы, скопировать туда shellcode и прыгнуть. Оба пути стандартны для Windows pwn.

## ASLR, CFG и их обход

ASLR рандомизирует базы модулей. Если у вас есть утечка адреса (например, через `printf`/`WriteFile` с указателем), вы вычисляете базу и корректируете цепочку. CFG (Control Flow Guard) проверяет косвенные вызовы: `call [reg]` валиден только если `reg` указывает на начало функции, помеченной в таблице CFG. Обход CFG: использовать прямые вызовы (гаджеты `ret`), вызывать легитимные функции (`WinExec`, `LoadLibrary`), либо гаджеты внутри валидных функций. На практике ROP с гаджетами `ret` обходит CFG, потому что `ret` не проверяется. Поэтому ROP остаётся рабочим даже при CFG. Проверяйте наличие CFG через `winchecksec` и `!dh`.

## Отладка в WinDbg и x64dbg

Настройте WinDbg для user-mode отладки: `windbg app.exe`, затем `g` для запуска, `bp module!func` для точек останова, `g` для продолжения, `k` для backtrace, `r` для регистров, `dq rsp L20` для дампа стека. Для поиска offset используйте cyclic-паттерн (pwntools `cyclic`) и `!mona pattern_offset`. В x64dbg удобнее GUI: смотрите регистры и стек, ставьте точки. Для анализа PE используйте `!dh module` (заголовки) и `lm` (список модулей). Установите символы Microsoft через `_NT_SYMBOL_PATH` — это даст имена функций в `ntdll`/`kernel32`. Логируйте адреса и сравнивайте с ожидаемыми.

## Практические рекомендации

Windows pwn проще, если ASLR отключён (часто в CTF). Начните с ret2win (если есть функция `win`), затем переходите к ROP с `WinExec`/`VirtualProtect`. Всегда проверяйте выравнивание стека и shadow space. Изучите Microsoft x64 ABI до автоматизма — большинство ошибок новичков связаны именно с ним. Для сложных целей (CFG, ASLR) используйте mona.py, которая автоматизирует поиск гаджетов и построение цепочек. Помните, что Windows-бинари часто содержат удобные строки (`"calc"`, `"cmd"`) — используйте их вместо размещения своих.

## Итоговые рекомендации

Windows pwn требует освоения Microsoft x64 ABI, SEH и работы с WinDbg/x64dbg. Начните с ret2win и простого ROP (`WinExec`), затем переходите к `VirtualProtect` и обходу CFG/ASLR. Помните, что многие CTF-бинари имеют отключённый ASLR, что упрощает задачу. Практикуйтесь на специально уязвимых приложениях и используйте mona.py для автоматизации. Уверенное владение этими основами откроет вам путь к более сложным целям — Windows kernel и browser exploitation.

## Квиз

```quiz
- question: "Что такое SEH в Windows?"
  options:
    - "Structured Exception Handling — цепочка обработчиков исключений на стеке"
    - "Тип кучи"
    - "Таблица GOT"
    - "Формат PE"
  answer: 0
  explanation: "SEH хранит обработчики исключений; перезапись handler даёт контроль."
- question: "Какой гаджет классически используют для обхода SEH?"
  options:
    - "pop pop ret"
    - "leave; ret"
    - "syscall; ret"
    - "xchg rsp, rax"
  answer: 0
  explanation: "pop pop ret возвращает управление на next SEH (короткий прыжок на shellcode)."
- question: "Как обходят DEP на Windows?"
  options:
    - "ROP с VirtualProtect/VirtualAlloc для RWX"
    - "Отключением ASLR"
    - "Снятием canary"
    - "Расширением tcache"
  answer: 0
  explanation: "ROP вызывает VirtualProtect, делая память исполняемой."
- question: "Где передаются первые аргументы в x64 Windows?"
  options:
    - "В rcx, rdx, r8, r9"
    - "В rdi, rsi, rdx"
    - "Только на стеке"
    - "В rax"
  answer: 0
  explanation: "x64 Windows использует RCX, RDX, R8, R9 + shadow space."
- question: "Зачем нужен mona.py?"
  options:
    - "Поиск гаджетов/модулей/SEH-гаджетов в Immunity/WinDbg"
    - "Сканирование портов"
    - "Сборка PE"
    - "Фаззинг"
  answer: 0
  explanation: "mona автоматизирует поиск гаджетов и анализ модулей на Windows."
```

## Где пригодится

- **CTF:** Pwn — Windows-задачи.
- **Bug bounty:** Windows-приложения/сервисы.
- **Пентест:** Windows exploit development.
- **Работа:** vulnerability research.
