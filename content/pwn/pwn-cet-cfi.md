---
id: pwn-cet-cfi
title: "Обход CET/CFI и shadow stack"
category: pwn
parent: pwn-mitigations-bypass
difficulty: expert
order: 4
tags: [cet, shadow-stack, cfi, ibt, endbr64, intel, hardware-mitigation]
prerequisites: [pwn-mitigations, pwn-rop, pwn-ret2libc]
useful_for:
  - "CTF Pwn категория"
  - "Vulnerability research"
  - "Exploit mitigation bypass"
estimated_minutes: 55
summary: "Intel CET (shadow stack + IBT) и CFI усложняют ROP/ret2libc: разбираем, как они работают, когда реально включены и какие обходы существуют."
lab:
  kind: shell
  title: "Практика: ENDBR64 в CET-бинаре"
  toolset: [core, objdump, readelf]
  workdir: /home/student/task
  files: [task.md, cet]
  check: "grep -q 'f3 0f 1e fa' answer.txt"
  hints:
    - "`objdump -d cet` — начало функции `target`."
    - "ENDBR64 — это 4-байтовый опкод перед прологом."
    - "`readelf -n cet` подтвердит `IBT, SHSTK`."
---

## Вопрос, с которого всё начинается

Ты собрал идеальную ROP-цепочку, протестировал локально — работает. Но на новой машине с современным Intel-процессором она падает на первом же `ret`. Что изменилось?

Ответ — **CET** (Control-flow Enforcement Technology): аппаратная защита, которая ломает классический ROP. Разберём, как она устроена и как её обойти.

## Наш пример: бинарь с shadow stack

```bash
$ checksec --file=./chall
    CET:      CET enabled
$ readelf -n ./chall | grep -i "SHSTK\|IBT"
    Properties: x86 feature: IBT, SHSTK
$ objdump -d ./chall | grep endbr64 | head -3
  401020: f3 0f 1e fa    endbr64
```

`SHSTK` — shadow stack включён, `IBT` — включён. Классический ROP не сработает. Разберём почему.

## Шаг 1. Shadow stack: копия адресов возврата

**Shadow stack** — отдельный стек, куда процессор аппаратно сохраняет адреса возврата при `call` и сверяет при `ret`. Если ты перезаписал адрес возврата на обычном стеке, `ret` сравнит его с теневой копией и вызовет fault.

Это блокирует классический ROP (перезапись адреса возврата). Но защищает shadow stack **только `ret`** — не `call` и не `jmp`. Отсюда обходы.

## Шаг 2. IBT и endbr64

**IBT** (Indirect Branch Tracking) требует, чтобы косвенные переходы (`jmp`/`call` через регистр) попадали на инструкцию `endbr64`. Это блокирует прыжки на произвольные гаджеты — цель должна начинаться с `endbr64`.

Обход: использовать гаджеты, которые **начинаются** с `endbr64`. В бинаре с IBT каждая функция начинается с неё, поэтому легитимные точки входа функций можно использовать как цели.

## Шаг 3. CFI: проверка целей

**CFI** (Control Flow Integrity) проверяет, что косвенный вызов идёт на допустимую цель (по таблице). Варианты: forward-edge (косвенные вызовы) и backward-edge (возвраты). Реализации: LLVM CFI, Windows CFG, Intel CET.

CFI ограничивает набор целей, но не устраняет атаки: неполная проверка, использование легитимных целей с нужными аргументами, data-only атаки, **COOP** (Counterfeit Object-Oriented Programming).

| Защита | Что проверяет | Обход |
|---|---|---|
| shadow stack | `ret` | SROP, JOP |
| IBT | косвенные переходы | `endbr64`-гаджеты |
| CFI | цели вызовов | COOP, data-only |

## Шаг 4. Обход 1: SROP

**SROP** — самый надёжный обход shadow stack. Syscall `rt_sigreturn` (номер 15) восстанавливает **все** регистры из поддельного фрейма на стеке — и делает это **не через `ret`**, поэтому shadow stack не мешает:

```python
from pwn import *
context.binary = elf = ELF('./chall')
frame = SigreturnFrame()
frame.rax = 59              # execve
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_gadget
frame.rsp = stack
payload = flat(b'A'*offset, pop_rax, 15, syscall_gadget, frame)
```

Схема: ставим `rax = 15`, делаем `syscall` — ядро выполняет `rt_sigreturn` и берёт регистры из фрейма. Классического `ret` в этой цепочке нет, значит shadow stack не участвует.

## Шаг 5. Обход 2: JOP через endbr64

Если IBT включён, строй **JOP** (Jump-Oriented Programming): вместо `ret` используй косвенные переходы на гаджеты, начинающиеся с `endbr64`:

```bash
$ ROPgadget --binary ./chall | grep -A1 endbr64
$ objdump -d ./chall | grep -B1 endbr64
```

В бинаре с IBT каждая функция начинается с `endbr64` — эти точки можно использовать как цели. JOP-цепочка: косвенный переход на `endbr64`-гаджет, который выполняет действие и делает косвенный переход дальше. Сложнее ROP, но реализуемо.

## Шаг 6. Обход 3: data-only

Самый простой путь часто — вообще не трогать поток управления. **Data-only** атака изменяет данные, а не код: перезапись `modprobe_path`, токена, флагов привилегий. CET и CFI контролируют **поток управления**, поэтому против data-only они бессильны.

В ядре это `modprobe_path`/токен (см. `pwn-kernel-intro`), в userland — флаги привилегий, конфигурация, указатели, которые не проверяются CFI.

## Шаг 7. CFI и COOP

Против CFI в C++-приложениях применяют **COOP** — переиспользование существующих виртуальных функций, вызываемых через подделанные vtable, но так, чтобы каждая цель была «легитимной» по CFI. Также работают data-only и баги в самой CFI. Изучай, какие вызовы защищены, а какие — нет.

## Дополнительные приёмы обхода

Помимо SROP, JOP и data-only, есть и другие пути. **ret2dlresolve** не требует `ret`-контроля в чистом виде — он использует резолвер. **Перезапись GOT/указателей функций** работает, если CFI проверяет лишь часть вызовов. **Манипуляция обработчиками сигналов** (например, SIGSEGV) позволяет получить контроль через доставку сигнала. **Подделка unwind-структур** (исключения) даёт ещё один канал. Изучай, какие именно вызовы защищены CFI, а какие — нет: непроверенные места и есть твой вход.

Data-only атаки часто проще и надёжнее всех перечисленных: они не трогают поток управления, поэтому CET/CFI против них бессильны. В ядре это `modprobe_path` и токен, в userland — флаги привилегий и конфигурация. Комбинируй приёмы: например, SROP для первичного контроля, затем data-only для финального повышения привилегий.

## Практика: SROP-шаблон под CET

Собери SROP-шаблон один раз и переиспользуй: найди `syscall; ret` и `pop rax; ret`; установи `rax = 15` (`rt_sigreturn`) и выполни `syscall`; подготовь `SigreturnFrame` с `rax = 59`, `rdi = binsh`, `rip = syscall`; отправь. `rt_sigreturn` не проходит через `ret`, поэтому shadow stack не мешает. Для IBT ищи `endbr64`-гаджеты (`ROPgadget | grep endbr64`) и строй JOP. Для CFI используй COOP или data-only. Практикуйся на системах с CET (Intel 11th gen+) и CFI (LLVM/Windows CFG). Держи шаблон под рукой — он экономит время, когда очередная цель окажется с аппаратной защитой.

## На что смотреть дальше

- **Игнорирование CET** — классический ROP молча упадёт.
- **Неверный SROP-фрейм** — структура должна быть точной, иначе краш.
- **CFI-таблица** ограничивает цели — не любой адрес подойдёт.
- **Data-only не всегда возможны** — нужен примитив записи в данные.
- **Версии CET/CFI различаются** — проверяй конкретную реализацию.
- **CET встречается редко на CTF**, но становится стандартом на новых Intel.

## Что мы теперь знаем

- Shadow stack сверяет адреса возврата и ломает классический ROP.
- IBT требует `endbr64` на цели косвенного перехода.
- CFI ограничивает цели вызовов по таблице.
- SROP обходит shadow stack, JOP — IBT, COOP/data-only — CFI.
- Data-only атаки не трогают поток управления, поэтому обходят все три.

Проверка CET занимает минуту (`readelf -n`, `checksec`), а пренебрежение ею стоит часа отладки на цепочке, которая «почему-то» падает на первом `ret`. Всегда начинай с вопроса: включены ли shadow stack и IBT на этой цели.

## Квиз

Проверь себя.

```quiz
- question: "Что защищает shadow stack?"
  options:
    - "Адреса возврата (ret) от перезаписи"
    - "Косвенные вызовы"
    - "Кучу"
    - "ASLR"
  answer: 0
  explanation: "Shadow stack хранит копию адресов возврата и сверяет их при ret."
- question: "Что требует IBT от цели косвенного перехода?"
  options:
    - "Начало с инструкции endbr64"
    - "Чётного адреса"
    - "Адреса в куче"
    - "Нулевого регистра"
  answer: 0
  explanation: "IBT допускает косвенные переходы только на endbr64-точки."
- question: "Какой приём обходит shadow stack, не возвращаясь через ret?"
  options:
    - "sigreturn/setcontext или перезапись указателя функции с вызовом через call"
    - "Заполнение tcache"
    - "Утечка libc"
    - "Отключение NX"
  answer: 0
  explanation: "Control-flow hijack без ret (call/JOP/sigreturn) не затрагивает shadow stack."
- question: "Что такое data-only attack?"
  options:
    - "Изменение данных (флагов, указателей), а не потока управления"
    - "Атака только на данные в сети"
    - "ROP без гаджетов"
    - "Атака на диск"
  answer: 0
  explanation: "CFI контролирует поток управления; data-only атаки его не затрагивают."
- question: "Где проверить, поддерживает ли бинарь CET?"
  options:
    - "readelf -n (GNU_PROPERTY_X86_FEATURE_1_SHSTK/IBT)"
    - "nm"
    - "ldd"
    - "strings"
  answer: 0
  explanation: "Note-секция GNU_PROPERTY_X86_FEATURE_1 указывает на поддержку SHSTK/IBT."
```

## Куда дальше

В `pwn-heap-uaf` мы вернёмся к куче и разберём use-after-free — класс багов, лежащий в основе большинства современных heap-эксплойтов. А пока главное: **CET/CFI повышают планку, но не абсолютны: SROP обходит shadow stack, JOP — IBT, а data-only — вообще все control-flow защиты.**

## Где пригодится

- **CTF:** Pwn — современные задачи с CET/CFI.
- **Bug bounty:** реальные системы с включённым CET.
- **Пентест:** обход современных защит.
- **Работа:** exploit mitigation research.
