---
id: pwn-kernel-data-only
title: "Data-only атаки в ядре: root без перехвата потока"
category: pwn
parent: pwn-kernel-primitives
difficulty: expert
order: 4
tags: [pwn, kernel, data-only, cred, modprobe-path, no-control-flow, cfi]
prerequisites: [pwn-kernel-info-leak, pwn-kernel-core]
useful_for:
  - "Обход CFI/CET и защит потока управления в ядре"
  - "Повышение привилегий через данные"
estimated_minutes: 65
summary: "Data-only kernel-атаки: перезапись cred, modprobe_path и других данных вместо захвата потока управления; почему это обходит CFI и когда data-only проще, чем ROP."
lab:
  kind: shell
  title: "Практика: цель data-only атаки"
  toolset: [core, elf]
  workdir: /home/student/task
  files: [task.md, cred.h]
  check: "grep -q 'target=cred' answer.txt"
  hints:
    - "Data-only не трогает поток управления."
    - "Цель — структура, описывающая права процесса."
    - "Она называется cred."
    - "Запиши `target=cred`."
---

## Вопрос, с которого всё начинается

На современных ядрах включают CFI и shadow stack — защиты, которые ломают ROP.
Но что, если вообще не перехватывать поток управления? Есть целый класс атак,
которые меняют только **данные**. В ядре это часто и проще, и надёжнее. Как это
работает?

## Наш пример

Смотрим, как ядро хранит права процесса:

```c
struct cred {
    atomic_t usage;
    kuid_t   uid, gid, suid, sgid, euid, egid, fsuid, fsgid;
    unsigned cap_*;       // capabilities
    ...
};
```

Права root — это `uid = 0`, `gid = 0` и полный набор capabilities в структуре
`cred`. Если мы можем **записать нули** в поля чужого `cred`, процесс станет
root. Поток управления при этом не трогается вообще.

## Шаг 1: почему data-only обходит CFI

CFI (Control-Flow Integrity) проверяет, что косвенные вызовы идут в допустимые
цели. Shadow stack проверяет, что `ret` возвращается туда, откуда пришёл. Обе
защиты следят за **потоком управления**. Data-only атака меняет данные, поэтому
обе защиты «не замечают» атаку — они просто не на этом уровне.

Именно поэтому на системах с CFI/CET data-only — предпочтительный путь.

## Шаг 2: цель №1 — cred

Классический data-only privesc:

1. Находим адрес `cred` текущего процесса. Его можно утечь через
   `task_struct` → `cred` (если есть read-примитив) или через спрей.
2. Записываем нули в `uid`..`fsgid` и выставляем все capabilities в `0xffffffff`.
3. Проверяем `id` — процесс стал root.

Есть тонкость: `cred` иммутабелен, ядро использует copy-on-write через
`prepare_creds`. Но если мы пишем напрямую в память, это неважно — главное
попасть в правильную структуру.

## Шаг 3: цель №2 — modprobe_path

`modprobe_path` — глобальная строка в ядре (обычно `/sbin/modprobe`). Когда
ядро встречает файл с неизвестным форматом (например, `\xff\xff\xff\xff`), оно
вызывает `call_usermodehelper` и запускает `modprobe_path` от имени root.

Атака:

1. Перезаписываем строку на `/tmp/x` (наш скрипт).
2. Создаём `/tmp/x`, который делает что-то полезное (например, копирует shell).
3. Триггерим неизвестный формат — ядро запускает наш скрипт как root.

Здесь тоже нет перехвата потока управления — только запись строки.

## Шаг 4: цель №3 — core_pattern

Похожий приём: `core_pattern` определяет, что делать с core-дампом. Если
перезаписать его на `|/tmp/x %p`, то при падении процесса ядро запустит наш
скрипт как root. Запись данных — и root без ROP.

## Шаг 5: когда data-only не подходит

Data-only требует **записи** по нужному адресу. Если у нас только read или
только control-flow-примитив, придётся строить ROP. Кроме того:

- Нужно точно знать смещения полей (`cred` менялся между версиями ядра).
- Некоторые структуры защищены (например, `cred` может быть в `SLAB_ACCOUNT`).
- KASLR всё равно нужно обойти, чтобы найти адрес цели.

То есть data-only — не замена утечке, а замена control-flow части эксплойта.

## Шаг 6: пример с перезаписью cred

```c
uint64_t cred_addr = leak_cred();        // нашли через утечку
uint64_t zeros[4] = {0};
write_kernel(cred_addr + 4, zeros, 32);  // uid..fsgid = 0
uint64_t caps = 0xffffffffffffffffULL;
write_kernel(cred_addr + 0x28, &caps, 8); // capabilities
```

После этого `getuid()` вернёт 0. Смещения (4, 0x28) — примерные, для конкретного
ядра их берут из BTF/отладочных символов.

## Шаг 7: отладка и проверка

Проверяем через `id`/`getuid` после атаки. Под `qemu` с `gdb` смотрим
`cred` процесса: `p ((struct task_struct*)$current)->cred`. Если поля обнулились —
атака сработала. Полезно логировать адрес `cred` до и после.

## Что мы теперь знаем

- Data-only меняет данные, не трогая поток управления.
- `cred` — главная цель: нулевые uid = root.
- `modprobe_path`/`core_pattern` дают выполнение команды как root.
- CFI/CET не ловят data-only.
- Нужны запись по адресу и обход KASLR.

## Квиз

Проверь себя.

```quiz
- question: Почему data-only обходит CFI?
  options:
    - "CFI следит за потоком управления, а data-only его не трогает"
    - "CFI выключен"
    - "Data-only быстрее"
    - "CFI для userland"
  answer: 0
  explanation: Защита потока не замечает изменения данных.
- question: Что перезаписывают, чтобы получить root через cred?
  options:
    - "Поля uid/gid и capabilities на 0"
    - "Имя файла"
    - "DNS"
    - "Стек"
  answer: 0
  explanation: Нулевые uid и полные capabilities = root.
- question: Как modprobe_path даёт выполнение команды?
  options:
    - "Ядро запускает его от root при неизвестном формате файла"
    - "Он шифрует диск"
    - "Он логирует"
    - "Он монтирует"
  answer: 0
  explanation: call_usermodehelper запускает modprobe_path от имени root.
- question: Что нужно кроме записи для data-only?
  options:
    - "Обход KASLR (знать адрес цели)"
    - "Больше памяти"
    - "Второй процессор"
    - "Сеть"
  answer: 0
  explanation: Без базы ядра адрес cred/modprobe_path неизвестен.
- question: Когда data-only не подходит?
  options:
    - "Когда есть только read или control-flow примитив"
    - "Когда ядро свежее"
    - "Когда включён ASLR"
    - "Когда мало RAM"
  answer: 0
  explanation: Нужна именно запись по нужному адресу.
```

## Куда дальше

Дальше — **обход защит ядра**: KASLR и KPTI. А пока запомни: **data-only меняет
данные (cred, modprobe_path) и потому переживает CFI/CET, которые смотрят только
на поток управления**.

## Где пригодится

- Повышение привилегий в ядре на системах с CFI.
- Побег из контейнера.
- Разбор современных kernel-эксплойтов.
