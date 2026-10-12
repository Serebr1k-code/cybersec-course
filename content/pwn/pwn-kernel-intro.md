---
id: pwn-kernel-intro
title: "Введение в kernel pwn: ret2usr, modprobe_path, msg_msg"
category: pwn
parent: pwn-mitigations
difficulty: hard
order: 2
tags: [kernel, ret2usr, modprobe-path, msg-msg, privesc, lkm]
prerequisites: [pwn-mitigations, pwn-rop, pwn-heap-basics]
useful_for:
  - "CTF Pwn категория"
  - "Linux kernel exploitation"
  - "Local privilege escalation"
estimated_minutes: 65
summary: "Знакомимся с эксплуатацией ядра Linux: разбираем уязвимый модуль, ret2usr, перезапись modprobe_path и heap-примитивы через msg_msg для повышения привилегий до root."
---

## Вопрос, с которого всё начинается

Ты — обычный пользователь на Linux-машине. У тебя нет root, но есть загруженный **модуль ядра** (`vuln.ko`), который создаёт устройство `/dev/vuln`. Через него можно читать и писать — и в модуле есть баг.

Ядро имеет доступ ко всей памяти и всем привилегиям. Если ты сможешь заставить его выполнить твой код, ты станешь root. Это **kernel pwn** — следующий уровень после userland.

## Наш пример: уязвимый модуль

```c
static struct file_operations fops = {
    .read  = vuln_read,
    .write = vuln_write,
    .ioctl = vuln_ioctl,
};
```

Модуль регистрирует эти функции — ядро будет вызывать их, когда мы работаем с `/dev/vuln`. Начнём с разведки.

## Шаг 1. Изучаем модуль

```bash
$ file vuln.ko
vuln.ko: ELF 64-bit LSB relocatable, x86-64 ...
$ modinfo vuln.ko
$ objdump -d vuln.ko | grep -A20 '<vuln_ioctl>:'
```

Ищем баг: неверные границы в `copy_from_user`/`copy_to_user`, отсутствие проверки индекса, `kfree` без зануления указателя (UAF). Типичный сценарий — модуль выделяет объект и освобождает его, но **оставляет указатель**, а через `ioctl` можно писать в объект.

## Шаг 2. Собираем окружение для отладки

Ядро отлаживают в QEMU с `gdb`:

```bash
$ qemu-system-x86_64 -m 256M -nographic \
    -kernel ./bzImage -initrd ./rootfs.cpio.gz \
    -append "console=ttyS0 kaslr oops=panic panic=1 nokaslr" \
    -s -S
```

Флаг `-s` открывает gdb-сервер на порту 1234, `-S` останавливает CPU до подключения отладчика. Подключаемся:

```bash
$ gdb ./vmlinux -ex 'target remote :1234'
```

`nokaslr` отключает рандомизацию ядра, чтобы адреса были фиксированы на время разработки. В реальном задании KASLR включён — об этом позже.

## Шаг 3. Определяем защиты

Прежде чем выбрать приём, узнай, что включено:

```bash
$ grep -oE "smep|smap" /proc/cpuinfo | sort -u
$ dmesg | grep -i "Kernel Offset"      # KASLR
$ zcat /proc/config.gz | grep -E "CONFIG_SLAB_FREELIST|CONFIG_RANDOMIZE_BASE"
```

| Защита | Что делает |
|---|---|
| KASLR | рандомизирует адреса ядра |
| SMEP | запрещает ядру исполнять userland-код |
| SMAP | запрещает ядру обращаться к userland-памяти |
| KPTI | изолирует таблицы страниц ядра и user |

Именно SMEP/SMAP определяют, какой приём вообще возможен.

## Шаг 4. Приём 1: ret2usr

Если **SMEP выключен**, можно вернуть управление на твой userland-код. Перезапиши указатель на функцию в структуре модуля так, чтобы он указывал на твою функцию, которая повышает привилегии:

```c
void escalate() {
    commit_creds(prepare_kernel_cred(NULL));
}
```

`prepare_kernel_cred(NULL)` создаёт «идеальные» привилегии (root), `commit_creds` применяет их текущему процессу. Дальше — триггерим вызов, и мы root.

При включённом SMEP этот путь закрыт: ядро не станет исполнять user-страницу. Тогда нужен ROP в ядре (`pwn-kernel-rop`).

## Шаг 5. Приём 2: modprobe_path

`modprobe_path` — ядерная переменная со строкой `/sbin/modprobe`. Когда ядру встречается файл с неизвестной «магией», оно вызывает `request_module`, а тот запускает программу по этому пути **от root**.

Если у нас есть произвольная запись, перезапишем `modprobe_path` на свой скрипт:

```bash
$ echo -e '#!/bin/sh\nchmod 777 /flag' > /tmp/x
$ chmod +x /tmp/x
# эксплойт: записать "/tmp/x" в modprobe_path
# затем execve файла с неизвестной сигнатурой -> request_module -> /tmp/x от root
```

Этот приём не требует ROP и работает **даже при включённых SMEP/SMAP** — нужна лишь произвольная запись. Часто это самый дешёвый путь.

## Шаг 6. Приём 3: msg_msg

`msg_msg` — структура сообщений System V IPC. Она размещается в SLUB-кэшах через `kmalloc`, и её размер и содержимое **контролируются** из userland. Это делает её удобным инструментом: освободив `msg_msg` и переиспользовав память другим объектом, получаешь перекрытие.

В UAF-задаче план такой:

```text
1) Определить размер объекта и SLUB-кэш.
2) Освободить объект (но указатель остаётся).
3) Переиспользовать память другим ядерным объектом (msg_msg/tty_struct/seq_operations).
4) Через UAF перезаписать указатель на функцию.
5) Триггернуть вызов: ret2usr (SMEP off), ROP (SMEP on) или modprobe_path.
```

Подробнее — в `pwn-kernel-heap`.

## Шаг 7. Стабилизация: привязка к CPU

Важная деталь: SLUB хранит свободные объекты в **per-CPU** freelist. Если освобождение и аллокация произойдут на разных ядрах, переиспользование не сработает. Привяжи процесс к одному CPU:

```c
sched_setaffinity(0, sizeof(mask), &mask);   // в маске установлен один бит
```

Это частая причина «эксплойт работает через раз». Плюс помогает «прогрев» кэша: перед ключевой операцией сделай несколько аллокаций/освобождений.

## Шаг 8. Отладка ядра

```text
(gdb) target remote :1234
(gdb) b commit_creds
(gdb) b vuln_ioctl
(gdb) p &modprobe_path
```

pwndbg/gef с kernel-поддержкой дают команды `kbase`, `slab`, `kmalloc`. Если ядро паникует, смотри `dmesg` в QEMU: `BUG: unable to handle kernel paging request` с адресом и регистрами подскажет, где ошибка. Логируй всё.

## Стратегия выбора приёма

Выбор приёма зависит от бага и защит:

- **SMEP/SMAP выключены** → простой ret2usr с `commit_creds`.
- **SMEP/SMAP включены, но есть произвольная запись** → `modprobe_path` (самый дешёвый).
- **Есть только контроль RIP** → kernel ROP с trampoline.
- **Баг — heap UAF** → переиспользование объектов (`seq_operations`, `msg_msg`, `pipe_buffer`).
- **Баг — гонка** → нужен `userfaultfd`/FUSE для расширения окна.

Начинай с самого дешёвого приёма, соответствующего примитиву, и усложняй только при необходимости. Так экономишь время и снижаешь риск паники.

## Отладка ядра и типичные сообщения

Отладка ведётся через QEMU с `-s -S` и gdb с символами из `vmlinux`. Полезно поставить `nokaslr` на время разработки, чтобы адреса были фиксированы, и только в конце проверить с KASLR. В gdb используй kernel-aware команды pwndbg (`kbase`, `slab`, `kmalloc`), ставь точки останова на функции модуля (`b vuln_ioctl`) и на ключевые ядерные функции (`b commit_creds`, `b native_write_cr4`). Если ядро паникует, смотри `dmesg` в QEMU: сообщение `BUG: unable to handle kernel paging request` с адресом и регистрами подскажет, где ошибка. Логируй всё — адреса, значения регистров, содержимое структур.

## На что смотреть дальше

- **Забыл про KASLR** — адреса ядра рандомизированы, нужна утечка.
- **SMEP/SMAP включены** — ret2usr не сработает, переходи на ROP или `modprobe_path`.
- **Неверный SLUB-кэш** — объект может не попасть в нужный кэш из-за размера.
- **Разные CPU** — переиспользование ломается; привязывайся к одному ядру.
- **Паника ядра** убивает систему — тестируй осторожно, в QEMU.

## Что мы теперь знаем

- Kernel pwn — эксплуатация ядра через уязвимый модуль; цель — root.
- SMEP/SMAP/KASLR определяют выбор приёма.
- ret2usr работает только при выключенном SMEP.
- modprobe_path — самый дешёвый приём при произвольной записи, обходит SMEP/SMAP.
- msg_msg даёт контролируемые объекты в kernel heap для UAF-перекрытий.
- Стабилизация требует привязки к CPU.

## Квиз

Проверь себя.

```quiz
- question: "Что обычно является целью kernel pwn?"
  options:
    - "Повышение привилегий до root"
    - "Отказ в обслуживании"
    - "Утечка cookies"
    - "Сканирование сети"
  answer: 0
  explanation: "Kernel pwn добивается root (LPE) через уязвимый модуль."
- question: "Что делает commit_creds(prepare_kernel_cred(0))?"
  options:
    - "Повышает привилегии текущего процесса до root"
    - "Отключает SMEP"
    - "Включает KASLR"
    - "Расширяет tcache"
  answer: 0
  explanation: "prepare_kernel_cred(0) даёт root-cred, commit_creds применяет его."
- question: "Что такое modprobe_path?"
  options:
    - "Строка в ядре с путём к modprobe (цель для перезаписи)"
    - "Файл /etc/passwd"
    - "Таблица GOT"
    - "Стек ядра"
  answer: 0
  explanation: "Перезапись modprobe_path на свой скрипт даёт выполнение от root."
- question: "Для чего используют msg_msg в kernel pwn?"
  options:
    - "Как контролируемый объект kmalloc для спрея/перекрытия"
    - "Для отключения KPTI"
    - "Для снятия canary"
    - "Для сканирования портов"
  answer: 0
  explanation: "msg_msg даёт контроль содержимого в kernel heap нужного размера."
- question: "Что мешает простому ret2usr на современных ядрах?"
  options:
    - "SMEP/SMAP (запрещают исполнение/доступ к userspace)"
    - "ASLR пользователя"
    - "tcache"
    - "canary"
  answer: 0
  explanation: "SMEP запрещает исполнять userspace-код из ring 0, а SMAP — обращаться к нему."
```

## Куда дальше

Мы продолжим heap-ветку в userland: `pwn-musl` разберёт аллокатор musl, а `pwn-canary-bypass` и `pwn-pie-bypass` — обход двух оставшихся митигаций. А пока главное: **уязвимый модуль ядра = потенциальный root; выбор между ret2usr, kernel ROP и modprobe_path диктуют SMEP/SMAP.**

## Где пригодится

- **CTF:** Pwn — kernel-задачи (LPE).
- **Bug bounty:** ядерные уязвимости.
- **Пентест:** локальное повышение привилегий.
- **Работа:** security research ядра.
