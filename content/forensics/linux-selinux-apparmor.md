---
id: linux-selinux-apparmor
title: 'SELinux и AppArmor: мандатный доступ и его отказы'
category: forensics
parent: forensics-linux-kernel
difficulty: medium
order: 4
tags: [linux, selinux, apparmor, mac, audit, forensics]
prerequisites: [forensics-linux-artifacts-advanced]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Что такое мандатный контроль доступа, как читать отказы SELinux/AppArmor в audit-логе и почему злоумышленник их отключает.'
lab:
  kind: shell
  title: 'Практика: SELinux и AppArmor'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Обычные права в Linux (rwx) — **дискреционные**: владелец сам решает, кому что можно.
Но есть второй, **мандатный** уровень (MAC): SELinux и AppArmor. Он может запретить
даже root. Для форензики это золото: каждый отказ — запись о том, что кто-то **пытался**
сделать. Разберёмся, как это читать.

## Наш пример: отказы в audit-логе

Начнём с того, включён ли MAC.

## Шаг 1: определяем режим

```
$ getenforce
Enforcing
$ cat /sys/module/apparmor/parameters/enabled
Y
```

`Enforcing` — SELinux активно запрещает. `Y` у AppArmor — он тоже включён. Бывает
`Permissive`: политика только **логирует**, но не мешает. Это любимый режим
злоумышленников: отказы видны, но атака проходит.

## Шаг 2: где отказы

SELinux пишет в audit-лог:

```
$ sudo ausearch -m avc -ts recent | head
time->Thu Jan 14 03:31:02 2026
type=AVC msg=audit(...): avc:  denied  { write } for  pid=991 comm="x" path="/etc/shadow" ...
```

`denied { write }` — процесс `x` (PID 991) пытался **записать** в `/etc/shadow`. Это
прямая улика вредоносной активности, пойманной политикой.

## Шаг 3: читаем AVC целиком

```
$ sudo ausearch -m avc -ts recent | grep -A2 'scontext'
scontext=system_u:system_r:init_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file
```

- `scontext` — контекст **источника** (процесса `init_t`);
- `tcontext` — контекст **цели** (`shadow_t` — файл паролей);
- `tclass` — тип объекта.

Сопоставляя контексты, понимаешь, кто и куда лез.

## Шаг 4: AppArmor

AppArmor проще — профили на путь. Отказы в `dmesg`/`journald`:

```
$ sudo journalctl -k | grep -i apparmor | tail
audit: type=1400 ... apparmor="DENIED" operation="open" profile="/usr/sbin/nginx"
name="/root/.ssh/id_rsa" pid=2211 comm="nginx"
```

Nginx пытался прочитать приватный ключ root — либо ошибка конфигурации, либо
компромисс веб-сервера.

## Шаг 5: как злоумышленник это обходит

Классика:

```
$ cat /sys/fs/selinux/enforce
0
```

`0` — SELinux переведён в Permissive. В логах будет `setenforce 0`:

```
$ grep -i setenforce /var/log/audit/audit.log
type=USER_CMD ... cmd="setenforce 0"
```

Аналогично AppArmor отключают через `aa-teardown` или удаление профилей из
`/etc/apparmor.d/`.

## Что мы теперь знаем

- SELinux/AppArmor — мандатный контроль, работает поверх обычных прав.
- `Enforcing` запрещает, `Permissive` только логирует.
- Отказы SELinux — в `ausearch -m avc`; читай scontext/tcontext/tclass.
- AppArmor логирует в journald с `apparmor="DENIED"`.
- `setenforce 0` / удаление профилей — способ обойти защиту, и это видно в логах.

## Если не сработало

- Нет auditd? Смотри journald и `/var/log/messages`.
- Логи пусты? Возможно, режим был выключен изначально — проверь конфиг.
- Контексты непонятны? `seinfo`, `sesearch` помогут разобрать правила.

## Квиз

Проверь себя.

```quiz
- question: Чем мандатный контроль (MAC) отличается от дискреционного?
  options:
    - 'ничем'
    - 'MAC может запретить даже root, независимо от прав владельца'
    - 'MAC только для Windows'
    - 'MAC ускоряет систему'
  answer: 1
  explanation: 'MAC накладывает политику поверх rwx и не зависит от владельца.'
- question: Что означает Permissive-режим SELinux?
  options:
    - 'всё запрещено'
    - 'политика логирует, но не блокирует'
    - 'SELinux выключен'
    - 'только для чтения'
  answer: 1
  explanation: 'Permissive пишет отказы, но не мешает действиям.'
- question: Где читать отказы SELinux?
  options:
    - 'в /etc/passwd'
    - 'в ausearch -m avc / audit.log'
    - 'в /proc/cpuinfo'
    - 'в /etc/fstab'
  answer: 1
  explanation: 'AVC-сообщения (Access Vector Cache) содержат все запреты SELinux.'
- question: Почему setenforce 0 подозрителен?
  options:
    - 'это ускоряет работу'
    - 'это отключает защиту SELinux перед атакой'
    - 'это включает сеть'
    - 'это норма при загрузке'
  answer: 1
  explanation: 'Перевод в Permissive снимает барьеры и фиксируется в audit-логе.'
```
