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

## Как устроен SELinux: метки вместо путей

Дискреционные права (rwx) привязаны к **путям и uid**. SELinux работает иначе — он
навешивает **метку** (label, контекст) на каждый объект и процесс. Формат контекста:

```
user:role:type:level
system_u:system_r:httpd_t:s0
```

- `user` — SELinux-пользователь (не путать с системным);
- `role` — роль (`object_r` для объектов, `system_r` для процессов);
- `type` — **главное**: тип объекта (`httpd_t`) и тип процесса — домен;
- `level` — уровень MLS/MCS (для изоляции, часто `s0`).

Правило простое: **домен процесса должен иметь право на тип объекта**. Веб-сервер с
доменом `httpd_t` не может писать в `shadow_t`, даже будучи root. Метку файла смотрят
так:

```
$ ls -Z /etc/shadow
system_u:object_r:shadow_t:s0 /etc/shadow
$ ps -eZ | grep nginx
system_u:system_r:httpd_t:s0 2211 nginx
```

`-Z` показывает контекст. Именно несовпадение домена и типа рождает отказ `avc: denied`.

## Разбор AVC-записи по полям

AVC — это структурированная запись. Разберём её целиком:

```
type=AVC msg=audit(1768300000.123:456): avc: denied { write } for
  pid=991 comm="nginx" path="/root/.ssh/id_rsa"
  scontext=system_u:system_r:httpd_t:s0
  tcontext=system_u:object_r:ssh_home_t:s0
  tclass=file permissive=0
```

| Поле | Значение |
|------|----------|
| `denied { write }` | какое право запрошено |
| `pid`/`comm` | кто пытался |
| `path` | к какому объекту |
| `scontext` | домен процесса-источника |
| `tcontext` | тип объекта-цели |
| `tclass` | класс объекта (file, dir, socket) |
| `permissive=0` | отказ **блокирующий** (0) или только логирование (1) |

Именно `permissive=0` отличает реальный запрет от «шума» в Permissive-режиме. При
расследовании фильтруй по `permissive=0`, чтобы видеть только реально заблокированные
действия.

## AppArmor: профили вместо меток

AppArmor проще SELinux: он привязывает **профиль** к программе и описывает пути, к
которым ей можно обращаться. Режимы:

- `enforce` — запрещает;
- `complain` — только логирует (аналог Permissive, тоже любим злоумышленниками).

```
$ sudo aa-status
apparmor module is loaded.
5 profiles are loaded.
4 profiles are in enforce mode.
1 profiles are in complain mode.
   /usr/sbin/nginx
```

Профили лежат в `/etc/apparmor.d/` как обычные текстовые файлы — их легко прочитать,
изменить и **удалить**. Отказ выглядит так:

```
audit: type=1400 audit(...): apparmor="DENIED" operation="open"
  profile="/usr/sbin/nginx" name="/root/.ssh/id_rsa" requested_mask="r" denied_mask="r"
```

`requested_mask`/`denied_mask` показывают, что именно запрашивалось и что запрещено.

## Таблица: SELinux против AppArmor

| Критерий | SELinux | AppArmor |
|----------|---------|----------|
| Модель | метки на объектах (type enforcement) | профили на пути |
| Сложность | высокая, много правил | ниже, путь-based |
| Лог отказов | `ausearch -m avc` / audit.log | journald / dmesg `apparmor=` |
| Режим логов | Permissive | complain |
| Включение | `getenforce`, `/sys/fs/selinux/enforce` | `aa-status` |
| Отключение атакующим | `setenforce 0` | `aa-teardown`, удаление профилей |
| Типовые дистрибутивы | RHEL, Fedora, CentOS | Ubuntu, Debian, SUSE |

Обе системы можно увидеть одновременно — например, Ubuntu с AppArmor и SELinux-модулем.

## Что искать при инциденте

1. **Режим сейчас**: `getenforce` / `aa-status`. Если `Permissive`/`complain` — спроси
   почему; это могло быть включено атакующим.
2. **Когда переключали**: `grep -i setenforce /var/log/audit/audit.log` и
   `journalctl | grep -i apparmor`.
3. **Пик отказов в окне атаки**: `ausearch -m avc -ts 03:00 -te 04:00` — множество
   `denied` от одного `comm` рисует портрет вредоносного процесса.
4. **Отключённые профили**: пустой `/etc/apparmor.d/` или файлы с `.disabled`.
5. **Изменения конфигов**: mtime `/etc/selinux/config`, `/etc/apparmor.d/` в окне атаки.

Отключение MAC — это **изменение состояния защиты**, а значит отдельная улика. Даже если
после отключения следов атаки не осталось, сам факт «защиту выключили в 03:12» говорит о
подготовке.

## Читаем правила SELinux: sesearch и seinfo

Отказ `avc: denied` — это симптом. Чтобы понять, **разрешено** ли действие в принципе,
смотрят политику. `sesearch` отвечает на вопрос «есть ли правило allow»:

```
$ sesearch -A -s httpd_t -t shadow_t -c file
(пусто — правила нет)
$ sesearch -A -s httpd_t -t httpd_sys_content_t -c file | head -2
allow httpd_t httpd_sys_content_t:file { read getattr open };
```

Пустой вывод = правило запрета отсутствует, действие невозможно. Есть вывод = показаны
разрешённые права. `seinfo` даёт обзор:

```
$ seinfo -t | head
Types: 5123
   httpd_t
   shadow_t
```

Если в окне атаки политику **дописывали** (`semanage`, `semodule -i`), это меняет
поверхность доступа — проверь mtime `/etc/selinux/` и историю `semodule`.

## AppArmor: где искать изменения профилей

Профили — обычные файлы, и атакующий может их править или удалять:

```
$ ls -la /etc/apparmor.d/ | head
-rw-r--r-- 1 root root 3.2K ... usr.sbin.nginx
drwxr-xr-x ... abstractions
$ sudo aa-status | grep -i complain
1 profiles are in complain mode.
   /usr/sbin/nginx
```

`complain`-режим снимает запреты, но оставляет логи. Если профиль из `enforce` перевели
в `complain` перед атакой — в журнале будет `apparmor="AUDIT"` вместо `"DENIED"`, а в
`/etc/apparmor.d/` появится `.disabled`-суффикс или файл пропадёт.

## Различия в поведении: когда MAC реально спасает

- **SELinux** спасает, когда процесс уже root, но домен ограничен (веб-сервер не пишет в
  `/etc/shadow`).
- **AppArmor** спасает, когда программа обращается к пути вне профиля (nginx не читает
  `~/.ssh`).
- **Оба** бесполезны, если атакующий сначала отключил защиту (`setenforce 0`,
  `aa-teardown`) — тогда спасает только лог самого отключения.

## Ограничения и подводные камни

- **Permissive/complain-режим по умолчанию** в некоторых дистрибутивах — «отказов нет» не
  значит «никто не пытался».
- **Логи ротируются** — `audit.log` может быть обрезан (`rotate`, `max_log_file`); старые
  AVC теряются, если не настроена пересылка на центральный сервер.
- **`dontaudit`** — политика может намеренно **не логировать** некоторые запреты, тогда
  отказ не появится в AVC.
- **Контексты неочевидны** — `scontext`/`tcontext` требуют знания типов; без `seinfo`/
  `sesearch` вывод читается как абракадабра.
- **Не всё блокируется** — SELinux защищает целостность, но не шифрование; украденные
  данные он не вернёт.

## Практический чеклист

1. `getenforce` / `aa-status` — текущий режим и список профилей.
2. `ausearch -m avc -ts <окно>` — отказы в окне атаки, фильтр по `permissive=0`.
3. `journalctl | grep -i apparmor` — отказы и смены режима AppArmor.
4. `grep -i setenforce /var/log/audit/audit.log` — попытки отключения.
5. mtime `/etc/selinux/`, `/etc/apparmor.d/` — изменения политики.
6. `sesearch`/`seinfo` — разбор непонятных контекстов.
7. Проверить, не переведены ли профили в `complain`/Permissive.

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
