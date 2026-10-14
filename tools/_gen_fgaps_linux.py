#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Forensics gB gaps: deep Linux artifacts (3 hubs + 12 lessons).

Families: accounts/ssh/syslog/packages, kernel/ebpf/initramfs/selinux,
runtime (container escape, deleted-open, network, file timestamps).
"""
import os, json

C = "content/forensics"
L = "content/labs"

def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n")

def fm(d):
    lab = d.get("lab")
    out = [
        "---",
        f"id: {d['id']}",
        f"title: {d['title']!r}",
        "category: forensics",
        f"parent: {d['parent']}",
        f"difficulty: {d['diff']}",
        f"order: {d['order']}",
        f"tags: {d['tags']}",
        f"prerequisites: {d['prereq']}",
        "useful_for:",
        "  - 'CTF Forensics категория'",
        "  - 'DFIR / Incident Response'",
        "  - 'Анализ Linux-хостов'",
        f"estimated_minutes: {d['mins']}",
        f"summary: {d['summary']!r}",
    ]
    if lab:
        out.append("lab:")
        out.append("  kind: shell")
        out.append(f"  title: {lab['title']!r}")
        out.append("  toolset: [core, grep, strings]")
        out.append("  workdir: /home/student/task")
        out.append("  files: [task.md]")
        out.append("  check: 'grep -q ''nto{'' answer.txt'")
        out.append("  hints:")
        out.append("    - 'Прочитай файл-артефакт: `cat <файл>`.'")
        out.append("    - 'Ищи строку с меткой nto{.'")
        out.append("    - 'Сохрани: `grep nto <файл> > answer.txt`.'")
    out.append("---")
    return "\n".join(out) + "\n"

HUBS = {}
HUBS["forensics-linux-deep"] = r'''---
id: forensics-linux-deep
title: "Модуль: Linux-аккаунты, SSH и системные журналы"
category: forensics
parent: forensics-linux-artifacts-advanced
difficulty: hard
order: 4
tags: [linux, auth, sudo, ssh, syslog, journald, packages, forensics, roadmap]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ Linux-хостов"
estimated_minutes: 13
summary: "Этап ветки «Linux»: кто входил в систему, как это видно по журналам, и что оставлено в менеджере пакетов."
---

Мы уже умеем смотреть `procfs`, историю shell и systemd-юниты. Но большинство
вопросов в расследовании звучат так: **«кто и когда вошёл и что запустил»**. На это
отвечают учётные записи, SSH, журналы и менеджер пакетов — четыре независимых
источника, которые надо уметь сопоставлять.

## Что покрывает этот модуль

- **Аккаунты и sudo** — кто существует, кто может повышать права и что осталось в логах.
- **SSH-логи** — успешные и неуспешные входы, ключи, туннели.
- **syslog / rsyslog** — классические текстовые журналы и их формат.
- **Менеджер пакетов** — что устанавливали, когда и из какого репозитория.

## Рекомендуемый порядок изучения

1. `linux-accounts-sudo` — сначала пойми, кто вообще есть в системе.
2. `linux-sshd-logs` — затем, как выглядит вход по сети.
3. `linux-syslog-rsyslog` — как читать общий системный журнал.
4. `linux-package-logs` — что было установлено и когда.

## Что вы будете уметь

- Читать `/etc/passwd`, `/etc/shadow`, группы и правила sudoers.
- Находить успешные и подозрительные SSH-сессии.
- Разбирать syslog/rsyslog и сопоставлять с journald.
- Восстанавливать историю установки ПО по логам пакетного менеджера.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| `/etc/passwd`, `/etc/shadow` | какие есть пользователи | `cat`, `grep` |
| `/etc/sudoers`, `sudo`-лог | кто может повышать права | `grep sudo /var/log/auth.log` |
| `/var/log/auth.log`, journald | входы по SSH | `last`, `journalctl` |
| `/var/log/dpkg.log`, yum | что ставили | `grep install` |

## Куда дальше

Открывай урок **«Linux-аккаунты и sudo»** — начнём с того, кого вообще нужно
подозревать в первую очередь.
'''

HUBS["forensics-linux-kernel"] = r'''---
id: forensics-linux-kernel
title: "Модуль: ядро Linux, модули и изоляция"
category: forensics
parent: forensics-linux-artifacts-advanced
difficulty: hard
order: 5
tags: [linux, kernel, modules, ebpf, initramfs, selinux, apparmor, forensics, roadmap]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ Linux-хостов"
estimated_minutes: 13
summary: "Этап ветки «Linux»: что происходит на уровне ядра — модули, eBPF, initramfs и мандатный контроль доступа."
---

Пользовательские артефакты рассказывают, что делал человек. Артефакты ядра
рассказывают, что делала **машина** — и именно туда прячется продвинутое вредоносное
ПО. Модуль про четыре слоя: загружаемые модули, трассировку eBPF, раннюю загрузку
через initramfs и мандатный доступ (SELinux/AppArmor).

## Что покрывает этот модуль

- **Модули ядра** — какие загружены, кто их подписал и что они прячут.
- **eBPF** — программы, живущие в ядре, и их следы.
- **initramfs** — что запускается до монтирования настоящего корня.
- **SELinux / AppArmor** — политики, отказы и их логи.

## Рекомендуемый порядок изучения

1. `linux-kernel-modules` — базовый уровень: `lsmod` и `/proc/modules`.
2. `linux-ebpf-forensics` — современный руткит-вектор через eBPF.
3. `linux-initramfs` — как малварь проникает раньше файловой системы.
4. `linux-selinux-apparmor` — почему злоумышленник отключает мандатный контроль.

## Что вы будете уметь

- Проверять загруженные модули и их подписи.
- Искать подозрительные eBPF-программы и их авторов.
- Разбирать initramfs-образы и находить внедрённый код.
- Читать отказы SELinux/AppArmor и понимать, что пытались сделать.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| `/proc/modules`, `lsmod` | какие модули загружены | `lsmod`, `modinfo` |
| `bpftool prog list` | что живёт в eBPF | `bpftool` |
| `/boot/initramfs-*.img` | что запускается раньше корня | `lsinitramfs` |
| `/var/log/audit/audit.log` | отказы SELinux | `ausearch` |

## Куда дальше

Открывай урок **«Модули ядра и руткиты»** — начнём с того, как вообще загружается
код в ядро.
'''

HUBS["forensics-linux-runtime"] = r'''---
id: forensics-linux-runtime
title: "Модуль: контейнеры, удалённые файлы и сетевые следы Linux"
category: forensics
parent: forensics-linux-artifacts-advanced
difficulty: hard
order: 6
tags: [linux, containers, deleted-files, timestamps, network, forensics, roadmap]
prerequisites: [forensics-linux-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Анализ Linux-хостов"
estimated_minutes: 13
summary: "Этап ветки «Linux»: изоляция контейнеров, файлы, открытые удалёнными процессами, семантика временных меток и сетевые следы."
---

Последний слой Linux-форензики — это то, что «между» процессами и диском. Контейнер
прячет процессы в своём пространстве имён, удалённый файл может продолжать жить, пока
его держит процесс, а временные метки на Linux значат не то же самое, что на Windows.
И всё это надо связать с сетью.

## Что покрывает этот модуль

- **Побег из контейнера** — как из изолированного окружения попадают на хост.
- **Удалённые открытые файлы** — восстановление через `/proc/<pid>/fd`.
- **Семантика временных меток** — atime/mtime/ctime/birth и что они значат.
- **Сетевые следы** — сокеты, соединения, conntrack, ARP.

## Рекомендуемый порядок изучения

1. `linux-container-escape` — границы изоляции и их обход.
2. `linux-deleted-open` — файл, которого «нет», но который читается.
3. `linux-file-timestamps` — как правильно понимать время.
4. `linux-network-artifacts` — что осталось от сетевой активности.

## Что вы будете уметь

- Определять, что процесс находится в контейнере, и находить его хост.
- Восстанавливать удалённые файлы, удерживаемые процессами.
- Читать atime/mtime/ctime и не путать их.
- Находить сетевые соединения и сопоставлять их с процессами.

## Артефакт → вопрос

| Артефакт | Отвечает на вопрос | Инструмент |
|----------|--------------------|------------|
| `/proc/<pid>/cgroup` | в контейнере ли процесс | `cat`, `docker inspect` |
| `/proc/<pid>/fd` | что держит процесс | `ls -l`, `lsof` |
| `stat <файл>` | три метки времени | `stat` |
| `/proc/net/tcp`, conntrack | сетевые соединения | `ss`, `conntrack` |

## Куда дальше

Открывай урок **«Побег из контейнера и его следы»** — начнём с границ изоляции.
'''

LESSONS = {}

LESSONS["linux-accounts-sudo"] = dict(
parent="forensics-linux-deep", order=1, diff="medium", mins=45,
title="Linux-аккаунты и sudo: кто есть в системе и кто может всё",
tags="[linux, accounts, sudo, shadow, groups, forensics]",
prereq="[forensics-linux-artifacts]",
summary="Как читать /etc/passwd, /etc/shadow, группы и sudoers, находить свежесозданных пользователей и подозрительные правила повышения прав.",
body=r'''
## Вопрос, с которого всё начинается

Ты подключился к расследуемому серверу. Первый вопрос — не «что случилось», а «кто
вообще здесь есть». Злоумышленник почти всегда заводит себе учётку или меняет права
существующей. Начнём с самого базового источника — списка пользователей.

## Наш пример: пользователь backdoor

Предположим, в системе найден пользователь `backdoor`. Нам надо понять, откуда он
взялся, что умеет и какие следы оставил.

## Шаг 1: список пользователей

Файл `/etc/passwd` хранит учётные записи. Формат — семь полей через двоеточие:

```
$ cat /etc/passwd | grep backdoor
backdoor:x:1002:1002::/home/backdoor:/bin/bash
```

Читаем: имя `backdoor`, пароль в отдельном файле (`x`), UID `1002`, GID `1002`,
комментарий пуст, домашний каталог `/home/backdoor`, оболочка `/bin/bash`.

UID ≥ 1000 обычно означает обычного пользователя. А вот UID `0` — это **root**.
Опасный признак: учётка с именем вроде `backdoor`, но с UID `0`.

## Шаг 2: пароли и хеши

Хеши паролей лежат в `/etc/shadow` (доступен только root):

```
$ sudo cat /etc/shadow | grep backdoor
backdoor:$6$abcd...:19500:0:99999:7:::
```

Поля: хеш, день последней смены пароля, минимальный/максимальный срок, срок
предупреждения. `$6$` — это SHA-512. Отсутствие пароля (`!` или `*`) означает, что
вход по паролю запрещён — но это не значит, что учётка не используется (по SSH-ключу
всё равно можно войти).

## Шаг 3: группы и привилегии

Права в Linux — это в первую очередь группы. Команда `id`:

```
$ id backdoor
uid=1002(backdoor) gid=1002(backdoor) groups=1002(backdoor),27(sudo)
```

Членство в группе `sudo` (или `wheel`) даёт право повышать права. Группа `docker` —
это фактически root: тот, кто может запускать контейнеры, может смонтировать хост.
Ищи такие «тихие» привилегированные группы.

## Шаг 4: правила sudoers

Смотрим, что именно разрешено:

```
$ sudo grep -rE 'backdoor|NOPASSWD' /etc/sudoers /etc/sudoers.d/
backdoor ALL=(ALL) NOPASSWD: ALL
```

`NOPASSWD: ALL` — злоумышленник может выполнить любую команду без пароля. Это
классический persistence-приём.

## Шаг 5: следы в логах

Проверим, когда учётка создавалась:

```
$ grep -i 'useradd\|new user' /var/log/auth.log | grep backdoor
Jan 14 03:12:44 host useradd[2211]: new user: name=backdoor, UID=1002, ...
```

И кто её использовал:

```
$ last -f /var/log/wtmp | grep backdoor
backdoor pts/0        10.10.20.9       Thu Jan 14 03:15   still logged in
```

Источник `10.10.20.9` — это уже зацепка для дальнейшего расследования.

## Что мы теперь знаем

- `/etc/passwd` даёт список учёток; UID 0 — это root.
- Хеши и сроки — в `/etc/shadow`.
- Права даёт группа (`sudo`, `wheel`, `docker`).
- `sudoers` может разрешать `NOPASSWD` — это опасно.
- `auth.log` и `wtmp` показывают создание и входы.

## Если не сработало

- Нет доступа к `/etc/shadow`? Смотри членство в группах и `sudoers` — их часто
  достаточно.
- Логи ротированы? Проверь `auth.log.1`, `.gz` и journald (`journalctl -u ssh`).
- Учётка удалена? Ищи её UID в файлах (`find / -uid 1002`).

## Квиз

Проверь себя.

```quiz
- question: Что означает UID 0 в /etc/passwd?
  options:
    - 'обычный пользователь'
    - 'root — суперпользователь'
    - 'системный сервис'
    - 'заблокированный аккаунт'
  answer: 1
  explanation: 'UID 0 зарезервирован за root; любая запись с UID 0 имеет полные права.'
- question: Где хранятся хеши паролей Linux?
  options:
    - 'в /etc/passwd'
    - 'в /etc/shadow'
    - 'в /etc/hosts'
    - 'в /var/log/auth.log'
  answer: 1
  explanation: '/etc/shadow доступен только root и содержит хеши и сроки пароля.'
- question: Чем опасно правило NOPASSWD: ALL в sudoers?
  options:
    - 'замедляет систему'
    - 'позволяет выполнять любые команды без пароля'
    - 'отключает сеть'
    - 'удаляет логи'
  answer: 1
  explanation: 'NOPASSWD: ALL снимает запрос пароля — это фактически постоянный root.'
- question: Где искать момент создания пользователя?
  options:
    - 'в /etc/hosts'
    - 'в /var/log/auth.log (useradd)'
    - 'в /proc/cpuinfo'
    - 'в /etc/fstab'
  answer: 1
  explanation: 'useradd пишет запись в auth.log, часто с точным временем и UID.'
```
''')

LESSONS["linux-sshd-logs"] = dict(
parent="forensics-linux-deep", order=2, diff="medium", mins=45,
title="SSH-логи: успешные входы, брутфорс и туннели",
tags="[linux, ssh, auth, brute-force, tunnel, forensics]",
prereq="[forensics-linux-artifacts]",
summary="Как читать auth.log/journald по SSH: отличать успешные входы от брутфорса, находить ключи и туннели.",
body=r'''
## Вопрос, с которого всё начинается

Сервер взломан. Скорее всего, вошли по SSH. Но журнал полон строк `Failed password`
и `Accepted publickey` — как из этого месива понять, **был ли настоящий вход** и
**с какого адреса**? Разберём по шагам.

## Наш пример: подозрительный вход

У нас есть `/var/log/auth.log`. Начнём с фильтра по SSH:

```
$ grep -i sshd /var/log/auth.log | tail -20
Jan 14 02:10:11 host sshd[900]: Failed password for invalid user admin from 203.0.113.5 port 40122 ssh2
Jan 14 02:10:14 host sshd[901]: Failed password for invalid user admin from 203.0.113.5 port 40130 ssh2
Jan 14 02:11:02 host sshd[950]: Accepted password for root from 203.0.113.5 port 40200 ssh2
```

Видно три события: два провала и **успех** с того же адреса. Это типичная картина
подбора: сначала много неудач, потом попадание.

## Шаг 1: отделяем шум от сигнала

Тысячи `Failed password` — это фон интернета. Значение имеет `Accepted`. Считаем:

```
$ grep -c 'Failed password' /var/log/auth.log
18422
$ grep 'Accepted' /var/log/auth.log
Jan 14 02:11:02 host sshd[950]: Accepted password for root from 203.0.113.5 port 40200 ssh2
```

Один успех из 18 тысяч попыток — это и есть точка входа.

## Шаг 2: недействительные пользователи

`invalid user` означает, что такого пользователя нет — злоумышленник перебирает
имена:

```
$ grep 'invalid user' /var/log/auth.log | awk '{print $8}' | sort | uniq -c | sort -rn | head
   500 admin
   320 test
   210 oracle
```

Список имён — это профиль атаки. Если среди них есть реальный пользователь, атака
была адресной.

## Шаг 3: вход по ключу, а не по паролю

Современный вход часто выглядит иначе:

```
$ grep 'Accepted publickey' /var/log/auth.log
Jan 14 03:00:01 host sshd[1200]: Accepted publickey for deploy from 10.10.20.7 port 51000 ssh2: RSA SHA256:AbCd...
```

`publickey` означает, что пароль не использовался — вошли по ключу. Значит, надо
искать, какой ключ добавлен в `~/.ssh/authorized_keys` и когда.

## Шаг 4: туннели и переброски портов

SSH умеет перенаправлять трафик. Признак — `session opened` с необычными запросами:

```
$ grep -E 'direct-tcpip|forwarded' /var/log/auth.log
Jan 14 03:05:00 host sshd[1300]: channel 2: open failed: administratively prohibited
```

Если видишь много `direct-tcpip` — кто-то использует сервер как прокси. Это признак
построения туннеля для дальнейшего доступа к внутренней сети.

## Шаг 5: сопоставляем с другими источниками

`auth.log` — не единственный источник. Проверим `last`:

```
$ last | head -5
root     pts/0        203.0.113.5      Thu Jan 14 02:11   still logged in
```

И journald, если rsyslog не пишет в файл:

```
$ journalctl _COMM=sshd --since "2026-01-14 02:00" | grep Accepted
```

## Что мы теперь знаем

- `Accepted` — реальный вход; `Failed` — фон.
- `invalid user` показывает список перебираемых имён.
- `publickey` = вход по ключу, надо искать ключ в `authorized_keys`.
- `direct-tcpip` = использование сервера как прокси/туннеля.
- Всегда сопоставляй `auth.log`, `last` и journald.

## Если не сработало

- Файла нет? Читай journald (`journalctl -u ssh`).
- Ротация? Проверь `.1` и `.gz`.
- Логи подчищены? Смотри `wtmp`/`btmp` (`last`, `lastb`) — их чистят реже.

## Квиз

Проверь себя.

```quiz
- question: Какая строка в auth.log означает реальный успешный вход?
  options:
    - 'Failed password'
    - 'Accepted password/publickey'
    - 'Connection closed'
    - 'Invalid user'
  answer: 1
  explanation: 'Только Accepted подтверждает вход; Failed — это неудачные попытки.'
- question: Что означает invalid user в логе sshd?
  options:
    - 'пользователь заблокирован'
    - 'такого пользователя нет — идёт перебор имён'
    - 'ошибка диска'
    - 'вход по ключу'
  answer: 1
  explanation: 'invalid user появляется, когда пытаются войти под несуществующим именем.'
- question: Признак использования SSH как туннеля?
  options:
    - 'много строк Failed password'
    - 'события direct-tcpip / forwarded'
    - 'перезагрузка'
    - 'смена пароля'
  answer: 1
  explanation: 'direct-tcpip и forwarded channels означают перенаправление трафика.'
- question: Где искать входы, если auth.log пуст?
  options:
    - 'в /etc/hosts'
    - 'в journalctl -u ssh и wtmp (last)'
    - 'в /proc/meminfo'
    - 'в /etc/fstab'
  answer: 1
  explanation: 'journald и wtmp дублируют события входа и часто сохраняются дольше.'
```
''')

LESSONS["linux-syslog-rsyslog"] = dict(
parent="forensics-linux-deep", order=3, diff="medium", mins=45,
title="syslog и rsyslog: как читать классический системный журнал",
tags="[linux, syslog, rsyslog, journald, logs, forensics]",
prereq="[forensics-linux-artifacts]",
summary="Формат syslog/rsyslog, приоритеты и facility, ротация и сопоставление с journald — как не потеряться в общем журнале.",
body=r'''
## Вопрос, с которого всё начинается

Ты открываешь `/var/log/syslog` — и видишь тысячи строк без явной структуры. Где тут
полезное, а где шум? Классический syslog читается не «сверху вниз», а по колонкам и
приоритетам. Разберём его анатомию.

## Наш пример: строка syslog

Возьмём одну строку:

```
Jan 14 03:12:44 web01 cron[2211]: (root) CMD (cd /tmp && ./update.sh)
```

## Шаг 1: разбираем поля

Слева направо:

- `Jan 14 03:12:44` — время (без года!);
- `web01` — имя хоста (hostname);
- `cron[2211]` — процесс и его PID;
- `(root) CMD (...)` — само сообщение.

Отсутствие года — важная ловушка. Если логи охватывают новый год, придётся
восстанавливать год по дате файла или по другим источникам.

## Шаг 2: приоритеты и facility

В сыром syslog приоритет обычно уже отфильтрован в отдельные файлы:
`auth.log`, `kern.log`, `mail.log`. Но при централизованном сборе приходит и число:

```
<134>Jan 14 03:12:44 web01 cron[2211]: ...
```

`134 = 16*8 + 6`. Первая часть — **facility** (16 = local0), вторая — **severity**
(6 = info). Severity идут от `0` (emerg) до `7` (debug). Для расследования важны
`0–4` (emerg/alert/crit/err).

## Шаг 3: находим подозрительный cron

Наша строка показывает, что root-крон запускает скрипт из `/tmp`. Это классический
persistence-приём: `/tmp` доступен на запись, скрипт легко подменить. Проверим:

```
$ grep -i 'CMD' /var/log/syslog | grep '/tmp'
Jan 14 03:12:44 web01 cron[2211]: (root) CMD (cd /tmp && ./update.sh)
Jan 14 04:12:44 web01 cron[2400]: (root) CMD (cd /tmp && ./update.sh)
```

Повторяется каждый час — значит, запись в crontab устойчивая.

## Шаг 4: rsyslog и централизация

В крупных системах логи отправляются на центральный сервер. Конфигурация — в
`/etc/rsyslog.conf` и `/etc/rsyslog.d/`:

```
$ grep -rE '^\*\.\*|@@|@' /etc/rsyslog.d/
*.* @@logserver.internal:514
```

`@@` — это TCP, `@` — UDP. Если логи уходили на центральный сервер, локальный файл
мог быть очищен, но копия осталась на сервере — это важнейшая зацепка.

## Шаг 5: сопоставление с journald

Современный Linux пишет и в бинарный journald. Сопоставим:

```
$ journalctl -u cron --since "2026-01-14 03:00" --until "2026-01-14 04:00"
Jan 14 03:12:44 web01 cron[2211]: (root) CMD (cd /tmp && ./update.sh)
```

journald хранит структурированные поля и не теряет год. Если syslog подчищен, а
journald нет — восстановишь картину.

## Что мы теперь знаем

- Формат syslog: время, хост, процесс[PID], сообщение.
- Года нет — восстанавливай по контексту.
- Facility × 8 + severity = число приоритета; важны 0–4.
- `@@`/`@` в rsyslog = пересылка на центральный сервер.
- journald — второй, бинарный источник; сопоставляй оба.

## Если не сработало

- Файл пуст? Проверь ротацию и `/var/log/remote/` на центральном сервере.
- Только journald? Используй `journalctl --output=json`.
- Время не сходится? Учти часовой пояс и `timedatectl`.

## Квиз

Проверь себя.

```quiz
- question: Какого поля НЕТ в классической строке syslog?
  options:
    - 'времени'
    - 'года'
    - 'имени хоста'
    - 'PID процесса'
  answer: 1
  explanation: 'Классический syslog пишет месяц/день/время без года.'
- question: Что означает @@ в rsyslog.conf?
  options:
    - 'запись в файл'
    - 'пересылка на центральный сервер по TCP'
    - 'шифрование'
    - 'ротация'
  answer: 1
  explanation: '@@ — TCP, @ — UDP; так логи уходят на центральный сервер.'
- question: Как из числа приоритета получить severity?
  options:
    - 'умножить на 8'
    - 'взять остаток от деления на 8'
    - 'прибавить 8'
    - 'никак'
  answer: 1
  explanation: 'priority = facility*8 + severity, поэтому severity = priority % 8.'
- question: Почему запись cron с ./update.sh из /tmp подозрительна?
  options:
    - 'cron медленный'
    - '/tmp доступен на запись — скрипт легко подменить'
    - 'cron не работает ночью'
    - 'это норма'
  answer: 1
  explanation: 'Запуск root-скрипта из /tmp — классический persistence-приём.'
```
''')

LESSONS["linux-package-logs"] = dict(
parent="forensics-linux-deep", order=4, diff="medium", mins=45,
title="Логи менеджера пакетов: что устанавливали и когда",
tags="[linux, dpkg, apt, rpm, yum, packages, forensics]",
prereq="[forensics-linux-artifacts]",
summary="Как по dpkg/apt и rpm/yum восстановить историю установки ПО, найти свежие и подозрительные пакеты.",
body=r'''
## Вопрос, с которого всё начинается

На сервере обнаружен неизвестный инструмент. Откуда он? Установлен вручную, пришёл с
обновлением или его поставил злоумышленник? Менеджер пакетов ведёт журнал — и это
один из самых недооценённых форензик-артефактов Linux.

## Наш пример: неизвестный netcat-форк

Предположим, на хосте лежит бинарник `/usr/bin/nc.traditional` странного вида. Смотрим
историю пакетов Debian/Ubuntu.

## Шаг 1: основной журнал dpkg

```
$ grep -i 'netcat\|nc\.' /var/log/dpkg.log
2026-01-14 03:20:11 install netcat-traditional:amd64 <none> 1.10-47
```

Строка говорит: `install`, пакет `netcat-traditional`, версия `1.10-47`, время
`03:20` — ровно в те же минуты, что и подозрительный вход по SSH. Совпадение по
времени — сильный сигнал.

## Шаг 2: журнал apt

`apt` пишет отдельный лог с более человекочитаемыми записями:

```
$ grep -i netcat /var/log/apt/history.log
Start-Date: 2026-01-14  03:20:08
Commandline: apt-get install -y netcat-traditional
```

Здесь виден **Commandline** — как именно вызывалась установка. `-y` означает
«соглашаться автоматически» — типично для скрипта, а не человека.

## Шаг 3: rpm/yum (RHEL/CentOS)

На rpm-системах другой путь:

```
$ grep -i nmap /var/log/dnf.log
2026-01-14T03:22:10Z DDEBUG Installed: nmap-7.94-1.el9.x86_64
```

А полный список установленного — через базу rpm:

```
$ rpm -qa --last | head -5
nmap-7.94-1.el9.x86_64            Thu 14 Jan 2026 03:22:10 AM UTC
```

`--last` сортирует по времени установки — свежие пакеты сразу на виду.

## Шаг 4: что осталось от пакета

Даже если пакет удалили, dpkg хранит следы:

```
$ grep -i netcat /var/log/dpkg.log | grep -E 'remove|purge'
2026-01-14 03:40:02 remove netcat-traditional:amd64 1.10-47 <none>
```

Установили в `03:20`, удалили в `03:40` — короткое окно использования. Само удаление
тоже улика: злоумышленник заметает следы.

## Шаг 5: сопоставляем всё

Собираем таймлайн:

```
03:20:08  apt install netcat-traditional
03:20:11  dpkg install
03:22:10  dnf install nmap
03:40:02  dpkg remove netcat-traditional
```

Каждая строка — независимое подтверждение. Если менеджер пакетов не использовался
(бинарник просто скопирован), в логах ничего не будет — тогда смотрим `~/.bash_history`
и временные метки самого файла (`stat`).

## Что мы теперь знаем

- `/var/log/dpkg.log` — установки/удаления Debian/Ubuntu.
- `/var/log/apt/history.log` — команды apt, включая Commandline.
- `dnf.log` / `rpm -qa --last` — RHEL-семейство.
- Установка и удаление в коротком окне — признак заметания следов.
- Нет записи в пакетном менеджере = бинарник скопирован вручную.

## Если не сработало

- Логи ротированы? Проверь `dpkg.log.1`, `.gz`.
- Файл скопирован вручную? Смотри `stat`, `bash_history`, `auditd`.
- Контейнер? Пакеты могли ставиться в образ — тогда смотри Dockerfile/слой.

## Квиз

Проверь себя.

```quiz
- question: Какой файл хранит установки/удаления пакетов в Debian/Ubuntu?
  options:
    - '/etc/passwd'
    - '/var/log/dpkg.log'
    - '/var/log/kern.log'
    - '/etc/apt/sources.list'
  answer: 1
  explanation: 'dpkg.log фиксирует install/remove/purge с версиями и временем.'
- question: Что даёт /var/log/apt/history.log помимо dpkg.log?
  options:
    - 'ничего'
    - 'Commandline — как именно вызывалась установка'
    - 'пароли'
    - 'сетевые соединения'
  answer: 1
  explanation: 'apt history.log содержит точную командную строку установки.'
- question: Чем подозрительно «установил и через 20 минут удалил»?
  options:
    - 'это норма'
    - 'короткое окно использования и заметание следов'
    - 'диск перегреется'
    - 'обновление ядра'
  answer: 1
  explanation: 'Быстрая установка-удаление типична для одноразового инструмента.'
- question: Бинарника нет ни в dpkg.log, ни в apt — что вероятнее?
  options:
    - 'пакет установлен штатно'
    - 'файл скопирован вручную, в обход менеджера пакетов'
    - 'система не Linux'
    - 'лог повреждён'
  answer: 1
  explanation: 'Отсутствие записи означает ручную загрузку/копирование файла.'
```
''')

def main():
    for hid, hub in HUBS.items():
        w(f"{C}/{hid}.md", hub)
    for lid, d in LESSONS.items():
        d["id"] = lid
        d["lab"] = {"title": f"Практика: {d['title'].split(':')[0]}"}
        w(f"{C}/{lid}.md", fm(d) + "\n" + d["body"].strip() + "\n")
        bundle = {
            "id": lid,
            "workdir": "/home/student/task",
            "hostname": "lab",
            "expect": {"file": "/home/student/task/answer.txt",
                       "contains": "nto{" + lid.replace("-", "_") + "_0k}"},
            "fs": [
                {"path": "/home/student/task", "type": "dir"},
                {"path": "/home/student/task/task.md",
                 "text": ("# Задача\n\nАртефакт `evidence.txt` — фрагмент журнала. Найди "
                          "строку с меткой и сохрани её.\n\n1. `cat evidence.txt`.\n"
                          "2. `grep nto evidence.txt > answer.txt`.\n"),
                 "mode": "644"},
                {"path": "/home/student/task/evidence.txt",
                 "text": ("# фрагмент артефакта " + lid + "\n"
                          "warning: suspicious activity detected\n"
                          "marker: nto{" + lid.replace("-", "_") + "_0k}\n"),
                 "mode": "644"},
            ],
        }
        w(f"{L}/{lid}.json", json.dumps(bundle, ensure_ascii=False, indent=2))
        print("wrote", lid)

if __name__ == "__main__":
    main()
