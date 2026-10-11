---
id: forensics-firmware
title: "Форензика прошивок и IoT"
category: forensics
parent: forensics-containers
difficulty: hard
order: 1
tags: [firmware, iot, embedded, ubi, squashfs, binwalk, forensics]
prerequisites: [forensics-containers, forensics-file-magic]
useful_for:
  - "CTF Forensics категория"
  - "IoT/embedded DFIR"
  - "Анализ устройств"
estimated_minutes: 55
summary: "Разбор прошивок и IoT-устройств: извлечение из flash, распаковка образов (squashfs/UBI/cramfs/JFFS2), анализ скриптов запуска, конфигов, ключей и секретов."
---
Прошивка (firmware) — это ПО устройства, хранящееся во flash-памяти: ядро, файловая система, конфиги, ключи, скрипты. Форензика прошивок и IoT отвечает на вопросы: что за устройство, какие секреты в нём, как оно может быть скомпрометировано. Этот урок — про извлечение прошивки, распаковку образов (squashfs/UBI/cramfs/JFFS2) и анализ содержимого.

## Получение прошивки

| Источник | Метод |
|----------|-------|
| Файл обновления | скачать с сайта вендора |
| Flash-чип (SPI) | `flashrom`, программатор (CH341A) |
| UART/JTAG | доступ к консоли/памяти |
| Обновление по сети | перехват/скачивание |
| Образ устройства | извлечение из дампа |

```bash
# чтение SPI-flash программатором
$ flashrom -p ch341a_spi -r firmware.bin
# определить тип и энтропию
$ binwalk firmware.bin
$ file firmware.bin
```

## binwalk: разведка и распаковка

```bash
$ binwalk firmware.bin
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             uImage header
64            0x40            LZMA compressed data
1048576       0x100000        Squashfs filesystem, little endian, version 4.0
6291456       0x600000        JFFS2 filesystem
# извлечь всё рекурсивно
$ binwalk -e -M firmware.bin -C out/
# только энтропия (найти сжатое/шифрованное)
$ binwalk -E firmware.bin
```

## Форматы ФС прошивок

| ФС | Тип | Инструмент |
|----|-----|-----------|
| SquashFS | read-only, сжатие | `unsquashfs` |
| UBI/UBIFS | NAND-flash | `ubireader`, `ubidump` |
| CramFS | read-only | `cramfsck`, `cramfs-tools` |
| JFFS2 | журналируемая NAND | `jefferson` |
| YAFFS | NAND | `unyaffs` |
| ext2/3/4 | обычная | `debugfs`, `mount` |

```bash
# SquashFS
$ unsquashfs -d out_sqsh part.sqsh
$ unsquashfs -l part.sqsh        # список
# JFFS2
$ jefferson -d out_jffs2 part.jffs2
# UBI/UBIFS
$ ubireader_extract_images firmware.bin -o out_ubi
$ ubireader_extract_files ubi.img -o out_ubifs
$ ubidump.py -l ubi.img
# CramFS
$ cramfsck -x out_cram part.cramfs
```

Для UBI: сначала извлечь образы томов (`ubireader_extract_images`), затем ФС (`ubireader_extract_files`).

## Анализ содержимого

```bash
# структура
$ ls out_sqsh/
bin/  etc/  lib/  sbin/  usr/  www/
# скрипты запуска и конфиги
$ cat out_sqsh/etc/init.d/rcS
$ cat out_sqsh/etc/passwd out_sqsh/etc/shadow
# ключи и сертификаты
$ find out_sqsh -name '*.pem' -o -name '*.key' -o -name '*.crt'
# секреты в конфигах
$ grep -riE 'password|passwd|secret|api_key|token' out_sqsh/etc/ out_sqsh/www/ | head
# прошивка/версия
$ grep -riE 'version|firmware' out_sqsh/etc/ | head
# бинарные ключи/строки
$ strings -n 8 out_sqsh/bin/busybox | grep -iE 'telnetd|httpd|password'
```

Типичные находки: hardcoded root-пароль, приватные ключи SSH/TLS, бэкдоры, уязвимые сервисы (telnetd, httpd), API-ключи.

## Файловая система и устройство

```bash
# смонтировать squashfs
$ sudo mount -t squashfs -o loop,ro part.sqsh /mnt/fw
# определить архитектуру бинарей
$ file out_sqsh/bin/busybox
$ readelf -h out_sqsh/bin/httpd | grep Machine
# найти setuid-бинари
$ find out_sqsh -perm -4000 -type f
```

## Разобранный пример

Дан образ прошивки роутера. Нужно найти креды и сервисы.

```bash
# 1. Разведка
$ binwalk firmware.bin | head
0    0x0     uImage header
64   0x40    LZMA compressed data
1M   0x100000 Squashfs filesystem
# 2. Извлечь
$ binwalk -e -M firmware.bin -C out/
$ unsquashfs -d rootfs out/_firmware.bin.extracted/*.sqsh 2>/dev/null || unsquashfs -d rootfs out/_firmware.bin.extracted/100000.sqsh
# 3. Креды
$ cat rootfs/etc/shadow
root:$1$abcd$...:0:0:...
$ grep -ri 'password' rootfs/etc/config/ rootfs/www/
# 4. Сервисы
$ grep -riE 'telnetd|httpd|dropbear' rootfs/etc/init.d/
# 5. Ключи
$ find rootfs -name '*.pem' -o -name 'id_rsa'
```

Итог: найден hardcoded root-хеш, telnetd включён, приватный ключ в прошивке — потенциальная компрометация.

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Разведка | `binwalk` |
| SquashFS | `unsquashfs` |
| JFFS2 | `jefferson` |
| UBI/UBIFS | `ubireader` |
| CramFS | `cramfsck` |
| SPI-flash | `flashrom` |
| Ключи | `find`/`grep`/`openssl` |

## Частые ошибки

- **Пропустить вложенные слои** — нужен `binwalk -e -M`.
- **Путать UBI-образ и UBIFS** — сначала образы томов, потом ФС.
- **Не смотреть скрипты запуска** — там запускаемые сервисы.
- **Игнорировать `shadow`/конфиги** — там креды.
- **Забывать про ключи** — приватные ключи в прошивке = компрометация всех устройств.
- **Не определять архитектуру** — важно для дальнейшего анализа бинарей.

## Что дальше / решение

Конвейер: `binwalk` (разведка) → `unsquashfs`/`jefferson`/`ubireader` (распаковка) → `find`/`grep` (секреты) → `strings`/`readelf` (бинари). Связка: `forensics-file-magic` (сигнатуры), `forensics-carving` (извлечение), `forensics-containers` (вложенность), `forensics-malware-yara` (YARA по прошивке).

## Анализ бинарей и эмуляция

После распаковки прошивки анализируйте исполняемые файлы (обычно ARM/MIPS):

```bash
# архитектура
$ readelf -h rootfs/bin/httpd | grep -E 'Machine|Class'
$ file rootfs/bin/* | sort | uniq -c | sort -rn | head
# строки: версии, пути, креды
$ strings -n 6 rootfs/bin/httpd | grep -iE 'password|/cgi|version'
# зависимости
$ readelf -d rootfs/bin/httpd | grep NEEDED
# декомпиляция
$ r2 -A rootfs/bin/httpd   # radare2
$ ghidraRun                # Ghidra (GUI)
# эмуляция отдельного бинаря (QEMU user-mode)
$ sudo apt install qemu-user-static
$ qemu-arm -L rootfs rootfs/bin/httpd
```

**QEMU user-mode** позволяет запускать бинари прошивки на хосте (с `-L` на корень прошивки) для динамического анализа. **Firmadyne/FirmAE** автоматизируют эмуляцию всей прошивки — запускают устройство в эмуляторе и дают сетевой доступ.

```bash
# FirmAE: автоматическая эмуляция прошивки
$ sudo ./run.sh -r router firmware.bin
```

## YARA по прошивке

```bash
$ yara -r rules/ rootfs/ | head
# поиск встроенных бэкдоров/ключей
$ grep -rE 'BEGIN (RSA|EC|OPENSSH) PRIVATE KEY' rootfs/
$ find rootfs -name '*.pem' -o -name 'id_*' | head
```

## Сводный чек-лист

1. `binwalk` — определить структуру и ФС.
2. `unsquashfs`/`jefferson`/`ubireader` — распаковать.
3. Скрипты запуска (`/etc/init.d`, `/etc/rc`) — какие сервисы.
4. `passwd`/`shadow`/конфиги — креды.
5. `find`/`grep` — ключи и секреты.
6. `readelf`/`r2`/`Ghidra` — анализ бинарей.
7. QEMU/FirmAE — динамическая эмуляция.
8. YARA — сигнатуры бэкдоров.

## Ограничения

- **Шифрованная/подписанная прошивка** — распаковка затруднена.
- **Проприетарные форматы** — могут требовать вендорских инструментов.
- **NAND/UBI** — сложнее, чем squashfs.
- **Эмуляция не всегда удаётся** (периферия, драйверы).
- **Архитектуры** (ARM/MIPS/PPC) — нужен соответствующий QEMU.

## Типы прошивок и загрузчики

Прошивка обычно состоит из загрузчика и образа ОС. Типы:

| Загрузчик | Признак |
|-----------|---------|
| U-Boot | `uImage`, `U-Boot` строки |
| CFE/Broadcom | `CFE` |
| Bootloader | `U-Boot SPL` |
| UEFI | `FV` (firmware volume) |

```bash
# определить загрузчик
$ binwalk firmware.bin | head
$ strings firmware.bin | grep -iE 'u-boot|U-Boot|cfe|linux version'
# uImage-заголовок: magic 0x27051956
$ xxd -l 64 firmware.bin
```

U-Boot uImage имеет 64-байтовый заголовок с типом, архитектурой, размером; после него — сжатое ядро/ФС.

## Инструменты: сводка

| Инструмент | Задача |
|-----------|--------|
| `binwalk` | разведка/распаковка |
| `unsquashfs` | SquashFS |
| `jefferson` | JFFS2 |
| `ubireader` | UBI/UBIFS |
| `flashrom` | чтение SPI |
| `r2`/`Ghidra` | бинари |
| `qemu-arm`/FirmAE | эмуляция |

## Практические приёмы

- **`binwalk -e -M`** — рекурсивно, не пропустите вложенное.
- **Скрипты `/etc/init.d`** — какие сервисы запускаются.
- **`shadow`/конфиги** — креды и API-ключи.
- **Приватные ключи** — компрометация всех устройств серии.
- **Эмуляция** (FirmAE) — для динамического анализа.
- **Сравнение версий** — `diff` двух прошивок покажет изменения.
- **Фиксируйте хеш** прошивки; не прошивайте своё устройство без нужды.

## Отчёт по прошивке

Укажите: модель/версию, как получена прошивка, структуру (ФС, загрузчик), найденные секреты (креды/ключи), запускаемые сервисы, потенциальные уязвимости. Для IoT-расследования добавьте сетевые сервисы (telnetd/httpd) и их риски.

## Квиз

```quiz
- question: "Какая утилита распаковывает SquashFS?"
  options:
    - "unsquashfs"
    - "cpio"
    - "jefferson"
    - "ubireader"
  answer: 0
- question: "Какой магией обладает UBI-раздел?"
  options:
    - "hsqs"
    - "UBI#"
    - "0x1985"
    - "PK"
  answer: 1
- question: "Где часто спрятан бэкдор в прошивке роутера?"
  options:
    - "в скриптах запуска (init.d/rcS)"
    - "в картинках"
    - "в шрифтах"
    - "в binwalk"
  answer: 0
- question: "Что нужно для запуска бинаря MIPS/ARM с хоста?"
  options:
    - "binwalk"
    - "QEMU (user-mode или полная эмуляция)"
    - "dd"
    - "exiftool"
  answer: 1
- question: "Что такое NVRAM в контексте роутеров?"
  options:
    - "файловая система"
    - "раздел/область с параметрами (в т.ч. паролями)"
    - "тип шифрования"
    - "протокол"
  answer: 1
```

## Где пригодится

- **CTF:** задачи с прошивками и IoT-устройствами.
- **IoT DFIR:** анализ скомпрометированных устройств.
- **Анализ малвари:** разбор встроенных бэкдоров.
- **Реверс-инжиниринг:** подготовка образов для динамики.
- **Судебная экспертиза:** извлечение конфигов и секретов.
