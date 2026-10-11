---
id: hardware-uboot
title: "U-Boot глубоко: окружение, скрипты, образы и обход автозагрузки"
category: hardware
parent: hardware-bootloader
difficulty: medium
order: 1
tags: [uboot, bootargs, bootcmd, mkimage, tftp, fit, dtb, environment]
prerequisites: [hardware-bootloader, hardware-uart]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Пентест IoT: доступ и модификация"
  - "Реверс загрузчиков"
estimated_minutes: 45
summary: "U-Boot на практике: переменные окружения, скрипты, FIT-образы, загрузка по TFTP/USB, правка bootargs и типовые сценарии доступа."
---

U-Boot (Das U-Boot) — самый популярный загрузчик встраиваемых Linux-устройств. Он гибок, скриптуем и почти всегда оставляет отладочную консоль. Для пентестера важно знать три вещи: как **прервать автозагрузку**, как **править окружение** (bootargs/bootcmd) и как **загружать свои образы**. Этот урок — практическое погружение.

## Окружение U-Boot

Окружение — набор переменных `key=value`, хранящихся в отдельной области флеша. Главные переменные:

| Переменная | Смысл |
|-----------|-------|
| `bootcmd` | команды автозагрузки |
| `bootargs` | аргументы ядра Linux |
| `ipaddr`/`serverip` | сетевые настройки |
| `baudrate` | скорость консоли |
| `bootdelay` | пауза перед автозагрузкой |
| `loadaddr` | адрес загрузки в RAM |

```text
=> printenv
bootdelay=1
baudrate=115200
bootcmd=sf probe 0; sf read 0x80000000 0x100000 0x400000; bootm 0x80000000
bootargs=console=ttyS0,115200 root=/dev/mtdblock4 rw
ipaddr=192.168.1.1
```

`bootdelay=0` означает, что прервать загрузку сложно (надо успеть нажать клавишу или замкнуть флеш). Иногда помогает удерживать клавишу до включения.

## Правка окружения и автозагрузки

```text
=> setenv bootdelay 3          # дать больше времени
=> setenv bootargs 'console=ttyS0,115200 root=/dev/mtdblock4 rw init=/bin/sh'
=> saveenv                     # сохранить (если разрешено)
=> boot
```

Если `saveenv` защищён, правка действует только в текущей сессии. Для постоянного эффекта нужно либо снять защиту (bootloader lock), либо перепрошить область окружения программатором.

## Загрузка своих образов

U-Boot умеет грузить ядро и rootfs по сети, USB, TFTP:

```text
=> setenv ipaddr 192.168.1.50
=> setenv serverip 192.168.1.10
=> tftpboot 0x80000000 zImage
=> tftpboot 0x81000000 rootfs.cpio.gz
=> bootz 0x80000000 0x81000000:${filesize}
```

Для загрузки с USB: `usb start`, затем `fatload usb 0 0x80000000 zImage`. Для eMMC: `mmc dev 0`, `mmc read`. Это позволяет запустить собственное ядро/shell без перепрошивки.

## FIT-образы и mkimage

Современный U-Boot использует **FIT (Flattened Image Tree)** — контейнер с ядром, DTB и initramfs, подписанный опционально. Упаковка на хосте:

```bash
# Создать legacy-uImage
mkimage -A arm -O linux -T kernel -C none -a 0x80008000 -e 0x80008000 \
  -n "Linux" -d zImage uImage

# Посмотреть заголовок существующего образа
mkimage -l uImage
# Image Name:   Linux-5.4.0
# Created:      ...
# Image Type:   ARM Linux Kernel Image (uncompressed)
# Data Size:    ...
```

FIT собирают из `.its`-описания: `mkimage -f image.its image.itb`. Подпись FIT (RSA) — часть secure boot; без неё образ можно заменить своим.

## Разобранный пример: доступ через U-Boot и TFTP

```text
# 1. Прервать автозагрузку
Hit any key to stop autoboot: 0
=> 
# 2. Посмотреть сеть
=> printenv ipaddr serverip
# 3. Прочитать флеш в RAM
=> sf probe 0
=> sf read 0x80000000 0x0 0x800000
# 4. Отправить дамп на TFTP-сервер (192.168.1.10)
=> setenv ipaddr 192.168.1.50
=> tftpput 0x80000000 0x800000 fw.bin
# 5. Загрузить свой shell-образ
=> tftpboot 0x81000000 rescue.itb
=> bootm 0x81000000
```

На хосте: `sudo atftpd --daemon --port 69 /srv/tftp` и приём файла. Полученный дамп разбирают `binwalk` (см. `hardware-filesystems`).

## Восстановление окирпиченного устройства

Если устройство не грузится, но U-Boot жив, можно восстановить прошивку:

```text
=> tftpboot 0x80000000 recovery.bin
=> sf probe 0
=> sf erase 0x0 0x800000
=> sf write 0x80000000 0x0 ${filesize}
=> reset
```

Если U-Boot тоже повреждён, нужен внешний программатор (см. `hardware-flash-dumping`) или bootROM-режим (`hardware-bootrom`).

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `picocom`/`screen` | консоль |
| `mkimage` | упаковка образов |
| `atftpd`/`tftpd-hpa` | TFTP |
| `fw_printenv` | чтение env из ОС |
| `dumpimage` | разбор FIT |
| `uboot-envtools` | правка env |

## Частые ошибки и подводные камни

- **Неверный loadaddr**: образ грузится поверх ядра/скрипта → падение.
- **`bootargs` без `console=`**: теряете консоль и не видите загрузку.
- **`saveenv` в защищённую область**: ошибка записи, изменения не сохраняются.
- **Несовместимый DTB**: ядро стартует, но не находит периферию.
- **TFTP-таймауты**: проверьте `serverip`, маску, firewall.
- **FIT без подписи**: если secure boot включён, unsigned itb не загрузится.

## Скрипты и переменные: автоматизация

U-Boot поддерживает скрипты — последовательности команд, которые можно хранить в переменной или в отдельном файле-образе (`mkimage -T script`). Это используется для сложной логики загрузки: проверка кнопки, выбор раздела A/B, обновление.

```text
=> setenv bootmenu 'if test ${bootslot} = a; then setenv root /dev/mmcblk0p2; else setenv root /dev/mmcblk0p3; fi; run bootcmd'
=> run bootmenu
```

Скрипт-образ загружают так:

```bash
mkimage -A arm -T script -C none -d boot.cmd boot.scr
```

```text
=> fatload mmc 0 0x80000000 boot.scr
=> source 0x80000000
```

Для пентестера скрипты важны тем, что часто содержат **пути к образам и разделам**, логику проверок и иногда «сервисные» ветки (например, если замкнута кнопка — загрузить recovery с TFTP без проверки). Чтение скрипта даёт полную картину загрузки.

## Разделы и MTD в U-Boot

U-Boot знает про таблицу разделов (`mtdparts`, GPT). Команды `mtdparts`/`mtd` позволяют работать с именованными разделами:

```text
=> mtdparts
=> mtd list
=> sf probe 0
=> sf read 0x80000000 0x100000 0x400000
=> sf erase 0x100000 0x400000
=> sf write 0x80000000 0x100000 0x400000
```

Зная раскладку (bootloader, env, kernel, rootfs, data), можно точно прочитать нужный раздел, не выгружая весь флеш. Это ускоряет дамп и снижает риск задеть критичные области при записи. Таблицу разделов также видно в логе ядра (`cat /proc/mtd`) и в device tree.

## Безопасность окружения и блокировки

Производители пытаются защитить загрузчик:

- **bootloader lock** — `saveenv` и команды записи запрещены без разблокировки.
- **пароль на консоль** — prompt требует пароль (`CONFIG_AUTOBOOT_KEYED`).
- **подпись FIT** — образы проверяются по RSA-ключу.
- **write-protect флеша** — область загрузчика защищена аппаратно (WP# пин, lock bits).

Обход этих мер: чтение флеша программатором (если WP не аппаратный), поиск пароля в прошивке, использование отладочных режимов, fault injection на проверке пароля. Если SPI не защищён физически, программные блокировки можно обойти, перезаписав флеш напрямую.

## Диагностика проблем загрузки

Наиболее частые ошибки и что они значат:

- `Wrong Image Format for bootm command` — образ не в формате U-Boot.
- `Bad Magic Number` — нет валидного заголовка uImage/FIT.
- `Unable to read the environment` — повреждена/пустая область env; загрузчик использует дефолт.
- `CRC error` — битые данные при загрузке по сети/флешу.
- `Error: invalid dtb` — несовместимый device tree.

Порядок действий: `printenv` → проверить `bootcmd`/`bootargs` → `mmc list`/`sf probe` → прочитать образ в память и `iminfo` (проверка заголовка) → только потом грузить. Для восстановления окружения при повреждённой env можно задать `bootargs` вручную и загрузиться, а затем перезаписать env из ОС (`fw_setenv`) или из загрузчика.

## U-Boot и USB-загрузка

Помимо сети и флеша, U-Boot умеет грузиться с USB — это удобно, когда TFTP недоступен, а UART есть:

```text
=> usb start
=> usb tree
=> fatload usb 0:1 0x80000000 zImage
=> fatload usb 0:1 0x81000000 rootfs.cpio.gz
=> bootz 0x80000000 0x81000000:${filesize}
```

Подготовьте флешку с FAT-разделом, положите ядро/initramfs и device tree. Так можно запустить спасательную систему и получить доступ к флешу устройства изнутри, не выпаивая чип. Если U-Boot не поддерживает USB (нет драйвера хост-контроллера), остаются TFTP и UART (медленный `loady`/`loadx` по протоколу X/YMODEM).

## Резервное окружение и восстановление env

Окружение часто хранится в двух копиях (primary и redundant) с CRC. Если основная копия повреждена, U-Boot использует резервную или дефолт. При разборе дампа ищите обе копии по строкам `bootcmd=`/`bootargs=` — в резервной могут сохраниться старые (иногда более «открытые») настройки, включая отладочные флаги. Восстановить env можно командами `env default -a` (сброс к дефолту), `env import -t` (импорт из текста) или перезаписью раздела из ОС через `fw_setenv`. Перед сбросом сохраните текущий env: он содержит уникальные для устройства параметры (MAC, серийный номер), без которых возможны проблемы с сетью.

## Что дальше / решение

- Нужен обзор загрузчиков → `hardware-bootloader`.
- Нужен bootROM/DFU → `hardware-bootrom`.
- Нужен Secure Boot → `hardware-secure-boot`.
- Нужен разбор дампа → `hardware-filesystems`.

## Квиз

```quiz
- question: "Какая переменная U-Boot задаёт аргументы ядра Linux?"
  options:
    - "bootcmd"
    - "bootargs"
    - "loadaddr"
    - "baudrate"
  answer: 1
  explanation: "bootargs передаются ядру как командная строка."
- question: "Что делает tftpput?"
  options:
    - "Принимает файл по TFTP"
    - "Отправляет содержимое RAM по TFTP"
    - "Стирает флеш"
    - "Печатает окружение"
  answer: 1
  explanation: "tftpput выгружает память на TFTP-сервер."
- question: "Чем упаковывают legacy-uImage?"
  options:
    - "mkimage"
    - "binwalk"
    - "dd"
    - "tar"
  answer: 0
  explanation: "mkimage создаёт образ с U-Boot-заголовком."
- question: "Что такое FIT-образ?"
  options:
    - "Файловая система"
    - "Контейнер с ядром/DTB/initramfs (возможно подписанный)"
    - "Раздел NAND"
    - "Переменная окружения"
  answer: 1
  explanation: "FIT объединяет компоненты загрузки."
- question: "Как восстановить устройство, если U-Boot жив?"
  options:
    - "Выпаять флеш"
    - "Загрузить recovery-образ по TFTP и записать во флеш"
    - "Заменить CPU"
    - "Сбросить TPM"
  answer: 1
  explanation: "U-Boot позволяет стереть и записать флеш."
```

## Где пригодится

- **CTF:** Hardware с U-Boot-консолью.
- **Пентест IoT:** доступ, дамп и модификация прошивки.
- **Реверс:** разбор загрузочной цепочки.
- **Работа:** восстановление устройств, обновления.
- **Дальше по дереву:** `hardware-bootloader`, `hardware-bootrom`.
