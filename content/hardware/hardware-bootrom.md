---
id: hardware-bootrom
title: "bootROM и режимы восстановления: DFU, USB download, mask ROM"
category: hardware
parent: hardware-bootloader
difficulty: hard
order: 2
tags: [bootrom, dfu, mask-rom, usb-download, recovery, rockusb, fastboot, edl]
prerequisites: [hardware-bootloader, hardware-usb]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Восстановление и модификация устройств"
  - "Пентест IoT и мобильных устройств"
estimated_minutes: 50
summary: "bootROM и режимы восстановления: DFU, USB download (Rockchip/Allwinner), Qualcomm EDL, fastboot — как войти и что можно сделать."
---

**bootROM** (mask ROM) — первый код, исполняемый SoC после сброса. Он зашит в кремний, неизменяем и умеет загружать следующий этап из разных источников: SPI/NAND/eMMC, а если их нет или нажата сервисная кнопка — по USB/UART. Этот «режим восстановления» — точка входа для восстановления «окирпиченных» устройств и мощный вектор атаки: часто bootROM не проверяет подпись, если secure boot не активирован.

## Что делает bootROM

- Инициализирует минимальную периферию (часы, DDR-контроллер, USB PHY).
- Пытается найти загрузочный носитель по приоритету (SPI, eMMC, SD, USB).
- Проверяет подпись первого этапа, **если** включён secure boot.
- Даёт режим **download** — приём образа по USB/UART.

Если носитель пуст или есть спец-условие (замкнутая кнопка, определённая комбинация), bootROM переходит в режим приёма образа.

## Ключевые режимы по вендорам

| SoC | Режим | Инструмент |
|-----|-------|-----------|
| Qualcomm | EDL (Emergency Download) | QFIL, `edl.py`, firehose |
| Rockchip | Mask ROM / Loader | `rkdeveloptool`, `upgrade_tool` |
| Allwinner | FEL | `sunxi-fel` |
| MediaTek | BROM / Preloader | `mtkclient` |
| Broadcom | CFE | TFTP |
| STM32 | DFU | `dfu-util` |
| Generic | Fastboot | `fastboot` |

Понимание вендора и режима — половина успеха. Определить SoC можно по маркировке на плате, по строке ядра (`/proc/cpuinfo`) или по VID/PID в режиме download.

## Qualcomm EDL

Режим **EDL (9008)** — сервисный режим Qualcomm. В нём устройство принимает образы (firehose programmer) по USB и может читать/писать разделы, включая boot, modemst, persist.

```bash
# Проверить, что устройство в EDL
lsusb | grep -i qualcomm   # VID 05c6, PID 9008
# Утилита edl (bkerler)
pip3 install edl
edl printgpt              # таблица разделов
edl r boot boot.img       # читать раздел
edl w boot new_boot.img   # записать
edl e boot                # стереть
```

Ключевой момент: если secure boot включён, firehose проверяет подпись и отказывает в записи неподписанного образа. Если выключен — можно залить что угодно.

## Rockchip Mask ROM

```bash
# Определить режим
lsusb | grep -i rockchip   # VID 2207, PID 110a/330c/...
# rkdeveloptool
rkdeveloptool ld            # загрузить loader
rkdeveloptool rl 0 0x800000 dump.bin   # читать флеш
rkdeveloptool wl 0x0 image.img         # записать
rkdeveloptool rd            # reset
```

Rockchip bootROM в Mask ROM режиме принимает **loader** (второй этап), который и делает основную работу. Loader обычно не подписан, что даёт полный доступ к флешу.

## Allwinner FEL

```bash
# FEL-режим: VID 1f3c, PID ffff
sunxi-fel ver
sunxi-fel read 0x0 0x100000 dump.bin
sunxi-fel write 0x0 new.bin
sunxi-fel exec 0x40000000
```

FEL умеет читать/писать DRAM и запускать код, что делает его удобным для восстановления и исследования.

## DFU и fastboot

**DFU** (Device Firmware Update) — стандартный USB-класс для прошивки:

```bash
dfu-util -l
dfu-util -d 0483:df11 -a 0 -D firmware.bin
dfu-util -d 0483:df11 -a 0 -U backup.bin
```

**Fastboot** — режим Android/embedded, позволяет прошивать разделы и загружать образы в RAM:

```bash
fastboot devices
fastboot flash boot boot.img
fastboot boot recovery.img
fastboot oem unlock
```

## Разобранный пример: восстановление окирпиченного роутера

```bash
# Устройство не грузится. Плата на Rockchip (RK3328).
# 1. Войти в Mask ROM: удерживая кнопку reset, подать питание.
lsusb | grep 2207
# Bus 001 Device 012: ID 2207:330c Fuzhou Rockchip Electronics
# 2. Загрузить loader
rkdeveloptool db rk3328_loader.bin
# 3. Прочитать текущий флеш (бэкап!)
rkdeveloptool rl 0 0x2000000 backup.img
# 4. Записать recovery-образ
rkdeveloptool wl 0x0 recovery.img
rkdeveloptool rd
# Устройство снова грузится
```

Тот же сценарий через EDL/FEL/DFU — с соответствующими утилитами.

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `edl`/QFIL | Qualcomm EDL |
| `rkdeveloptool` | Rockchip |
| `sunxi-fel` | Allwinner |
| `mtkclient` | MediaTek |
| `dfu-util` | DFU |
| `fastboot` | Android/embedded |
| `lsusb` | определение режима |

## Частые ошибки и подводные камни

- **Не тот loader**: несовместимый второй этап не запустится.
- **Secure boot включён**: запись неподписанного образа отклоняется — нужен обход или сервисный доступ.
- **Питание**: прерывание записи флеша может окончательно «убить» устройство.
- **Забыли бэкап**: сначала читать (`rl`/`r`/`-U`), потом писать.
- **Драйверы**: на Linux нужны udev-правила для доступа к USB-устройству.
- **Разные PID**: один SoC может показывать разные PID в разных режимах.

## MediaTek BROM и preloader

У MediaTek своя двухэтапная схема: **BROM** (bootROM) принимает **preloader**, который затем грузит основную систему. Режим BROM включается замыканием определённого тест-поинта или комбинацией кнопок, и по USB устройство определяется как MediaTek.

```bash
# mtkclient — работа с BROM/preloader
pip3 install mtkclient
mtk printgpt                  # таблица разделов
mtk r boot boot.img           # читать раздел
mtk w boot new_boot.img       # записать
mtk e userdata                # стереть
mtk payload                   # загрузить payload в BROM
```

Особенность MediaTek: BROM умеет принимать **payload** — код, исполняемый в контексте bootROM до загрузки системы. Через payload можно читать/писать флеш, обходить некоторые проверки и получать доступ к защищённым областям. Многие утилиты (mtkclient) построены именно на этом. Если secure boot (SBC/SLA) включён, часть операций блокируется, но чтение обычно остаётся доступным.

## Как определить SoC и режим

Прежде чем работать, нужно понять, что за платформа:

- **Маркировка на чипе** — самый надёжный способ (например, RK3328, MT7621, i.MX6).
- **VID/PID в режиме download** — `lsusb` показывает вендора (Qualcomm 05c6, Rockchip 2207, Allwinner 1f3c, MediaTek 0e8d).
- **Строка ядра** — если устройство частично грузится, `/proc/cpuinfo` и `dmesg` содержат SoC.
- **Device tree** — `/sys/firmware/devicetree` описывает модель.
- **Строки в прошивке** — `strings` по дампу находит упоминания SoC/loader.

Точное определение SoC критично: неверный loader/payload не запустится и может усугубить ситуацию. Всегда начинайте с идентификации и поиска официальной документации/утилит вендора.

## Правовые и практические ограничения

Режимы восстановления — это мощный инструмент, но его применение ограничено:

- **Своё устройство** — можно свободно (root, кастомные прошивки, восстановление).
- **Устройство клиента на пентесте** — только в рамках scope, с письменным согласием и пониманием, что запись во флеш может необратимо изменить устройство.
- **Чужое устройство** — неправомерный доступ; обход secure boot для «разблокировки» чужого гаджета — нарушение закона.

Практически всегда первый шаг — **бэкап** (полный дамп флеша), и только затем любые записи. Храните оригинальные образы: они позволяют откатиться и служат эталоном для сравнения. И помните: прерывание записи eMMC/NAND на питании может окончательно вывести устройство из строя.

## Безопасность режима восстановления

Производители понимают риск сервисных режимов и пытаются их ограничить:

- **Secure boot**: проверка подписи загружаемого образа, запись неподписанного отклоняется.
- **Fuse/blow OTP**: одноразовые биты, запрещающие загрузку в download-режиме.
- **Signed firehose/loader**: второй этап тоже проверяется.
- **Отключение USB-режима** в релизной прошивке.

Однако на практике эти меры часто неполны: fuse не запрограммированы, проверяется только первый этап, или остаётся уязвимость в самом bootROM (история знает множество таких CVE). Для защитника вывод простой: сервисный режим — это часть модели угроз, и его надо либо закрывать fuse-битами, либо считать, что при физическом доступе устройство будет скомпрометировано. Для атакующего — это первое, что стоит проверить при работе с железом.

## Что происходит на уровне USB в download-режиме

Технически режим download — это обычный USB-обмен vendor-specific протоколом. Хост отправляет команды, bootROM отвечает. Полезно снять этот трафик через `usbmon`/Wireshark: видно структуру команд, размеры блоков, последовательность handshake. Это помогает, когда официальная утилита не поддерживает ваш чип — можно понять протокол и обратиться напрямую. Для отладки используйте `lsusb -v`, чтобы увидеть дескрипторы устройства в режиме восстановления, и `tcpdump`/Wireshark с usbmon для разбора обмена. Многие open-source утилиты (rkdeveloptool, sunxi-tools, mtkclient, edl) выросли именно из такого реверса.

## Что дальше / решение

- Нужен обзор загрузчиков → `hardware-bootloader`.
- Нужен U-Boot → `hardware-uboot`.
- Нужен USB-анализ → `hardware-usb`.
- Нужен Secure Boot → `hardware-secure-boot`.

## Квиз

```quiz
- question: "Что такое bootROM?"
  options:
    - "Перезаписываемый загрузчик"
    - "Неизменяемый first-stage код в SoC"
    - "Раздел eMMC"
    - "USB-класс"
  answer: 1
  explanation: "bootROM зашит в кремний."
- question: "Какой режим у Qualcomm для восстановления?"
  options:
    - "FEL"
    - "EDL (9008)"
    - "Mask ROM"
    - "DFU"
  answer: 1
  explanation: "EDL — Emergency Download, VID 05c6 PID 9008."
- question: "Какая утилита работает с Rockchip Mask ROM?"
  options:
    - "sunxi-fel"
    - "rkdeveloptool"
    - "dfu-util"
    - "edl"
  answer: 1
  explanation: "rkdeveloptool читает/пишет флеш Rockchip."
- question: "Что нужно сделать ПЕРЕД записью образа?"
  options:
    - "Стереть флеш"
    - "Считать и сохранить текущий образ (бэкап)"
    - "Сбросить TPM"
    - "Обновить ядро"
  answer: 1
  explanation: "Бэкап — обязательный первый шаг."
- question: "Что произойдёт при включённом secure boot в режиме download?"
  options:
    - "Ничего не изменится"
    - "Запись неподписанного образа будет отклонена"
    - "Устройство сгорит"
    - "Флеш сотрётся"
  answer: 1
  explanation: "Проверка подписи блокирует неподписанные образы."
```

## Где пригодится

- **CTF:** Hardware-задачи с восстановлением/дампом SoC.
- **Пентест IoT:** доступ к флешу через сервисный режим.
- **Мобильные:** EDL/fastboot для Android.
- **Работа:** восстановление «окирпиченных» устройств.
- **Дальше по дереву:** `hardware-bootloader`, `hardware-uboot`, `hardware-usb`.
