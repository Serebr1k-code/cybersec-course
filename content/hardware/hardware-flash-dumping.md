---
id: hardware-flash-dumping
title: "Дамп флеш-памяти: eMMC, NAND, NOR и обход bad-block"
category: hardware
parent: hardware-logic-analysis
difficulty: hard
order: 4
tags: [flash, emmc, nand, nor, dump, chip-off, isp, in-system, binwalk]
prerequisites: [hardware-spi, hardware-logic-analysis]
useful_for:
  - "CTF-задачи категории Hardware/Forensics"
  - "Пентест IoT"
  - "Аппаратная криминалистика"
estimated_minutes: 45
summary: "Как снять полный дамп с SPI-NOR, eMMC и NAND: in-system через SPI, eMMC по DAT0/CMD, chip-off, работа с bad-блоками и извлечение файловой системы."
---

Полный дамп флеш-памяти — цель большинства аппаратных исследований: в нём лежит прошивка, ключи, файлы и конфиги. Разные типы памяти требуют разных подходов: NOR легко читается по SPI, eMMC — по протоколу MMC, NAND требует учёта bad-блоков и ECC. Урок — практическое продолжение `hardware-spi`.

## Теория

| Тип | Интерфейс | Особенности | Инструмент |
|-----|-----------|-------------|------------|
| SPI-NOR | SPI (4–6 линий) | простая, байтовый доступ, до 256 МБ | CH341A, flashrom, SPI-адаптер |
| SPI-NAND | SPI | страничная, bad-блоки, ECC | flashrom (частично), программатор |
| eMMC | MMC (CLK/CMD/DAT0–7) | блочная, до десятков ГБ | eMMC-ридер, Easy-JTAG, mmc-utils |
| SD-карта | SD-протокол | как eMMC | ридер |
| NAND raw | параллельная шина | bad-блоки, ECC, OOB | программатор (NANDO, XGecu) |
| UFS | M-PHY | современные телефоны | специализированный |

Ключевые понятия:
- **In-system (ISP)** — чтение чипа прямо на плате, без выпаивания. Быстро, но другие компоненты мешают (нужен изолятор/питание).
- **Chip-off** — выпаивание чипа и чтение отдельно. Надёжнее, но риск повредить.
- **Bad blocks** — «плохие» блоки NAND, помеченные; при дампе их нужно учитывать.
- **OOB (spare area)** — служебная область NAND с ECC и метаданными.
- **Readout protection** — запрет чтения (RDP на STM32, security fuse).

## Инструменты и команды

- **flashrom** — чтение/запись SPI-NOR.
- **CH341A + clip** — самый доступный способ ISP-чтения.
- **spi-nor / mtd-utils** — работа с MTD в Linux.
- **eMMC-ридер / SD-переходник**.
- **binwalk, dd, strings, mtd-utils** — анализ дампа.
- **Easy-JTAG, XGecu T56** — программаторы среднего класса.

```bash
# --- SPI-NOR in-system через CH341A ---
flashrom -p ch341a_spi -r dump.bin          # чтение
flashrom -p ch341a_spi -v dump.bin          # верификация
flashrom -p ch341a_spi -r dump1.bin && \
flashrom -p ch341a_spi -r dump2.bin && \
cmp dump1.bin dump2.bin                     # два чтения должны совпасть

# --- eMMC в Linux (если есть /dev/mmcblk) ---
lsblk
dd if=/dev/mmcblk0 of=emmc.img bs=1M status=progress
# или через mmc-utils
mmc extcsd read /dev/mmcblk0

# --- анализ дампа ---
binwalk dump.bin
binwalk -e dump.bin                          # извлечь вложенные ФС
strings -n 8 dump.bin | less
file dump.bin
```

## Разобранный пример: дамп SPI-NOR роутера через clip

**Дано:** роутер, SPI-NOR 25Q128 (16 МБ), в плате. Есть CH341A и SOIC-8 clip.

**Шаг 1 — определить распиновку.** По даташиту SOIC-8 25Q128: 1=CS, 2=DO(MISO), 3=WP, 4=GND, 5=DI(MOSI), 6=CLK, 7=HOLD, 8=Vcc. Прикладываем clip, ориентируясь по метке-кружку на чипе.

**Шаг 2 — питание платы.** Часто ISP-чтение не работает без питания на плате (процессор держит линию). Подаём штатное питание роутера (не USB-программатора) и читаем.

**Шаг 3 — первое чтение.**

```bash
flashrom -p ch341a_spi -r dump1.bin
```

**Шаг 4 — верификация.** Читаем второй раз и сравниваем. Если `cmp` показывает различия — плохой контакт или помехи.

**Шаг 5 — анализ.** `binwalk dump.bin` показывает U-Boot, ядро, squashfs. Извлекаем ФС:

```bash
binwalk -e dump.bin
ls _dump.bin.extracted/
unsquashfs -d rootfs _dump.bin.extracted/*.squashfs
```

**Шаг 6 — если чип не читается.** Возможные причины: readout protection (для микроконтроллеров), чип под напряжением держит линии, clip плохо контачит. Варианты: снять чип (chip-off), применить fault injection для снятия RDP.

## Частые ошибки

- **Одно чтение без верификации.** Всегда читайте минимум дважды и сравнивайте. Единичная ошибка = «битый» дамп.
- **Питание от программатора на плате.** Может конфликтовать со штатным питанием. Пробуйте оба варианта: только программатор (снятый чип) или штатное питание (ISP).
- **Игнорирование bad-блоков NAND.** Прямой `dd` с raw NAND даст мусор в OOB и сдвиги. Нужен ECC-корректный ридер или разбор OOB.
- **Не тот размер чипа.** CH341A читает только по адресному пространству, которое «видит»; для >16 МБ нужен правильный размер/драйвер.
- **Перезапись без бэкапа.** Если после чтения планируете писать — сохраните оригинал минимум в двух местах.
- **Chip-off без навыка.** Выпаивание BGA/eMMC требует термофена/ИК-станции и опыта; легко оторвать пятаки.

## Теория: типы флеш-памяти

| Тип | Интерфейс | Особенности | Дамп |
|-----|-----------|-------------|------|
| SPI-NOR | SPI (SOIC-8) | простая, частая | ch341a/flashrom |
| NAND | parallel/SPI | bad blocks, ECC | NAND-ридер |
| eMMC | MMC | BGA, in-system | mmc-utils/ISP |
| eMMC (chip-off) | BGA | нужен реболлинг | программатор |

SPI-NOR (W25Q, MX25) — самая частая: 8 ног, читается клипом прямо на плате. NAND требует учёта bad-block и ECC. eMMC — либо in-system (через eMMC-адаптер), либо chip-off (снять чип).

## Инструменты и команды

```bash
# SPI-NOR через ch341a
flashrom -p ch341a_spi -r dump.bin
flashrom -p ch341a_spi -w modified.bin
# определение чипа
flashrom -p ch341a_spi --flash-name
# eMMC in-system (Linux)
ls /dev/mmcblk*
dd if=/dev/mmcblk0 of=emmc.bin bs=1M
# NAND
nanddump -f nand.bin /dev/mtd0
```

`flashrom -r` — read, `-w` — write, `-p` — программатор. Для in-system SPI используйте clip (SOIC-8) — но убедитесь, что другие устройства на шине не мешают (иногда нужно удерживать CPU в reset).

## Разобранный пример 2: дамп SPI-NOR клипом

1. Определяем чип по маркировке (W25Q128).
2. Подключаем clip к SOIC-8, ch341a к USB.
3. `flashrom -p ch341a_spi --flash-name` — проверяем определение.
4. `flashrom -p ch341a_spi -r dump.bin` — снимаем дамп.
5. `binwalk -Me dump.bin` — распаковываем.
6. Ищем `/etc/shadow`, ключи, строки.

## Защита

- Read-protection (если поддерживается).
- Шифрование прошивки и подпись.
- Secure boot.
- Физическая защита (заливка, сокрытие тест-поинтов).

## NAND: bad-blocks и ECC

NAND-память имеет bad-blocks (непригодные блоки) и требует ECC (коррекция ошибок). При дампе NAND учитывайте: (1) таблицу bad-blocks, (2) ECC-данные (OOB/spare area), (3) перемежение (interleaving). Без учёта этих параметров образ будет «битым» и не смонтируется. Инструменты: `nanddump`, NAND-ридеры, `ubireader` для UBI/UBIFS.

```bash
nanddump -f nand.bin -o /dev/mtd0
ubireader_extract_images nand.bin
ubireader_extract_files ubi.img
```

## Практика

Снимите дамп SPI-NOR через ch341a, распакуйте binwalk и найдите `/etc/shadow`. Затем для NAND-образа используйте `ubireader` и убедитесь, что файлы извлекаются с учётом bad-block. Сравните, чем отличается работа с NOR (простая) и NAND (сложнее из-за ECC).

## Сводка по дампу

| Носитель | Инструмент | Команда |
|----------|-----------|---------|
| SPI-NOR | ch341a | flashrom -p ch341a_spi -r d.bin |
| NAND | nanddump | nanddump -f n.bin /dev/mtd0 |
| eMMC | mmc-utils | dd if=/dev/mmcblk0 of=e.bin |
| UBI | ubireader | ubireader_extract_images n.bin |

Начните с SPI-NOR — самый простой носитель. Для NAND учитывайте bad-block/ECC.

## Квиз

```quiz
- question: "Почему дамп надо читать минимум дважды и сравнивать?"
  options:
    - "Чтобы убедиться в отсутствии ошибок чтения (плохой контакт/помехи)"
    - "Чтобы чип быстрее читался"
    - "Чтобы снять readout protection"
    - "Это требование производителя"
  answer: 0
- question: "Чем ISP-чтение отличается от chip-off?"
  options:
    - "ISP читает чип на плате, chip-off — после выпаивания"
    - "ISP работает только с eMMC"
    - "Chip-off быстрее и безопаснее"
    - "ISP не требует питания"
  answer: 0
- question: "Почему raw-дамп NAND нельзя просто смонтировать?"
  options:
    - "Из-за bad-блоков и служебной области OOB с ECC нужен корректный разбор"
    - "NAND всегда зашифрован"
    - "NAND не хранит данные"
    - "Потому что он слишком маленький"
  answer: 0
- question: "Что делать, если SPI-флеш не читается при подключённой плате?"
  options:
    - "Попробовать подать штатное питание, проверить контакт или снять чип"
    - "Подать 12 В на линию данных"
    - "Сразу заменить процессор"
    - "Считать чип неисправным и выбросить"
  answer: 0
- question: "Какой инструмент открытый и часто используется для SPI-NOR?"
  options:
    - "flashrom"
    - "Wireshark"
    - "Burp Suite"
    - "Metasploit"
  answer: 0
```

## Где пригодится

- **CTF:** Hardware/Forensics-задачи с дампом флеш и поиском флагов/ключей.
- **Пентест IoT:** извлечение прошивки и секретов из устройства.
- **Криминалистика:** снятие образов памяти встроенных устройств.
- **Работа:** восстановление данных, реверс прошивок, ремонт.
- **Дальше по дереву:** `hardware-iot-firmware-diff`, `hardware-secure-boot`, `hardware-uefi`.
