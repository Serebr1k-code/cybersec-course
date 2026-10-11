---
id: hardware-filesystems
title: "Файловые системы прошивок: squashfs, JFFS2, UBIFS и CRAMFS"
category: hardware
parent: hardware-firmware-emulation
difficulty: medium
order: 1
tags: [firmware, squashfs, jffs2, ubifs, cramfs, binwalk, unsquashfs, filesystem]
prerequisites: [hardware-firmware-extract, hardware-spi]
useful_for:
  - "CTF-задачи категории Hardware/Forensics"
  - "Пентест IoT: разбор прошивок"
  - "Реверс встраиваемых Linux-систем"
estimated_minutes: 45
summary: "Как распознать и распаковать файловые системы внутри прошивки: squashfs, JFFS2, UBIFS/UBI, CRAMFS — инструменты, команды и разобранный пример."
---

Когда вы получили дамп флеш-памяти (SPI-NOR, NAND, eMMC) или скачали прошивку с сайта производителя, следующий шаг — вытащить из неё файловую систему. Именно в ФС лежат `/etc/passwd`, приватные ключи, скрипты инициализации, бинарники веб-интерфейса и бэкдоры. Промышленные встраиваемые системы используют несколько «нестандартных» ФС, которые не монтируются командой `mount` на обычном десктопе: **squashfs**, **JFFS2**, **UBIFS** и **CRAMFS**. Этот урок — про то, как каждую из них распознать и распаковать, и это этап-навигатор ветки: под ним лежат уроки по каждой ФС отдельно.

## Зачем разбирать файловую систему прошивки

Прошивка — это не монолитный бинарник, а контейнер: загрузчик + ядро + rootfs + разделы данных. Прикладная логика и секреты живут в rootfs:

- **Учётные данные**: `/etc/passwd`, `/etc/shadow`, хэши в `/etc/config`, базы sqlite с токенами.
- **Ключи**: SSH-хосты, приватные ключи TLS в `/etc/ssl/private`, сертификаты подписи обновлений.
- **Скрипты**: `init.d`, `rcS`, cron — показывают, какие сервисы стартуют и под каким пользователем.
- **Веб-приложение**: CGI-бинарники, шаблоны, JS — часто с уязвимостями (command injection в CGI).
- **Бэкдоры и отладочные учётки**: захардкоженные пароли, «сервисные» аккаунты, telnet-демоны.

Поэтому разбор ФС — центральный навык hardware-пентеста: он превращает «кусок флешки» в читаемый исходник устройства.

## Как ФС оказались внутри прошивки

Производитель собирает образ так: ядро (zImage/uImage) + rootfs. Для rootfs выбирают ФС под тип памяти:

| Тип памяти | Особенности | Типичная ФС |
|------------|-------------|-------------|
| SPI-NOR | Малый объём, байтовая запись, износ | squashfs (ro), JFFS2 (rw), CRAMFS |
| NAND | Большие блоки, bad-block, wear-leveling | UBIFS поверх UBI |
| eMMC/SD | Блочное устройство, контроллер | ext4, squashfs, F2FS |
| RAM | initramfs | cpio.gz |

Важно: **JFFS2 и UBIFS «сырые»** — их нельзя просто вырезать и смонтировать, потому что это журналируемые ФС для raw-flash, зависящие от геометрии чипа (erase size, page size, bad-block). Их надо разбирать специализированными инструментами, умеющими эмулировать NAND-контроллер.

## squashfs: самая частая rootfs

**SquashFS** — сжатая read-only ФС, доминирует в OpenWrt, роутерах, камерах, IoT. Сигнатура в hex: `hsqs` (`68 73 71 73`), в конце образа — `sqsh`. Внутри — блоки, сжатые gzip/xz/lzo/lz4/zstd.

```bash
# Найти смещение squashfs в дампе
binwalk firmware.bin | grep -i squashfs
# Пример вывода:
# 131072   0x20000   Squashfs filesystem, little endian, version 4.0, size: 6291456 bytes

# Вырезать по смещению и распаковать
dd if=firmware.bin of=rootfs.squashfs bs=1 skip=131072 count=6291456
unsquashfs -d rootfs/ rootfs.squashfs
# Если не указать size, binwalk -e сделает это сам:
binwalk -eM firmware.bin
```

`unsquashfs` из пакета `squashfs-tools` поддерживает все сжатия; для старых образов с LZMA нужен `unsquashfs-lzma` или патченая версия. Флаг `-stat` покажет список inode без распаковки.

## JFFS2: журналируемая ФС для NOR

**JFFS2** (Journalling Flash File System v2) — ФС для raw NOR/NAND без блочного слоя. Сигнатура: магическое число `0x1985` в каждом узле (`85 19` little-endian). Из-за журнала и сжатия по узлам JFFS2 нельзя просто смонтировать как образ — нужен `jefferson` или `mtd-utils`.

```bash
# Демонтировать JFFS2-образ
pip3 install jefferson
jefferson -d jffs2_out/ partition.jffs2

# Альтернатива через mtd-utils (нужен loop + mtdram)
sudo modprobe mtdram total_size=65536 erase_size=256
sudo modprobe mtdblock
sudo dd if=partition.jffs2 of=/dev/mtdblock0 bs=1
sudo mount -t jffs2 /dev/mtdblock0 /mnt/jffs2
```

`jefferson` сам определяет endianness и разбирает узлы; при ошибке «unknown compression» помогает `--no-clean` или обновление zlib/lzo.

## UBIFS и UBI-тома

**UBI** (Unsorted Block Images) — слой управления износом поверх NAND; **UBIFS** — ФС поверх UBI-томов. Сигнатура UBI: `UBI#` (`55 42 49 23`). Разбирается через `ubireader` (ubi_reader).

```bash
pip3 install ubi_reader
# Показать тома
ubireader_list_volumes image.ubi
# Извлечь все тома
ubireader_extract_images image.ubi
ubireader_extract_files image.ubi   # распакует UBIFS внутри томов
# Ручной путь: ubinize-конфиг и mount
sudo modprobe nandsim first_id_byte=0x2c second_id_byte=0xda third_id_byte=0x90 fourth_id_byte=0x95
sudo flash_erase /dev/mtd0 0 0
sudo ubiformat /dev/mtd0 -f image.ubi
sudo ubiattach -m 0
sudo mount -t ubifs /dev/ubi0_0 /mnt/ubifs
```

NAND-геометрия критична: неверные `nandsim` ID дают «bad magic». `ubireader` умеет автоподбор и `-e` для извлечения.

## CRAMFS и другие read-only образы

**CRAMFS** — маленькая read-only ФС для NOR, сигнатура `0x28cd3d45` (`45 3d cd 28` в LE). Максимальный размер файла — 16 МБ, сжатие zlib. Монтируется нативно в Linux:

```bash
file rootfs.cramfs        # -> "Linux Compressed ROM File System data, little endian"
mkdir mnt && sudo mount -o loop,ro rootfs.cramfs mnt
# или извлечение без root:
cramfsck -x out/ rootfs.cramfs   # из пакета cramfs-tools
```

Прочие: **romfs** (устаревшая, сигнатура `-rom1fs-`), **ext2/ext4** (монтируются напрямую `mount -o loop`), **initramfs** (gzip+cpio — `binwalk -e` или `dd` + `zcat | cpio -idmv`).

## Инструменты и команды: шпаргалка

| Инструмент | ФС | Установка | Ключевые флаги |
|-----------|----|-----------|----------------|
| `binwalk` | все (детект+extract) | apt/pip | `-e` extract, `-M` recursive, `-A` signature scan |
| `unblob` | все | pip/docker | `unblob firmware.bin -o out/` (авто-каскад) |
| `unsquashfs` | squashfs | squashfs-tools | `-d dir`, `-stat`, `-l` |
| `jefferson` | JFFS2 | pip | `-d dir`, `-e` endian |
| `ubireader` | UBI/UBIFS | pip | `ubireader_extract_files` |
| `cramfsck` | CRAMFS | cramfs-tools | `-x dir` |
| `7z`/`unar` | cpio, tar | p7zip | `7z x image` |
| `firmware-mod-kit` | сборка/распаковка | git | `extract-firmware.sh` |

Для автоматизации каскада (binwalk пропускает вложенные образы) удобен **unblob** — он рекурсивно распаковывает и ведёт отчёт.

## Разобранный пример: от дампа до /etc/shadow

```bash
# 1. Получили дамп SPI-NOR
ls -l dump.bin
# -rw-r--r-- 1 user user 16777216 dump.bin   (16 МБ)

# 2. Автодетект разделов
binwalk dump.bin
# DECIMAL   HEXADECIMAL  DESCRIPTION
# 0         0x0          uImage header, ... Linux kernel
# 131072    0x20000      Squashfs filesystem, ... size: 15073280 bytes
# 15204352  0xE80000     JFFS2 filesystem, little endian

# 3. Извлекаем всё рекурсивно
binwalk -eM dump.bin
# Создаст _dump.bin.extracted/ с squashfs-root/

# 4. Ищем секреты
grep -rE 'root:|admin:' _dump.bin.extracted/squashfs-root/etc/passwd
# root:x:0:0:root:/root:/bin/sh
# admin:$1$xyz...:0:0:...          <-- хэш MD5crypt
cat _dump.bin.extracted/squashfs-root/etc/shadow 2>/dev/null

# 5. Смотрим сервисы и отладку
ls _dump.bin.extracted/squashfs-root/etc/init.d/
cat _dump.bin.extracted/squashfs-root/etc/rc.d/S50telnetd   # бэкдор-telnet?

# 6. Проверяем приватные ключи
find _dump.bin.extracted/squashfs-root -name '*.pem' -o -name '*key*'
```

Дальше хэш `$1$...` уходит в `hashcat -m 500` (md5crypt), а найденный ключ — на расшифровку трафика или подпись обновлений.

## Частые ошибки и подводные камни

- **Неверное смещение**: `dd` с `bs=1 skip=` медленный; используйте `bs=1M` с точным смещением или доверьте `binwalk -e`.
- **Обрезанный squashfs**: если взять `count` больше реального размера, `unsquashfs` падает; берите размер из `binwalk`.
- **JFFS2/UBIFS монтируют напрямую**: без `mtdram`/`nandsim` ядро не смонтирует raw-flash ФС — «wrong magic».
- **Endianness**: big-endian MIPS/ARM дают перевёрнутые сигнатуры (`sqsh` → `hsqs`); `jefferson` и `ubireader` принимают флаг endian.
- **Сжатие LZMA/LZO**: старый `unsquashfs` не понимает — обновите `squashfs-tools` или возьмите статический бинарь.
- **Симлинки наружу**: при распаковке squashfs не делайте `-d` в `/` — символические ссылки могут указывать на абсолютные пути.

## Что дальше / решение

Разобранная ФС — это не финиш, а новая точка старта:

1. **Учётки** → офлайн-взлом хэшей (`hashcat`, `john`) или прямое использование пароля.
2. **Сервисы** → сопоставить с сетевыми портами устройства, искать CGI/HTTP-демоны.
3. **Скрипты инициализации** → найти вызовы `telnetd`, `dropbear`, `nc -l`, «сервисные» учётки.
4. **Приватные ключи** → расшифровка прошивок/обновлений, MITM.
5. **Эмуляция** → запустить бинарники в QEMU (см. `hardware-firmware-emulation`) для динамического анализа.

Если ФС не распаковывается — проверьте, не шифрован ли rootfs (часто squashfs завёрнут в собственный формат производителя), и вернитесь к анализу заголовков/загрузчика.

## Квиз

```quiz
- question: "Какая сигнатура у squashfs в hex?"
  options:
    - "hsqs"
    - "UBI#"
    - "0x1985"
    - "cramfs"
  answer: 0
  explanation: "squashfs начинается с магических байтов hsqs."
- question: "Почему JFFS2 и UBIFS нельзя просто смонтировать как образ?"
  options:
    - "Они зашифрованы"
    - "Это raw-flash ФС, зависящие от геометрии чипа"
    - "Они больше 4 ГБ"
    - "Они используют только zstd"
  answer: 1
  explanation: "JFFS2/UBIFS работают поверх raw NAND/NOR и требуют эмуляции контроллера (mtdram/nandsim)."
- question: "Какая ФС read-only и имеет ограничение размера файла 16 МБ?"
  options:
    - "ext4"
    - "CRAMFS"
    - "F2FS"
    - "UBIFS"
  answer: 1
  explanation: "CRAMFS — маленькая read-only ФС для NOR."
- question: "Какой инструмент рекурсивно распаковывает вложенные образы прошивки?"
  options:
    - "unsquashfs"
    - "binwalk -eM"
    - "jefferson"
    - "nandsim"
  answer: 1
  explanation: "binwalk с -e (extract) и -M (matryoshka, рекурсивно) идёт вглубь вложенных образов."
- question: "Где в прошивке чаще всего лежат хэши паролей?"
  options:
    - "В ядре zImage"
    - "В /etc/passwd и /etc/shadow внутри rootfs"
    - "В загрузчике U-Boot"
    - "В таблице разделов"
  answer: 1
  explanation: "Учётные записи живут в rootfs, обычно в /etc/passwd и /etc/shadow."
```

## Где пригодится

- **CTF:** Hardware/Forensics-задачи, где дают образ прошивки и просят найти флаг в rootfs.
- **Пентест IoT:** извлечение учёток, ключей и скрытых сервисов из прошивки роутера/камеры.
- **Реверс:** понимание, какие ФС и как собирает производитель, для поиска бэкдоров.
- **Работа:** анализ обновлений прошивок в SOC/IR, проверка цепочки поставок.
- **Дальше по дереву:** `hardware-squashfs`, `hardware-jffs2-ubifs`, `hardware-cramfs`, `hardware-firmware-emulation`.
