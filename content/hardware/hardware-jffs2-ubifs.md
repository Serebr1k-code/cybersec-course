---
id: hardware-jffs2-ubifs
title: "JFFS2 и UBIFS: raw-flash ФС, разбор и монтирование"
category: hardware
parent: hardware-filesystems
difficulty: hard
order: 3
tags: [jffs2, ubifs, ubi, nand, nor, jefferson, ubireader, mtdram, nandsim]
prerequisites: [hardware-filesystems, hardware-spi]
useful_for:
  - "CTF-задачи категории Hardware/Forensics"
  - "Пентест IoT: разбор NAND-прошивок"
  - "Реверс встраиваемых систем"
estimated_minutes: 50
summary: "Как разобрать журналируемые raw-flash ФС JFFS2 и UBIFS/UBI: jefferson, ubireader, mtdram, nandsim, эмуляция NAND и извлечение файлов."
---

JFFS2 и UBIFS — «неудобные» файловые системы: они работают напрямую поверх raw NAND/NOR и не являются блочными образами. Их нельзя просто `mount -o loop`, потому что журнал, сжатие по узлам и wear-leveling завязаны на геометрию чипа (erase block size, page size, количество блоков). Этот урок объясняет, почему так, и даёт два рабочих пути: высокоуровневые парсеры (`jefferson`, `ubireader`) и низкоуровневую эмуляцию MTD (`mtdram`, `nandsim`).

## Почему raw-flash ФС особые

Флеш-память имеет физические ограничения, которых нет у дисков:

- **Erase перед записью**: записать можно только в стёртый блок; перезапись бита 0→1 невозможна без стирания.
- **Ограниченный ресурс**: блок изнашивается после ~10⁵ циклов стирания.
- **Bad blocks**: NAND рождается с дефектными блоками и приобретает новые.
- **Большие erase-блоки**: 64–256 КиБ (NOR), 128 КиБ+ (NAND).

Поэтому ФС для raw-flash добавляет поверх логического содержимого **журнал изменений** и **wear-leveling**. JFFS2 хранит данные в узлах, разбросанных по блокам; UBIFS работает поверх слоя UBI, который управляет физическими блоками NAND.

## JFFS2: структура и сигнатура

JFFS2-образ состоит из последовательности узлов. Каждый узел начинается с magic `0x1985` (в little-endian это байты `85 19`). Узлы бывают:

- **inode** — метаданные файла (тип, режим, uid/gid, размер);
- **dirent** — запись каталога (имя + inode);
- **data** — сжатые данные (rtime, zlib, lzo, rtime);
- **cleanmarker** — маркер стёртого блока.

Из-за того, что обновления дописываются новыми узлами, «сырое» чтение даёт и старые, и новые версии. Парсер должен пройти все узлы и собрать актуальное состояние.

## Разбор JFFS2 через jefferson

```bash
pip3 install jefferson

# Определить смещение JFFS2 в дампе
binwalk dump.bin | grep -i jffs2
# 15204352  0xE80000  JFFS2 filesystem, little endian

# Вырезать и распаковать
dd if=dump.bin of=part.jffs2 bs=1 skip=15204352
jefferson -d jffs2_out/ part.jffs2
# jefferson v0.4.x
# LZMA compression detected
# Extracting files to jffs2_out/
ls jffs2_out/
# etc/  bin/  lib/  www/  usr/
```

Полезные флаги `jefferson`: `-d` (выходной каталог), `-e big` (big-endian), `--no-clean` (не чистить имена), `-v` (verbose). Если парсер падает — проверьте, что образ не обрезан по конец последнего узла.

## Разбор JFFS2 через mtdram (монтирование)

Когда `jefferson` не справляется, эмулируем MTD-устройство:

```bash
sudo modprobe mtdram total_size=65536 erase_size=256
sudo modprobe mtdblock
# /dev/mtd0 создан размером 64 МБ
sudo dd if=part.jffs2 of=/dev/mtdblock0 bs=1
sudo mkdir -p /mnt/jffs2
sudo mount -t jffs2 /dev/mtdblock0 /mnt/jffs2
ls /mnt/jffs2
sudo umount /mnt/jffs2
```

`total_size` должен быть **не меньше** образа; лишнее пространство останется стёртым. `erase_size` подбирайте под чип (часто 64 КиБ для NAND, но mtdram работает и с 256). Ошибка «jffs2: Magic bitmask is not 0x1985» означает неверный endian или смещение.

## UBI и UBIFS: два уровня

**UBI** — это не ФС, а слой управления raw NAND: логические erase-блоки (LEB), тома (volumes), wear-leveling, bad-block management. **UBIFS** — ФС поверх тома UBI. Сигнатура UBI-образа: `UBI#` (`55 42 49 23`). Внутри дампа можно встретить как UBI-образ (набор PEB), так и уже готовый UBIFS-том.

## Разбор UBI через ubireader

```bash
pip3 install ubi_reader

# Список томов
ubireader_list_volumes image.ubi
# Volume table record:
#   vol_id  vol_type  name
#   0       dynamic   rootfs
#   1       dynamic   data

# Извлечь образы томов
ubireader_extract_images image.ubi
# -> ubifs-rootfs.img, ubifs-data.img

# Извлечь файлы прямо из томов
ubireader_extract_files image.ubi
# -> ubifs-rootfs/  ubifs-data/
```

`ubireader` умеет автоподбирать endian и геометрию. Если том UBIFS не распознан — попробуйте `ubireader_extract_files -e big`. Для образов, где UBI повреждён, помогает `ubireader_utils_info` и ручной разбор через `ubiformat`.

## Монтирование UBIFS через nandsim

```bash
# Эмулируем NAND-чип: ID 0x2cda9095 = Micron MT29F2G08 (пример)
sudo modprobe nandsim first_id_byte=0x2c second_id_byte=0xda \
     third_id_byte=0x90 fourth_id_byte=0x95
ls -l /dev/mtd0
sudo flash_erase /dev/mtd0 0 0
sudo ubiformat /dev/mtd0 -f image.ubi
# ubiformat: formatting /dev/mtd0, UBI version 1
sudo ubiattach -m 0
sudo mkdir -p /mnt/ubifs
sudo mount -t ubifs /dev/ubi0_0 /mnt/ubifs
ls /mnt/ubifs
```

Критично: **ID чипа должен совпадать** с тем, для которого собран образ (page size, OOB size, количество блоков). Неверный ID → «UBI error: bad magic» или «cannot attach». Найти правильный ID можно по строке ядра в прошивке (`grep -a 'nand' zImage` или в логе U-Boot).

## Разобранный пример: NAND-роутер

```bash
# Дамп NAND получен через chip-off (hardware-chip-off)
binwalk nand_dump.bin | head
# 0      0x0        UBI erase count header, version: 1
# 2097152 0x200000 UBIFS filesystem superblock

# Путь 1: ubireader
ubireader_extract_files nand_dump.bin
find ubifs-rootfs -name shadow -o -name '*.pem' | head
cat ubifs-rootfs/etc/shadow

# Путь 2: если ubireader спотыкается, монтируем
sudo modprobe nandsim first_id_byte=0xec second_id_byte=0xd3 \
     third_id_byte=0x51 fourth_id_byte=0x95
sudo flash_erase /dev/mtd0 0 0
sudo ubiformat /dev/mtd0 -f nand_dump.bin
sudo ubiattach -m 0
sudo mount -t ubifs /dev/ubi0_0 /mnt/ubifs
grep root /mnt/ubifs/etc/passwd
```

## Таблица: чем что разбирать

| Артефакт | Сигнатура | Инструмент | Альтернатива |
|----------|-----------|-----------|--------------|
| JFFS2 | `85 19` | jefferson | mtdram + mount |
| UBI | `UBI#` | ubireader | nandsim + ubiformat |
| UBIFS | `UBI#` внутри | ubireader | nandsim + mount |
| MTD-разделы | по таблице | mtd-utils | binwalk |
| Bad-block таблица | `Bbt` | nanddump | ручной парсинг |

## Частые ошибки и подводные камни

- **Обрезанный образ**: если не захвачен конец раздела, последние узлы/PEB теряются — часть файлов пропадёт.
- **Неверный endian**: big-endian MIPS/ARM → `jefferson -e big`, `ubireader -e big`.
- **Неверная геометрия nandsim**: «bad magic» почти всегда про ID чипа, а не про данные.
- **Размер mtdram меньше образа**: `dd` обрежет, монтирование даст пустую ФС.
- **Один дамп — несколько UBI**: иногда есть два блока UBI (основной + резервный); ubireader может собрать неполно.
- **Сжатие LZO/LZMA**: редко, но требует правильной библиотеки; обновляйте парсеры.

## Пересборка JFFS2 и UBIFS

Если нужно вернуть модифицированный раздел, простого `cp` недостаточно — raw-flash ФС собирают специальными инструментами.

Для JFFS2 из каталога собирают образ через `mkfs.jffs2`:

```bash
sudo apt install mtd-utils
mkfs.jffs2 -r rootfs_dir/ -o new.jffs2 -e 0x10000 -p 0x1000000 -n
# -e erase block size, -p размер раздела, -n без cleanmarker
```

Критичны `-e` (erase size) и endianness (`-b` для big-endian). Неверный erase size → устройство не смонтирует ФС. Размер образа `-p` должен совпадать с разделом.

Для UBIFS последовательность такая:

```bash
mkfs.ubifs -r rootfs_dir/ -m 2048 -e 126976 -c 2048 -o rootfs.ubifs
ubinize -o image.ubi -m 2048 -p 128KiB ubinize.cfg
# ubinize.cfg описывает тома:
# [rootfs]
# mode=ubi
# image=rootfs.ubifs
# vol_id=0
# vol_type=dynamic
# vol_name=rootfs
```

Параметры `-m` (min I/O = page size), `-e` (LEB size = PEB − 2*page), `-c` (max LEB count) должны точно соответствовать чипу. Их можно взять из вывода `ubireader_utils_info` по оригинальному образу — это надёжнее, чем угадывать.

## Резервные копии UBI и двойные образы

Многие устройства хранят **две копии** UBI (основную и резервную) или два раздела rootfs A/B для отказоустойчивости обновлений. В дампе это выглядит как повторяющиеся блоки `UBI#`. `ubireader` может собрать тома из первого найденного образа; если он неполон, стоит вырезать второй регион и разобрать отдельно. При анализе прошивки полезно сравнить A и B: часто в «старом» разделе остаются учётки и ключи, которые удалили из нового.

## JFFS2: почему файл «не удаляется»

В JFFS2 удаление файла — это запись специального узла-надгробия, а не физическое стирание. Поэтому в сыром образе могут присутствовать **уже удалённые** данные: старые версии `/etc/shadow`, прежние ключи, конфиги с паролями. `jefferson` по умолчанию собирает актуальное состояние, но при `--no-clean` можно увидеть и «мусор». Именно поэтому JFFS2-дампы ценны в форензике: даже после смены пароля старый хэш часто остаётся в журнале и поддаётся восстановлению.

## Что дальше / решение

1. Файлы извлечены → искать учётки, ключи, скрипты (как в `hardware-filesystems`).
2. Нужен доступ к устройству → использовать найденные креды или модифицировать раздел (для JFFS2/UBIFS пересборка сложнее — нужен `mkfs.jffs2`/`mkfs.ubifs` + `ubinize`).
3. Динамика → эмулировать бинарники в QEMU.
4. Не распаковывается → проверить, не XOR-нут ли раздел и не перевёрнут ли endian.

## Квиз

```quiz
- question: "Какая магия у узла JFFS2?"
  options:
    - "0x1985"
    - "hsqs"
    - "UBI#"
    - "Bbt"
  answer: 0
  explanation: "Каждый узел JFFS2 начинается с 0x1985."
- question: "Что делает слой UBI?"
  options:
    - "Сжимает файлы"
    - "Управляет raw NAND: wear-leveling, тома, bad-block"
    - "Шифрует раздел"
    - "Монтирует ext4"
  answer: 1
  explanation: "UBI — слой управления NAND поверх которого работает UBIFS."
- question: "Какой модуль эмулирует NAND для монтирования UBI?"
  options:
    - "mtdram"
    - "nandsim"
    - "loop"
    - "overlay"
  answer: 1
  explanation: "nandsim эмулирует NAND-чип, mtdram — простой RAM-MTD."
- question: "Почему nandsim ругается 'bad magic' при верных данных?"
  options:
    - "Файл зашифрован"
    - "Неверный ID чипа (геометрия NAND)"
    - "Мало ОЗУ"
    - "Не тот endian"
  answer: 1
  explanation: "Геометрия (page/OOB/блоки) должна совпадать с чипом."
- question: "Какой инструмент проще всего извлечь файлы из UBI?"
  options:
    - "unsquashfs"
    - "ubireader_extract_files"
    - "jefferson"
    - "cramfsck"
  answer: 1
  explanation: "ubireader_extract_files вытаскивает файлы из томов UBI/UBIFS."
```

## Где пригодится

- **CTF:** Hardware/Forensics-задачи с дампом NAND.
- **Пентест IoT:** разбор прошивок камер, роутеров, NVR с NAND.
- **Реверс:** понимание журналов и структуры raw-flash ФС.
- **Работа:** восстановление данных из флеш-дампов в IR.
- **Дальше по дереву:** `hardware-filesystems`, `hardware-flash-dumping`, `hardware-chip-off`.
