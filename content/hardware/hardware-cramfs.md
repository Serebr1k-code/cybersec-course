---
id: hardware-cramfs
title: "CRAMFS, romfs, ext и initramfs: разбор простых образов"
category: hardware
parent: hardware-filesystems
difficulty: medium
order: 2
tags: [cramfs, romfs, initramfs, cpio, ext4, binwalk, cramfsck, firmware]
prerequisites: [hardware-firmware-extract]
useful_for:
  - "CTF-задачи категории Hardware/Forensics"
  - "Пентест IoT: быстрый разбор прошивок"
  - "Реверс встраиваемых Linux-систем"
estimated_minutes: 35
summary: "Простые read-only ФС прошивок: CRAMFS, romfs, ext2/ext4 и initramfs/cpio — распознавание, распаковка и извлечение без спецсофта."
---

Не всякая прошивка содержит squashfs или UBIFS. Старые и «тонкие» устройства часто используют совсем простые форматы: CRAMFS, romfs, обычный ext2/ext4 или initramfs (cpio, часто завёрнутый в gzip). Хорошая новость: их разбирают нативные инструменты Linux без сложной эмуляции. Этот урок — про быстрые образы и как не перепутать их с чем-то более хитрым.

## CRAMFS: компактная read-only ФС

**CRAMFS** (Compressed ROM File System) — read-only ФС с zlib-сжатием по блокам, рассчитанная на NOR-флеш. Магия — `0x28cd3d45`, в little-endian это байты `45 3d cd 28`, в файле выглядит как `cramfs`. Ограничения: максимальный размер файла 16 МБ, файлы не сжимаются, если выгода меньше накладных расходов, нет поддержки больших uid/gid (16 бит).

```bash
# Распознать
file rootfs.cramfs
# rootfs.cramfs: Linux Compressed ROM File System data, little endian, size: 4194304

# Извлечь без root (пакет cramfs-tools)
sudo apt install cramfsprogs
cramfsck -x cramfs_out/ rootfs.cramfs
ls cramfs_out/
# bin  dev  etc  lib  sbin  usr  var

# Или смонтировать
sudo mkdir -p /mnt/cramfs
sudo mount -o loop,ro rootfs.cramfs /mnt/cramfs
```

`cramfsck -x` работает без привилегий — удобно в контейнере. Для образов в дампе сначала вырезают по смещению из `binwalk`.

## romfs: предок, но всё ещё встречается

**romfs** — ещё более простая read-only ФС (магия `-rom1fs-`). Использовалась в старых роутерах и маршрутизаторах. Ядро Linux всё ещё её понимает:

```bash
file image.romfs
# image.romfs: RomFS filesystem, version 1, size: 131072, named "."

sudo mount -t romfs -o loop image.romfs /mnt/romfs
ls /mnt/romfs
```

Инструментов для userspace-распаковки почти нет — проще смонтировать или использовать `romfs`-модуль ядра. В CTF romfs встречается редко, но `binwalk` его детектирует.

## ext2/ext3/ext4 в прошивке

Устройства с eMMC/SD часто держат rootfs в **ext4**. Это самый простой случай: файловая система блочная и монтируется напрямую.

```bash
# Детект
file rootfs.ext4
# rootfs.ext4: Linux rev 1.0 ext4 filesystem data, UUID=...

# Монтирование
sudo mkdir -p /mnt/root
sudo mount -o loop,ro rootfs.ext4 /mnt/root
ls /mnt/root

# Без root: использовать debugfs
debugfs -R "ls -l /etc" rootfs.ext4
debugfs -R "dump /etc/passwd /tmp/passwd" rootfs.ext4
# или 7z умеет читать ext
7z x rootfs.ext4 -oext_out/
```

`debugfs` из `e2fsprogs` позволяет читать файлы и каталоги **без монтирования и без root** — идеально для анализа в изолированной среде.

## initramfs и cpio

**initramfs** — это не ФС, а архив `cpio`, часто сжатый gzip/xz/lz4. Ядро распаковывает его в ramfs при загрузке. В прошивках initramfs встречается как временный rootfs до монтирования основной ФС.

```bash
# Детект: binwalk покажет "gzip compressed data" + "ASCII cpio archive"
binwalk initramfs.bin
# 0     0x0     gzip compressed data
# 20000 0x...  ASCII cpio archive (SVR4 with no CRC)

# Распаковка
mkdir initramfs_out && cd initramfs_out
zcat ../initramfs.bin | cpio -idmv
# или для xz: xz -dc ../initramfs.bin | cpio -idmv
# lz4: lz4 -dc ../initramfs.bin | cpio -idmv
```

Если `binwalk` уже извлёк cpio в `_initramfs.bin.extracted/`, достаточно `cd` туда и `cpio -idmv < ../initramfs.cpio`. Для форматов `newc`/`crc` синтаксис тот же.

## Разобранный пример: три образа в одном дампе

```bash
binwalk camera_fw.bin
# 0        0x0        uImage header
# 1048576  0x100000   gzip compressed data (initramfs)
# 2097152  0x200000   CRAMFS filesystem
# 6291456  0x600000   ext4 filesystem

# 1) initramfs
binwalk -e camera_fw.bin
ls _camera_fw.bin.extracted/ | head
# 100000  initramfs.cpio  ...
cd _camera_fw.bin.extracted && cpio -idmv < initramfs.cpio 2>/dev/null

# 2) CRAMFS
dd if=camera_fw.bin of=rootfs.cramfs bs=1 skip=2097152 count=4194304
cramfsck -x cramfs_root/ rootfs.cramfs

# 3) ext4
dd if=camera_fw.bin of=data.ext4 bs=1 skip=6291456
debugfs -R "ls -l /" data.ext4
debugfs -R "dump /etc/passwd /tmp/pw" data.ext4
cat /tmp/pw
```

## Таблица: сигнатуры и инструменты

| ФС | Магия (hex) | Вид в файле | Инструмент |
|----|-------------|-------------|------------|
| CRAMFS | `45 3d cd 28` | `cramfs` | cramfsck, mount |
| romfs | `2d 72 6f 6d` | `-rom` | mount -t romfs |
| ext2/3/4 | `53 ef` @1024 | `ext` | mount, debugfs, 7z |
| cpio (initramfs) | `30 37 30 37` | `070701` | cpio -idmv |
| gzip | `1f 8b` | — | zcat, gunzip |
| xz | `fd 37 7a 58` | — | xz -dc |

## Частые ошибки и подводные камни

- **CRAMFS 16 МБ**: если внутри есть файл больше 16 МБ, образ не собран как cramfs (возможно, это ext).
- **Монтирование требует root**: в контейнере без привилегий используйте `cramfsck -x`, `debugfs`, `7z`.
- **cpio из wrong compression**: сначала определите сжатие (`file`), иначе `cpio` выдаст «premature end of file».
- **ext4 с журналом**: `debugfs` не «доигрывает» журнал — читайте аккуратно, при сомнениях монтируйте `-o ro,noload`.
- **Пропущенное смещение**: `dd` без `skip` даст мусор; всегда берите offset из `binwalk`.

## Автокаскад: unblob против binwalk

`binwalk` — классика, но у него есть слабости: он не всегда понимает новые сжатия и может пропускать вложенные образы. **unblob** — современная альтернатива на Python, которая рекурсивно распаковывает каскады и ведёт отчёт о каждом шаге.

```bash
pip3 install unblob
unblob camera_fw.bin -o unblob_out/
# unblob_out/
#   camera_fw.bin_extract/
#     ...
cat unblob_out/*/report.json | head
```

unblob умеет: squashfs, cramfs, romfs, ext, cpio, gzip, xz, lz4, UBI, JFFS2 и десятки проприетарных форматов. Для сложных прошивок каскад вида «gzip → cpio → squashfs → xz» он проходит за один запуск. Если unblob не справился, возвращайтесь к `binwalk -eM` и ручному `dd` — два инструмента дополняют друг друга.

## Пересборка простых ФС

Обратная сборка тоже нужна для модификации прошивки:

```bash
# CRAMFS
mkcramfs rootfs_dir/ new.cramfs      # пакет cramfsprogs
# ext4
mkfs.ext4 -d rootfs_dir/ -b 4096 new.ext4 -F
# cpio/initramfs
cd rootfs_dir && find . | cpio -o -H newc | gzip -9 > ../initramfs.cpio.gz
```

При пересборке CRAMFS помните про лимит 16 МБ на файл и общий размер раздела. Для initramfs важно сохранить структуру каталогов и права (`find . | cpio -o -H newc` делает это корректно). Проверяйте результат монтированием на хосте, прежде чем прошивать устройство.

## Форензика простых образов

Даже «скучная» ext4-прошивка ценна для форензики: в ней остаются история команд, логи, кэши и удалённые файлы. `debugfs` умеет искать удалённые inode:

```bash
debugfs -R "lsdel" data.ext4        # список удалённых inode
debugfs -R "dump <inode> /tmp/rec" data.ext4
```

Для ext4 без журнала (`-o noload`) часть удалённых данных может сохраниться. В CTF это частый путь к «удалённому» флагу: файл стёрли, но блок не перезаписали. Аналогично, в cpio/initramfs можно найти файлы, которые ядро игнорирует при загрузке, но они остались в архиве.

## Распознавание без binwalk

Иногда `binwalk` недоступен (нет pip, офлайн-стенд), а образ надо разобрать. Простые ФС определяются вручную по сигнатуре:

```bash
# Поиск сигнатур по смещениям
grep -abo $'\x45\x3d\xcd\x28' image.bin   # CRAMFS
grep -abo 'UBI#' image.bin                 # UBI
grep -abo 'hsqs' image.bin                 # squashfs
grep -abo $'\x85\x19' image.bin            # JFFS2 (может быть много ложных)
# Таблица разделов MTD в дампе часто рядом с заголовком
grep -abo 'mtdparts' image.bin
```

`grep -abo` печатает байтовое смещение найденной сигнатуры — это готовый `skip` для `dd`. Для big-endian устройств те же магии перевёрнуты (`sqsh`, `#IBU`, `28cd3d45`). Этот приём выручает, когда binwalk-сигнатуры устарели или образ обфусцирован по заголовку.

## Практические сценарии

- **Быстрый флаг в CTF**: дают образ → `file` показывает CRAMFS → `cramfsck -x` → `grep -r flag`. Минуты.
- **Восстановление пароля роутера**: CRAMFS rootfs → `/etc/shadow` → `hashcat -m 500`.
- **Анализ обновления**: сравнить старый и новый ext4-разделы, найти новые бинарники и ключи.
- **Проверка целостности**: `debugfs -R "stat /etc/passwd"` покажет даты — помогает понять, менялся ли файл после релиза.

Во всех случаях правило одно: сначала точно определить формат (`file`, `binwalk`, ручные сигнатуры), затем распаковать **подходящим** инструментом и только потом лезть в содержимое.

## Что дальше / решение

1. Извлечённые файлы → учётки, ключи, скрипты (см. `hardware-filesystems`).
2. Не распознаётся → возможно, образ проприетарный (обфускация/XOR/шифрование) — искать заголовок в загрузчике.
3. Нужно пересобрать CRAMFS/ext → `mkcramfs`, `mkfs.ext4` (следите за размером раздела).
4. Динамика → QEMU-эмуляция (`hardware-firmware-emulation`).

## Квиз

```quiz
- question: "Какой максимальный размер файла в CRAMFS?"
  options:
    - "4 МБ"
    - "16 МБ"
    - "64 МБ"
    - "без ограничений"
  answer: 1
  explanation: "CRAMFS ограничивает файл 16 МБ."
- question: "Как прочитать файл из ext4 без root?"
  options:
    - "mount -o loop"
    - "debugfs -R 'dump ...'"
    - "cramfsck"
    - "jefferson"
  answer: 1
  explanation: "debugfs читает ext без монтирования и привилегий."
- question: "Что такое initramfs по формату?"
  options:
    - "ext4-образ"
    - "cpio-архив, часто сжатый gzip/xz"
    - "squashfs"
    - "UBI-том"
  answer: 1
  explanation: "initramfs — это cpio (newc), сжатый gzip/xz/lz4."
- question: "Какая магия у CRAMFS в байтах?"
  options:
    - "45 3d cd 28"
    - "68 73 71 73"
    - "55 42 49 23"
    - "85 19"
  answer: 0
  explanation: "CRAMFS начинается с 0x28cd3d45."
- question: "Как извлечь файлы из ext4 в контейнере без привилегий?"
  options:
    - "mount"
    - "7z x image.ext4"
    - "unsquashfs"
    - "ubiformat"
  answer: 1
  explanation: "7z умеет читать ext2/3/4 без монтирования."
```

## Где пригодится

- **CTF:** Hardware/Forensics с простыми образами — быстрый путь к флагу.
- **Пентест IoT:** разбор старых устройств с CRAMFS/romfs.
- **Реверс:** понимание разнообразия ФС в прошивках.
- **Работа:** извлечение данных из eMMC-дампов.
- **Дальше по дереву:** `hardware-filesystems`, `hardware-firmware-extract`, `hardware-flash-dumping`.
