---
id: forensics-disk-images
title: "Образы дисков и восстановление удалённых данных"
category: forensics
parent: forensics-filesystems
difficulty: medium
order: 3
tags: [disk-image, dd, ewf, vmdk, mounting, recovery, testdisk]
prerequisites: [forensics-filesystems]
useful_for:
  - "CTF Forensics категория"
  - "Data recovery"
  - "Incident Response"
estimated_minutes: 40
summary: "Форматы образов, безопасное монтирование, восстановление удалённых файлов, работа с разделами, LVM и шифрованием."
---
Образ диска — это побайтовая копия носителя, зафиксированная для анализа. Умение корректно распознать формат образа, безопасно его смонтировать, разобрать разделы (включая LVM и шифрование) и восстановить удалённые данные — базовый навык форензика. Этот урок — про форматы (raw/E01/VMDK/QCOW2), read-only монтирование, разбор GPT/MBR, работу с LVM/LUKS и восстановление через Sleuth Kit и testdisk.

## Форматы образов

| Формат | Расширение | Особенности | Инструмент |
|--------|-----------|-------------|-----------|
| raw/dd | `.img`, `.dd`, `.raw` | побайтовая копия, монтируется напрямую | `dd`, `losetup` |
| E01 (EWF) | `.E01` | сжатие, сегменты, CRC, метаданные | `ewfmount`, `libewf` |
| AFF4 | `.aff4` | открытый формат, сжатие | `aff4imager` |
| VMDK | `.vmdk` | диск VMware (monolithic/split) | `qemu-nbd`, `vmware-mount` |
| VHD/VHDX | `.vhd`/`.vhdx` | Hyper-V | `qemu-nbd`, `guestmount` |
| QCOW2 | `.qcow2` | QEMU/KVM, дельта-слои | `qemu-nbd` |

```bash
$ file disk.E01
disk.E01: EWF/Expert Witness format
$ mmls disk.E01            # TSK читает E01 напрямую через libewf
```

E01 разбит на сегменты `.E01`, `.E02`… — передавайте первый, не открывайте по отдельности.

## Безопасное монтирование

Главное правило — **read-only**. Для raw-образов с разделами считайте offset (байты!) и монтируйте.

```bash
# 1. узнать offset раздела (секторы)
$ fdisk -l disk.img
/dev/loop0p1  2048  ...   Linux
# 2. смонтировать ro (offset в байтах = сектор * 512)
$ sudo mount -o ro,loop,offset=$((2048*512)) disk.img /mnt/img
# 3. или через losetup -P (авторазделы)
$ sudo losetup -Pf --show disk.img
$ sudo mount -o ro /dev/loop0p1 /mnt/img
$ sudo umount /mnt/img && sudo losetup -d /dev/loop0
```

Для E01 — сначала `ewfmount`:

```bash
$ ewfmount disk.E01 /mnt/ewf
$ mmls /mnt/ewf/ewf1
$ sudo mount -o ro,loop,offset=$((2048*512)) /mnt/ewf/ewf1 /mnt/img
```

Для VMDK/QCOW2 — `qemu-nbd` или `guestmount`:

```bash
$ sudo modprobe nbd max_part=8
$ sudo qemu-nbd --connect=/dev/nbd0 disk.vmdk
$ sudo mount -o ro /dev/nbd0p1 /mnt/img
$ sudo qemu-nbd --disconnect /dev/nbd0
# или без root:
$ guestmount -a disk.qcow2 -i --ro /mnt/img
```

## Разделы: MBR и GPT

`mmls` (TSK) и `parted`/`gdisk` показывают таблицу разделов.

```bash
$ mmls disk.img
DOS Partition Table
Offset Sector: 0
      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:00    0000002048   0000411647   0000409600   NTFS / exFAT (0x07)

$ parted disk.img unit s print
$ gdisk -l disk.img
```

Если таблица повреждена, `testdisk` находит потерянные разделы по резервным копиям (GPT backup в конце диска) и по сигнатурам ФС.

## LVM и шифрование

**LVM** добавляет слой: физический том (PV) → группа томов (VG) → логические тома (LV). Образ с LVM напрямую не смонтируется — нужен `vgscan`/`vgchange`.

```bash
$ sudo losetup -Pf --show lvm.img
$ sudo vgscan
$ sudo vgchange -ay vg0
$ sudo lvscan
$ sudo mount -o ro /dev/vg0/root /mnt/img
```

**LUKS** (Linux) и **BitLocker** (Windows) шифруют раздел целиком. Без ключа/пароля смонтировать нельзя; но можно:
- найти пароль/ключ в других источниках (память, `/etc/crypttab`, TPM-дамп);
- для BitLocker — `dislocker` с recovery key;
- для LUKS — `cryptsetup luksDump` покажет заголовок и слоты ключей.

```bash
$ sudo cryptsetup luksDump enc.img      # версия, шифр, слоты
$ sudo cryptsetup open enc.img dec --key-file=key.bin
$ sudo mount -o ro /dev/mapper/dec /mnt/img
```

## Sleuth Kit: анализ без монтирования

TSK разбирает ФС прямо из образа, не изменяя его — предпочтительно для улик.

```bash
$ mmls disk.img
$ fsstat -o 2048 disk.img | head
$ fls -r -p -o 2048 disk.img | tee fls.txt
$ fls -r -d -o 2048 disk.img           # удалённые
$ tsk_recover -o 2048 disk.img out/    # массово
$ tsk_recover -o 2048 -e disk.img rec_deleted/
```

## Восстановление удалённых данных

Удалённые файлы ищут тремя путями: (1) сохранившиеся inode/MFT-записи (`fls -d`, `icat`); (2) unallocated-пространство (`blkls` + `grep`/carving); (3) журнал ФС (ext4 `jbd2`, NTFS `$LogFile`/`$UsnJrnl`).

```bash
$ fls -r -d -o 2048 disk.img
r/r * 15: secret.txt
$ icat -o 2048 disk.img 15 > secret.txt
$ blkls -o 2048 disk.img > unalloc.bin
$ foremost -i unalloc.bin -o carved/
```

`extundelete`/`ext4magic` работают с журналом ext4:

```bash
$ sudo extundelete disk.img --restore-all
$ sudo ext4magic disk.img -r -d out/
```

## Разобранный пример

Дан `case.E01` с разделами и LVM.

```bash
$ ewfmount case.E01 /mnt/ewf
$ mmls /mnt/ewf/ewf1
002:  000:00  0000002048  0000206847  Linux LVM (0x8e)
# LVM поверх образа
$ sudo losetup -Pf --show /mnt/ewf/ewf1
$ sudo vgscan && sudo vgchange -ay vg0
$ sudo mount -o ro /dev/vg0/root /mnt/img
$ ls /mnt/img/home/user/
notes.txt
$ sudo umount /mnt/img && sudo vgchange -an vg0
$ sudo losetup -d /dev/loop0
$ fusermount -u /mnt/ewf
```

Если раздел оказался LUKS:

```bash
$ sudo cryptsetup luksDump /dev/loop0p2
$ sudo cryptsetup open /dev/loop0p2 dec --key-file=/tmp/key
```

## Таблица «задача → команда»

| Задача | Команда |
|--------|---------|
| Определить формат | `file disk.*` |
| Смонтировать E01 | `ewfmount disk.E01 /mnt/ewf` |
| Смонтировать raw ro | `mount -o ro,loop,offset=N img /mnt` |
| VMDK/QCOW2 | `qemu-nbd` или `guestmount` |
| Разделы | `mmls`, `parted`, `gdisk` |
| LVM | `vgscan && vgchange -ay` |
| LUKS | `cryptsetup open` |
| BitLocker | `dislocker` |
| Восстановить | `tsk_recover -e`, `extundelete` |
| Найти потерянные разделы | `testdisk` |

## Частые ошибки

- **Монтировать rw.** Всегда `ro`; иначе меняете улику.
- **Путать байты и секторы** в `offset=`.
- **Открывать сегмент `.E02`** вместо `.E01`.
- **Забывать `vgchange -ay`** — LVM-тома не появятся.
- **Считать LUKS/BitLocker непроходимым** — ищите ключ в памяти или конфигах.
- **Не отмонтировать/не отключить loop** — устройство останется занятым.
- **Анализировать образ на исходном диске** — копируйте образ на отдельный носитель.

## Что дальше / решение

Формат (`file`) → монтирование/разбор (`ewfmount`/`losetup`/`guestmount`) → ФС (`fsstat`) → восстановление (`tsk_recover -e`/`extundelete`). Связка: `forensics-filesystems` (структуры), `forensics-partition-tables` (MBR/GPT), `forensics-disk-encryption` (LUKS/BitLocker), `forensics-disk-imaging` (как правильно снять образ с write blocker).

## Контроль целостности и хеширование образов

Любой образ обязан иметь зафиксированную контрольную сумму — без неё доказательство недопустимо. Хешируйте **исходный носитель** и **полученный образ**, они должны совпадать.

```bash
$ sha256sum disk.img > disk.img.sha256
$ sha256sum -c disk.img.sha256
disk.img: OK
# E01 несёт встроенные CRC/хеши — проверяем
$ ewfverify disk.E01
ewfverify 20140813
Verify: SUCCESS
# dc3dd считает хеш «на лету» при снятии образа
$ dc3dd if=/dev/sdb of=disk.img hash=sha256 log=dd.log
```

Для VMDK/QCOW2/raw сверяйте хеш **логического диска** (после конвертации), а не файла-контейнера: `qemu-img convert` меняет представление, но не содержимое — сравнивайте `qemu-img map` и хеш по `qemu-nbd`-устройству.

## Разбор дельта-дисков и снапшотов

Виртуализация добавляет слой: снапшот — это не полный диск, а **дельта** относительно родителя. Чтобы получить актуальное состояние, нужно наложить цепочку.

| Формат | Родитель | Дельта | Как собрать |
|--------|----------|--------|-------------|
| VMDK | `disk.vmdk` | `disk-000001.vmdk` | `qemu-img convert` цепочки |
| QCOW2 | backing file | снапшот | `qemu-img commit`/`convert` |
| VHDX | `disk.vhdx` | `.avhdx` | `qemu-img` / Hyper-V |
| VM snapshot | `disk.vmdk` | `.vmsn`/`.vmsd` | парсинг `*.vmsd` (какой дельта активен) |

```bash
$ qemu-img info disk-000001.vmdk           # покажет backing file
$ qemu-img convert -O raw disk-000001.vmdk full.raw
$ qemu-img commit disk-000001.vmdk          # влить дельту в родителя (копия!)
```

Файл `.vmsd` описывает цепочку снапшотов в текстовом формате — из него видно, какой дельта-диск соответствует моменту времени, что критично для восстановления состояния системы на нужную дату.

## Квиз

```quiz
- question: "Как смонтировать образ с разделом, начинающимся с сектора 2048?"
  options:
    - "`mount disk.img /mnt`"
    - "`mount -o ro,loop,offset=1048576 disk.img /mnt`"
    - "`mount -o offset=2048 disk.img /mnt`"
    - "`losetup disk.img`"
  answer: 1
- question: "Какой флаг `losetup` создаёт устройства для разделов?"
  options:
    - "`-r`"
    - "`-P`"
    - "`-d`"
    - "`-a`"
  answer: 1
- question: "Чем открыть LUKS-образ?"
  options:
    - "`unzip`"
    - "`cryptsetup open`"
    - "`mount -t ntfs`"
    - "`dd`"
  answer: 1
- question: "Какая команда конвертирует VMDK в raw?"
  options:
    - "`qemu-img convert -f vmdk -O raw disk.vmdk disk.img`"
    - "`unrar x disk.vmdk`"
    - "`binwalk -e disk.vmdk`"
    - "`tar xf disk.vmdk`"
  answer: 0
- question: "Почему образ монтируют read-only?"
  options:
    - "так быстрее"
    - "чтобы не изменить доказательства/данные"
    - "иначе не смонтируется"
    - "для сжатия"
  answer: 1
```

## Где пригодится

- **CTF:** образы дисков — классика категории Forensics.
- **Data recovery:** восстановление после сбоев и шифровальщиков.
- **Incident Response:** анализ дисков инфицированных хостов.
- **Виртуализация:** извлечение данных из VMDK/VHDX/QCOW2.
- **Криминалистика:** корректная работа с уликами без их порчи.
