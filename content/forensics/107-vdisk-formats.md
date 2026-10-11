---
id: forensics-vdisk-formats
title: "Форматы виртуальных дисков: VMDK, QCOW2, VHD/VHDX, VDI"
category: forensics
parent: forensics-storage-layers
difficulty: hard
order: 3
tags: [vmdk, qcow2, vhd, vhdx, vdi, qemu-img, virtual-machine]
prerequisites: [forensics-img-acquisition]
useful_for:
  - "CTF Forensics категория"
  - "Анализ виртуальных машин"
  - "Cloud Forensics"
estimated_minutes: 50
summary: "Форматы виртуальных дисков: монолитный/sparse VMDK, QCOW2, VHD/VHDX, VDI; магии и дескрипторы, конвертация qemu-img, монтирование через qemu-nbd и разбор снапшотов."
---

Виртуальные диски — обычная форма виртуальных машин и облачных снапшотов. Формат оборачивает «сырые» сектора в контейнер с метаданными, снапшотами и сжатием. Чтобы добраться до файловой системы, контейнер нужно **развернуть в сырой образ** или смонтировать как блочное устройство. Неверный шаг здесь даёт «мусор» на выходе.

## Магии и типы форматов

| Формат | Магия/признак | Где встречается |
|--------|---------------|-----------------|
| RAW/DD | нет магии (сразу ФС/MBR) | универсальный |
| VMDK (sparse) | `KDMV` (0x4B444D56) в заголовке | VMware |
| VMDK (descriptor) | текст `# Disk DescriptorFile` | VMware (multi-file) |
| QCOW2 | `QFI\xfb` (0x514649FB) | QEMU/KVM |
| VHD (vpc) | `conectix` в конце файла | Hyper-V (legacy) |
| VHDX | `vhdxfile` | Hyper-V (modern) |
| VDI | `<<< Oracle VM VirtualBox Disk Image >>>` | VirtualBox |

Ключевое: **VMDK бывает нескольких видов** — монолитный sparse (один файл, магия KDMV), монолитный flat (raw + текстовый дескриптор), и «разделённый» на extent-файлы `-s001.vmdk`. Дескриптор (`*.vmdk` текстовый) описывает геометрию, тип (`SPARSE`, `FLAT`, `VMFS`, `STREAMOPTIMIZED`) и список extent-файлов.

## Конвертация и монтирование

```bash
# Информация о формате
qemu-img info disk.vmdk
qemu-img info disk.qcow2
qemu-img info disk.vhdx

# Конвертация в сырой образ (для sleuthkit)
qemu-img convert -O raw disk.vmdk disk.raw
qemu-img convert -O raw -f qcow2 disk.qcow2 disk.raw

# Монтирование как блочного устройства (без конвертации)
sudo modprobe nbd max_part=16
sudo qemu-nbd -c /dev/nbd0 --read-only disk.qcow2
# или конкретный снапшот VMDK:
sudo qemu-nbd -c /dev/nbd0 --read-only disk.vmdk
sudo mmls /dev/nbd0
sudo mount -o ro /dev/nbd0p1 /mnt/vm

# VHD/VHDX через libguestfs
guestfish --ro -a disk.vhdx -i
# или
sudo guestmount --ro -a disk.vhdx -i /mnt/vm
```

## Снапшоты и дельта-диски

Виртуальные диски часто имеют **цепочку снапшотов**: базовый диск + дельта-диски с изменениями. Чтобы увидеть состояние на момент снапшота, нужно «склеить» цепочку.

```bash
# VMDK: найти цепочку в дескрипторе
cat disk.vmdk | grep -E 'parentFileNameHint|CID|parentCID'
# QEMU: посмотреть backing file
qemu-img info --backing-chain disk.qcow2
# Склеить цепочку в один raw
qemu-img convert -O raw disk-snapshot.qcow2 merged.raw
```

VHDX хранит снапшоты внутри (block allocation table, BAT) и историю изменений (differencing VHDX). `guestfish`/`libvmdk` умеют читать их, но для точного анализа иногда нужен парсер формата.

## Разобранный пример: VMDK → ФС

```bash
$ qemu-img info win10.vmdk
image: win10.vmdk
file format: vmdk
virtual size: 60 GiB (64424509440 bytes)
disk size: 24 GiB
cluster_size: 65536
$ qemu-img convert -O raw win10.vmdk win10.raw
$ mmls win10.raw
      Slot      Start        End          Length       Description
      00:  -----   0000000000   0000002047   0000002048   Primary Table (#0)
      01:  00:00   0000002048   0000124927   0000122880   NTFS / exFAT (0x07)
$ fls -o 2048 -r win10.raw | head -5
r/r 5-128-1: $AttrDef
```

После конвертации всё работает штатным sleuthkit — формат перестал мешать.

## Краевые случаи и подводные камни

- **Не путайте sparse и flat VMDK.** Flat = raw + дескриптор; нужно конвертировать дескрипторный файл, а не extent напрямую.
- **Цепочка снапшотов.** Конвертация только «верхнего» дельта-диска без родителя даст неполную ФС. `--backing-chain` и `parentFileNameHint` — ваши друзья.
- **VHD `conectix` в конце.** VHD имеет footer в конце файла (и копию в начале для динамических). Обрезка файла ломает монтирование.
- **VHDX BAT.** Block Allocation Table может указывать на блоки вразброс; нельзя читать последовательно.
- **`qemu-nbd` требует `--read-only`.** Иначе вы (или ОС) измените диск.
- **Encryption.** VMDK/VHDX могут быть зашифрованы (VMware VM encryption, BitLocker внутри). Нужен ключ/пароль.
- **Cloud-образы.** AMI/EBS-снапшоты — тоже блочные образы, часто raw; но метаданные о них — в облачных API.
- **Сжатие/дедупликация.** QCOW2 с `-c` и VHDX могут сжимать кластеры; `qemu-img info` покажет `compressed`/`has backing file`.

## Как форматы влияют на сбор и анализ

Виртуальные диски добавляют слой, которого нет у «железного» носителя: контейнер с метаданными. Это даёт как плюсы (снапшоты, сжатие), так и подводные камни (цепочки дельт, вразброс блоки). Понимание формата определяет, получите вы валидный сырой образ или мусор.

Ключевое правило: **сначала развернуть контейнер, потом работать с ФС**. Sleuthkit, fls, mmls ожидают raw-диск или блочное устройство; на файл VMDK они смотрят как на «неизвестный формат».

## Сравнение форматов

| Свойство | RAW | VMDK | QCOW2 | VHD | VHDX | VDI |
|----------|-----|------|-------|-----|------|-----|
| Сжатие | нет | есть (stream) | есть | редко | есть | есть |
| Снапшоты | нет | дельта-цепочка | backing file | differencing | внутри | снапшоты |
| Шифрование | нет | VM encryption | LUKS-совместимо | нет | нет | есть |
| Монтирование | прямо | qemu-nbd/guestfish | qemu-nbd | guestfish | guestfish | VBoxManage |
| Магия | — | KDMV | QFI\xfb | conectix | vhdxfile | <<< Oracle |

## Инструменты libguestfs

`libguestfs` — набор утилит для работы с образами ВМ без запуска самой ВМ. Он сам определяет формат и «прошивает» нужные драйверы:

```bash
# Список файловых систем в образе
virt-filesystems -a disk.vmdk --all --long
# Интерактивная оболочка
guestfish --ro -a disk.vmdk -i
# Монтирование
guestmount --ro -a disk.vhdx -i /mnt/vm
# Копирование файла наружу
virt-copy-out -a disk.qcow2 /etc/shadow ./out/
# Просмотр логов
virt-ls -a disk.vmdk -l /
```

`virt-copy-out` особенно удобен, когда нужен один файл и не хочется монтировать весь диск.

## Разбор дескриптора VMDK

Текстовый дескриптор (`disk.vmdk`, если диск multi-file) — это читаемый файл:

```bash
cat disk.vmdk
# # Disk DescriptorFile
# version=1
# encoding="UTF-8"
# CID=fffffffe
# parentCID=ffffffff
# createType="monolithicSparse"
# RW 12345678 SPARSE "disk-s001.vmdk"
# ddb.geometry.cylinders = "65270"
# ddb.virtualHWVersion = "14"
# ddb.adapterType = "lsilogic"
```

Поле `createType` говорит о типе (monolithicSparse, twoGbMaxExtentSparse, vmfs и т. д.), а строки `RW <sectors> SPARSE/FLAT "file"` перечисляют extent-файлы. Если `parentCID` не `ffffffff`, у диска есть родитель (снапшот) — его нужно включить в цепочку.

## Практические сценарии

- **Облачный EBS-снапшот.** Обычно raw; метаданные (volume id, region, время) — в API/консоли. После скачивания — сразу `mmls`.
- **VMDK из бэкапа.** Часто это `monolithicSparse`; `qemu-img convert -O raw` и работайте как с диском.
- **VHDX с differencing.** Hyper-V-чекпоинт: базовый VHDX + AVHDX-дельты. `guestfish --ro -a base.vhdx -a delta.avhdx` соберёт цепочку.
- **Зашифрованный VMDK.** VMware VM Encryption: контейнер шифруется целиком; нужен ключ KMS/пароль.

## Типичные ошибки

- **Конвертировать extent-файл вместо дескриптора** — получите мусор.
- **Игнорировать родителя снапшота** — неполная ФС.
- **Монтировать read-write** — измените образ (и снапшот-цепочку).
- **Забыть про `--backing-chain`** — потеряете базовые блоки.
- **Обрезать VHD** — потеряете footer `conectix` и монтирование сломается.
- **Работать с QCOW2 без `qemu-nbd`** — не увидите партиции, только сырой файл.

## Хеширование и проверка виртуальных дисков

Контейнерный формат добавляет свои контрольные суммы, но они проверяют целостность контейнера, а не доказательства. Всегда считайте хеш **сырого** образа после конвертации и сверяйте с ожидаемым:

```bash
qemu-img convert -O raw disk.vmdk disk.raw
sha256sum disk.raw
# Сравните с предоставленным эталоном или повторите конвертацию и сравните дважды
```

Для QCOW2 полезно проверить целостность самого контейнера (`qemu-img check`), прежде чем конвертировать — это выявит повреждённые кластеры:

```bash
qemu-img check disk.qcow2
# 'No errors were found' — контейнер цел; иначе конвертация может дать дыры
```

Для облачных образов (EBS/AMI) часто дают SHA-256 в метаданных снапшота — обязательно сверяйте.

## Быстрая шпаргалка по форматам

| Задача | Команда |
|--------|---------|
| Определить формат | `qemu-img info disk` |
| Проверить целостность | `qemu-img check disk.qcow2` |
| Развернуть в raw | `qemu-img convert -O raw disk disk.raw` |
| Смонтировать без конвертации | `qemu-nbd -c /dev/nbd0 --read-only disk` |
| Цепочка снапшотов | `qemu-img info --backing-chain disk.qcow2` |
| Список ФС в образе | `virt-filesystems -a disk --all --long` |
| Вытащить один файл | `virt-copy-out -a disk /etc/shadow ./out/` |
| Интерактивно | `guestfish --ro -a disk -i` |
| Смонтировать VHDX | `guestmount --ro -a disk.vhdx -i /mnt/vm` |

Помните: `--read-only` обязателен везде, где инструмент это поддерживает, а после конвертации всегда работайте с raw-образом через sleuthkit.

## Что дальше / решение

1. `qemu-img info` — определить формат, размер, backing file.
2. Если есть снапшоты — собрать цепочку (`--backing-chain`).
3. `qemu-img convert -O raw` → сырой образ для sleuthkit, **или** `qemu-nbd`/`guestmount` для монтирования.
4. `mmls`/`fls` — работать с ФС как обычно.
5. Зашифровано — снимать слой шифрования (`forensics-disk-encryption`).

Дальше — `forensics-disk-images` (снятие образов) и `forensics-disk-encryption` (BitLocker/LUKS/VeraCrypt).

## Квиз

```quiz
- question: "Какая магия у формата QCOW2?"
  options:
    - "KDMV"
    - "QFI\\xfb"
    - "conectix"
    - "vhdxfile"
  answer: 1
  explanation: "QCOW2 начинается с магии QFI\\xfb."
- question: "Как корректно получить сырой образ из VMDK с цепочкой снапшотов?"
  options:
    - "скопировать только верхний дельта-диск"
    - "учесть всю цепочку (backing/parent) и конвертировать её"
    - "переименовать файл в .raw"
    - "открыть в блокноте"
  answer: 1
  explanation: "Дельта-диск без родителя неполон; нужно собирать всю цепочку."
- question: "Где у формата VHD хранится footer-магия?"
  options:
    - "только в начале"
    - "в конце файла (и копия в начале для динамических)"
    - "в MBR"
    - "в реестре"
  answer: 1
  explanation: "VHD помечает себя строкой conectix в footer в конце файла."
- question: "Зачем использовать `--read-only` при qemu-nbd?"
  options:
    - "для ускорения"
    - "чтобы не изменить образ"
    - "чтобы расшифровать диск"
    - "чтобы сжать образ"
  answer: 1
  explanation: "Read-only гарантирует неизменность доказательства."
```

## Где пригодится

- **CTF:** образы виртуальных машин и снапшотов.
- **Cloud Forensics:** анализ EBS/AMI-снапшотов.
- **DFIR:** разбор скомпрометированной ВМ.
- **Пентест:** извлечение данных из виртуальных дисков.
