---
id: forensics-raid
title: "RAID и LVM: реконструкция массивов и томов"
category: forensics
parent: forensics-img-acquisition
difficulty: hard
order: 3
tags: [raid, lvm, mdadm, dmraid, reconstruction, stripe, parity, unraid]
prerequisites: [forensics-disk-images]
useful_for:
  - "CTF Forensics категория"
  - "Data recovery (серверы/NAS)"
  - "Incident Response"
estimated_minutes: 60
summary: "Реконструкция RAID-массивов (0/1/5/6) и LVM из образов: определение layout, порядок дисков, размер stripe, сборка через mdadm, работа с missing-дисками."
---

Серверные образы часто представляют собой **набор** отдельных дисков, объединённых в RAID-массив и/или LVM. Если анализировать один такой образ как обычный диск, вы увидите «мусор»: ни таблицы разделов, ни ФС. Чтобы добраться до данных, нужно **реконструировать массив** — определить тип RAID, порядок дисков, размер stripe и собрать виртуальное устройство. Этот урок — про это.

## Как понять, что перед вами RAID/LVM

Признаки:
- Диск не имеет таблицы разделов (`mmls` даёт пусто/мусор), но содержит сигнатуру RAID.
- Есть подозрительные метки: `mdadm` superblock, `LVM2_member`, `Linux RAID`, `isw_raid` (Intel).
- `blkid` показывает `TYPE="linux_raid_member"` или `TYPE="LVM2_member"`.

```bash
# Быстрая диагностика каждого образа
blkid disk0.img disk1.img disk2.img
# disk0.img: TYPE="linux_raid_member" ...
# disk1.img: TYPE="linux_raid_member" ...

# Сигнатуры
xxd -s 0 -l 512 disk0.img | grep -i 'md\|raid\|LVM'

# Найти суперблок mdadm (offset 0 для 1.x, 64K для 0.90)
strings -a disk0.img | grep -iE 'linux_raid|mdadm|LVM2'
```

## Суперблок mdadm

Linux software RAID (mdadm) хранит **superblock**:
- **version 0.90** — в конце устройства (для 1.x) или offset 0 (для старых), magic `0xa92b4efc`.
- **version 1.x** — offset 0 (1.1), 8 KiB (1.0), или 4 KiB от конца (1.2). Хранит: уровень RAID, размер chunk (stripe), layout, порядок устройства, UUID, роль.

```bash
# Показать метаданные mdadm-суперблока
sudo mdadm --examine disk0.img
#  Magic : a92b4efc
#  Version : 1.2
#  Raid Level : raid5
#  Chunk Size : 512K
#  Device Role : Active device 0
#  Array UUID : ...
#  Data Offset : ...

# Все диски
for d in disk*.img; do echo "== $d =="; sudo mdadm --examine $d | grep -iE 'level|chunk|role|uuid|offset'; done
```

Ключевые поля: **Raid Level**, **Chunk Size** (stripe), **Device Role** (порядок диска в массиве), **Array UUID** (все диски одного массива), **Data Offset** (где начинаются данные).

## Типы RAID и восстановление

| RAID | Как работает | Нужно дисков | Восстановление |
|------|--------------|-------------:|----------------|
| 0 | stripe без чётности | ≥2 | все диски обязательны |
| 1 | mirror | ≥2 | достаточно одного |
| 5 | stripe + parity | ≥3 | допускает 1 missing |
| 6 | двойная parity | ≥4 | допускает 2 missing |
| 10 | mirror+stripe | ≥4 | по парам |

### RAID 0 (stripe)

Данные чередуются блоками по `chunk` между дисками. Нужны **все** диски и правильный порядок.

```bash
# Сборка через mdadm (если суперблок цел)
sudo mdadm --assemble --scan --uuid <uuid>
# или вручную
sudo mdadm --assemble /dev/md0 disk0.img disk1.img
sudo cat /proc/mdstat
```

### RAID 1 (mirror)

Достаточно одного диска — данные идентичны.

```bash
# Каждый диск — самостоятельная копия
mmls disk0.img
sudo mount -o ro,loop,offset=$((2048*512)) disk0.img /mnt/mirror
```

### RAID 5/6 (parity)

Данные + чётность (XOR для 5, Reed-Solomon для 6). При отсутствии одного диска (RAID5) данные восстанавливаются из чётности.

```bash
# Сборка с missing-диском (RAID5)
sudo mdadm --assemble /dev/md0 --level=5 --raid-devices=3 \
  disk0.img disk1.img missing
cat /proc/mdstat
sudo mount -o ro /dev/md0 /mnt/raid

# Или с «failed» устройством (создать пустой файл-заглушку)
truncate -s 100G missing.img
sudo mdadm --assemble /dev/md0 --level=5 --raid-devices=3 \
  disk0.img disk1.img missing.img
```

Если суперблок повреждён — используйте `--build`/`--create` с явными параметрами (уровень, число дисков, chunk, layout):

```bash
# Ручная сборка без метаданных (осторожно: read-only!)
sudo mdadm --build /dev/md0 --level=5 --raid-devices=3 --chunk=512 \
  --layout=left-symmetric disk0.img disk1.img disk2.img
```

Порядок дисков и layout критичны: при неверном порядке RAID5 не соберётся или даст «мусор». Пробуйте все перестановки (для 3 дисков — 6 вариантов) и проверяйте результат (`file`, `mmls`).

## LVM: поверх RAID или напрямую

LVM-раздел (`LVM2_member`) содержит **PV** (physical volume) с метаданными: **VG** (volume group) и **LV** (logical volumes).

```bash
# Прямая активация LVM из образа
sudo losetup -Pf --show disk.img         # /dev/loop0
sudo pvscan; sudo vgscan
sudo vgchange -ay
ls /dev/mapper/                          # vg-root, vg-swap, ...
sudo mount -o ro /dev/mapper/vg-root /mnt/lvm

# Если автоскан не видит (образ без таблицы разделов):
sudo losetup -f --show --offset 1048576 --sizelimit ... disk.img
```

Ручной разбор через `pvck`/`pvs -v`:

```bash
sudo pvck --dump headers disk.img 2>/dev/null | head
# Метаданные LVM лежат в начале PV; можно извлечь текстовый дамп
sudo vgcfgrestore --list <vg> 2>/dev/null
```

Если VG «размазана» по нескольким образам (RAID), сначала соберите массив, потом активируйте LVM поверх `/dev/md0`.

## dmraid / fake RAID (Intel RST, isw)

Аппаратно-программный (fakeraid) массив (Intel Rapid Storage `isw_raid_member`, dmraid) хранит метаданные в конце диска. `dmraid` активирует его как `/dev/mapper/isw_*`.

```bash
sudo dmraid -r              # список обнаруженных наборов
sudo dmraid -ay             # активировать
ls /dev/mapper/isw_*
sudo mount -o ro /dev/mapper/isw_xxx /mnt
```

## Реконструкция вручную (когда автоматика не справляется)

Если ни mdadm, ни dmraid не работают (разрушены суперблоки), массив собирают вручную скриптом/через `dd` по формуле stripe. Идея RAID0/5:
- данные разбиты на **chunks** (например 512K);
- chunk с индексом `i` лежит на диске `i mod N` (RAID0) или с учётом parity-ротации (RAID5);
- для RAID5 parity-блок смещается по диагонали (left/right, symmetric/asymmetric).

```python
# Скелет сборки RAID0 из N дисков
N = 3; CHUNK = 512*1024
disks = [open(f'disk{i}.img','rb') for i in range(N)]
out = open('raid0.img','wb')
# читаем chunk по очереди с дисков
i = 0
while True:
    d = disks[i % N]
    data = d.read(CHUNK)
    if not data: break
    out.write(data)
    i += 1
```

Для RAID5 нужно знать **layout** и **chunk**, а missing-диск восстанавливать XOR-ом соответствующих chunk-ов. Инструменты: `raidextract`, `raidreconstructor`, `ReclaiMe`, скрипты на Python.

## Разобранный пример: CTF «RAID5 с потерянным диском»

```bash
# Даны disk0.img disk1.img (3-й диск утерян)
for d in disk0.img disk1.img; do sudo mdadm --examine $d | grep -iE 'level|chunk|role|uuid'; done
# level=raid5, chunk=512K, raid-devices=3, uuid=<X>

# Собираем с missing
sudo mdadm --assemble /dev/md0 --level=5 --raid-devices=3 disk0.img disk1.img missing
cat /proc/mdstat

# Монтируем
mmls /dev/md0
sudo mount -o ro /dev/md0 /mnt/raid
ls -la /mnt/raid
cat /mnt/raid/flag.txt

# Если не собралось — пробуем перестановки/--build
sudo mdadm --stop /dev/md0 2>/dev/null
sudo mdadm --build /dev/md0 --level=5 --raid-devices=3 --chunk=512 \
  --layout=left-symmetric disk1.img disk0.img missing
```

## Частые ошибки

- **Анализировать один диск массива как целый** — нет ФС, потому что данные разбиты по stripe.
- **Забыть порядок дисков (Device Role)** — неверный порядок = «мусор»; пробуйте перестановки.
- **Игнорировать `chunk size`/`layout`** — критичны для RAID5/6.
- **Собирать массив read-write** — mdadm по умолчанию может инициализировать/перестроить; используйте `--readonly` и `--assume-clean`.
- **Путать LVM и RAID** — LVM может лежать поверх RAID; сначала массив, потом LVM.
- **Не проверять `Data Offset`** — данные начинаются не с 0, а после суперблока.
- **Забывать про fakeraid** — Intel RST требует dmraid, а не mdadm.

## Квиз

```quiz
- question: "Сколько дисков RAID5 может выйти из строя без потери данных?"
  options:
    - "0"
    - "1"
    - "2"
    - "зависит от ФС"
  answer: 1
- question: "Какой командой посмотреть метаданные mdadm-суперблока?"
  options:
    - "`mmls`"
    - "`mdadm --examine`"
    - "`pvscan`"
    - "`fls`"
  answer: 1
- question: "Какое поле mdadm-суперблока задаёт порядок диска в массиве?"
  options:
    - "Array UUID"
    - "Device Role"
    - "Data Offset"
    - "Chunk Size"
  answer: 1
- question: "Какой тип массива позволяет восстановить данные с одного диска?"
  options:
    - "RAID0"
    - "RAID1 (mirror)"
    - "RAID5"
    - "RAID6"
  answer: 1
- question: "Как активировать LVM из образа?"
  options:
    - "`mmls` + `icat`"
    - "`losetup -Pf` + `pvscan`/`vgchange -ay`"
    - "`mdadm --assemble`"
    - "`ewfmount`"
  answer: 1
```

## Где пригодится

- **CTF:** задачи с наборами дисков, RAID5 с потерянным диском, LVM.
- **Data recovery:** восстановление серверных массивов после сбоя.
- **Incident Response:** разбор серверов/NAS с RAID и LVM.
- **Судебная экспертиза:** корректная реконструкция без изменения улик.
- **Enterprise:** работа с СХД и виртуализацией.
