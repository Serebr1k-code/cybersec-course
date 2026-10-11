---
id: forensics-btrfs-zfs
title: "Btrfs / ZFS / XFS: форензика copy-on-write ФС"
category: forensics
parent: forensics-fs-internals
difficulty: hard
order: 3
tags: [btrfs, zfs, xfs, cow, snapshot, zpool, forensics]
prerequisites: [forensics-filesystems, forensics-ext4-journal]
useful_for:
  - "CTF Forensics категория"
  - "Data recovery (NAS/Linux)"
  - "Анализ серверных образов"
estimated_minutes: 60
summary: "Форензика современных CoW-файловых систем: Btrfs (суперблоки, деревья, snapshots), ZFS (uberblock, ZAP, zpool), XFS (AG, B-деревья), восстановление данных и поиск следов."
---

Btrfs, ZFS и XFS — «продвинутые» ФС, которые всё чаще встречаются на серверах, NAS и в CTF. Их объединяет принцип **copy-on-write (CoW)**: новые данные пишутся в новые блоки, а старые не перезаписываются. Для форензики это подарок — в старых блоках остаются **предыдущие версии** файлов и метаданных, доступные через snapshots и транзакции. Урок про то, как читать эти ФС и что искать.

## Общий принцип CoW

В обычных ФС (ext4, NTFS) перезапись файла затирает старые блоки. В CoW-ФС:
- данные всегда пишутся в **новые** блоки;
- метаданные обновляются копированием с изменением (copy-on-write);
- старые блоки освобождаются, но физически не затираются;
- **транзакции** (Btrfs) и **uberblock-история** (ZFS) хранят ссылки на прошлые состояния.

Отсюда два мощных приёма: **восстановление предыдущих версий** файлов и **поиск удалённых данных** в «мёртвых» блоках.

## Btrfs

Btrfs — дерево деревьев (B-деревья): суперблок → дерево корней → (FS tree, extent tree, checksum tree, chunk tree, device tree...).

Суперблок Btrfs — magic `_BHRfS_M` (0x4D5F53665248425F little-endian) в offset 0x10000 (64 KiB). Хранится **несколько копий** суперблока (по 64 KiB, 64 MiB, 256 GiB), что помогает при повреждении первого.

```bash
# Сигнатура
xxd -s 0x10000 -l 16 disk.img
# 5f 42 48 52 66 53 5f 4d  -> "_BHRfS_M"

# Инфо о ФС (нужен образ, смонтированный через loop или прямой доступ)
btrfs inspect-internal dump-super disk.img
btrfs filesystem show disk.img
```

Дерево корней (`tree_root`) содержит ссылки на все деревья и **snapshots**. Каждый snapshot — это поддерево с собственными корнями, хранящее состояние на момент снятия.

```bash
# Список файлов без монтирования (btrfs-progs)
btrfs restore -D disk.img out/          # восстановить всё
btrfs restore -l disk.img               # список
btrfs restore disk.img out/ -i          # с inode-инфо

# Смонтировать read-only и посмотреть snapshots
sudo mount -o ro,loop disk.img /mnt/btrfs
sudo btrfs subvolume list /mnt/btrfs
sudo btrfs subvolume snapshot /mnt/btrfs/@snapshots/old /tmp/snap_copy 2>/dev/null
ls /mnt/btrfs/@snapshots/old/          # старая версия файлов!
```

Снапшоты — главный источник «удалённого»: файл, удалённый в текущем состоянии, остаётся в старом snapshot.

```bash
# Поиск всех копий файла в снапшотах
find /mnt/btrfs -path '*snapshot*' -name 'secret*' 2>/dev/null

# Восстановление конкретной версии
cp /mnt/btrfs/@snapshots/2024-01-01/secret.txt /tmp/old_secret.txt
```

Удаление в Btrfs лишь снимает ссылку; блоки живут до сборки мусора. `btrfs restore` умеет вытаскивать данные по дереву extent без монтирования.

## ZFS

ZFS — пул (zpool) из vdev-ов; поверх — datasets (ФС/тома). Всё через **ZAP** (ZFS Attribute Processor, аналог словаря) и uberblock.

- **uberblock** — корень; ZFS хранит кольцо из 128 uberblock-ов, каждый со своим TXG (transaction group). Пока txg не «закреплён» (pool sync), старые uberblock-и указывают на предыдущие состояния.
- **ZAP** — хранит свойства, имена, данные в виде key/value.
- **Dataset** — namespace, снапшоты (`@snap`).

```bash
# Импорт пула из образа (loop)
sudo losetup -Pf --show disk.img      # /dev/loop0
sudo zpool import -d /dev/loop0 pool_tmp -R /mnt/zfs -o readonly=on
zfs list
zfs get all pool_tmp

# Снапшоты — предыдущие состояния
zfs list -t snapshot
zfs snapshot pool_tmp@now 2>/dev/null   # (на ro-пуле не выйдет — пример)
ls /mnt/zfs/pool_tmp/.zfs/snapshot/     # доступ к снапшотам как к каталогу
cat /mnt/zfs/pool_tmp/.zfs/snapshot/old/secret.txt
```

Важно: монтировать ZFS **только readonly** (`-o readonly=on`), иначе импорт изменит пул и перезапишет TXG-историю.

Прямой разбор без импорта — через `zdb`:

```bash
# Показать uberblock-и и их TXG
zdb -l disk.img
zdb -u disk.img
# Дамп объекта по номеру (ZAP, файл)
zdb -R disk.img 0:1000:1000
```

`zdb` позволяет достать данные по object number, если известен layout, и увидеть историю uberblock-ов.

## XFS

XFS — журналируемая ФС с **allocation groups (AG)**: том делится на AG, каждая со своим суперблоком, свободным списком и B-деревьями. Magic суперблока `XFSB` (0x58465342), в начале каждой AG (AG-0 в offset 0).

Структуры:
- **AGF** (free space B-tree), **AGI** (inode B-tree), **AGFL** (freelist).
- **Inode** — с B-деревом экстентов (data fork) и атрибутов.
- **Журнал** (log) — отдельный регион, транзакции метаданных.

```bash
# Инфо без монтирования
xfs_info disk.img        # размеры блоков, AG, версии
xfs_db -r disk.img       # интерактивно, read-only
# в xfs_db:
#   sb           — суперблок
#   agf 0        — allocation group free
#   p uuid
#   inode <num>  — inode
```

```bash
# Список файлов через sleuthkit (поддерживает XFS)
mmls disk.img
fls -r -o <offset> disk.img
icat -o <offset> disk.img <inode> > file.bin
```

Журнал XFS (`xfs_logprint`) хранит транзакции: создание/удаление inode, directory entries — источник имён удалённых файлов.

```bash
xfs_logprint -t disk.img | head -100
```

## Восстановление данных и поиск следов

Общий подход для CoW-ФС:

```bash
# 1. Btrfs: восстановление без монтирования
btrfs restore -D disk.img out/

# 2. ZFS: монтируем ro, идём в .zfs/snapshot
zfs list -t snapshot

# 3. XFS: sleuthkit + xfs_logprint
fls -r -o <offset> disk.img

# 4. Универсально: carving по «мёртвым» блокам
strings -n 6 disk.img | grep -iE 'flag|CTF\{'
binwalk disk.img
```

## Разобранный пример: CTF «секрет в снапшоте»

```bash
file disk.img
# -> BTRFS filesystem / ZFS / XFS

# --- Btrfs ---
xxd -s 0x10000 -l 8 disk.img          # _BHRfS_M
btrfs restore -l disk.img | grep -i secret
btrfs restore disk.img out/           # вытащить дерево
ls -R out | grep -i secret
sudo mount -o ro,loop disk.img /mnt/b
ls /mnt/b/@snapshots/                 # старые снапшоты
cat /mnt/b/@snapshots/*/secret.txt

# --- ZFS ---
sudo losetup -Pf --show disk.img
sudo zpool import -d /dev/loop0p1 p -R /mnt/z -o readonly=on
zfs list -t snapshot
cat /mnt/z/p/.zfs/snapshot/*/secret.txt

# --- XFS ---
xfs_info disk.img
fls -r -o <offset> disk.img
xfs_logprint -t disk.img | grep -i secret
```

## Частые ошибки

- **Импортировать/монтировать ZFS read-write** — перезапишет uberblock-историю. Только `-o readonly=on`.
- **Искать Btrfs суперблок в offset 0** — он в 0x10000 (64 KiB); копии — по 64 MiB и 256 GiB.
- **Считать, что удалённое в CoW-ФС исчезло** — данные живут до GC/scrub; ищите в снапшотах и свободных блоках.
- **Забывать про `.zfs/snapshot`** — самый быстрый путь к предыдущим версиям.
- **Путать AG в XFS с разделами** — это внутренние группы одной ФС.
- **Игнорировать checksum-ошибки** — повреждённый суперблок Btrfs ⇒ пробуйте его копии.

## Квиз

```quiz
- question: "В чём смещение основного суперблока Btrfs?"
  options:
    - "offset 0"
    - "offset 1024"
    - "offset 0x10000 (64 KiB)"
    - "offset 0x400"
  answer: 2
- question: "Как в ZFS получить доступ к предыдущему состоянию датасета?"
  options:
    - "через `.zfs/snapshot/<name>`"
    - "через `$MFT`"
    - "через ext4 journal"
    - "только перезагрузкой"
  answer: 0
- question: "Почему в CoW-ФС удалённые данные дольше живут на диске?"
  options:
    - "они шифруются"
    - "новые данные пишутся в новые блоки, старые не затираются"
    - "они сжимаются"
    - "их хранит суперблок"
  answer: 1
- question: "Какая сигнатура (magic) у суперблока XFS?"
  options:
    - "`XFSB`"
    - "`_BHRfS_M`"
    - "`0xEF53`"
    - "`NTFS`"
  answer: 0
- question: "Чем опасно монтирование ZFS-пула read-write при форензике?"
  options:
    - "не хватит памяти"
    - "перезапишется uberblock-история и улики"
    - "пул станет недоступен навсегда"
    - "пропадут снапшоты навсегда"
  answer: 1
```

## Где пригодится

- **CTF:** образы NAS/серверов с Btrfs/ZFS/XFS, снапшоты.
- **Data recovery:** восстановление из CoW-ФС и снапшотов.
- **Incident Response:** анализ серверных хостов и NAS.
- **Судебная экспертиза:** предыдущие версии файлов как доказательства.
- **Enterprise:** разбор корпоративных СХД и систем хранения.
