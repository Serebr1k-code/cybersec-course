---
id: hardware-squashfs
title: "SquashFS глубоко: сжатие, блоки, сборка и модификация rootfs"
category: hardware
parent: hardware-filesystems
difficulty: medium
order: 1
tags: [squashfs, unsquashfs, mksquashfs, lzma, xz, rootfs, openwrt, firmware]
prerequisites: [hardware-firmware-extract]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Пентест IoT: модификация прошивки"
  - "Реверс прошивок роутеров и камер"
estimated_minutes: 40
summary: "Устройство SquashFS, все сжатия, точная распаковка, сборка обратно и модификация rootfs без пересборки прошивки."
---

SquashFS — самая распространённая read-only файловая система во встраиваемых Linux-устройствах. Её используют OpenWrt, DD-WRT, IP-камеры, NVR, точки доступа. Она компактна, поддерживает сжатие и работает из read-only флеша. Для пентестера важны три вещи: **точно распаковать**, **изменить** (добавить бэкдор/учётку) и **собрать обратно** так, чтобы устройство загрузилось. Этот урок — про внутреннее устройство и практическую работу.

## Устройство формата

SquashFS-образ начинается с суперблока (96 байт). Магия — `hsqs` (`68 73 71 73`). Суперблок содержит: версию (3.x или 4.0), размер блока (обычно 131072 = 128 КиБ), тип сжатия, размеры таблиц inode и directory, размер образа. Данные хранятся в виде сжатых блоков; метаданные (inode, каталоги) — в отдельных сжатых таблицах.

Ключевые понятия:

- **Block size**: 4 КиБ – 1 МиБ (обычно 128 КиБ). Большие блоки — лучше сжатие, хуже random access.
- **Compression**: gzip, lzo, lz4, xz, zstd, lzma. Указывается в суперблоке.
- **Inode types**: файлы, каталоги, симлинки, device nodes, FIFO. SquashFS 4.0 не поддерживает «sparse» файлы.
- **Fragment blocks**: мелкие файлы пакуются в общий фрагмент-блок для экономии.

Версия критична: `unsquashfs` 4.x не всегда понимает образы 3.x и наоборот.

## Определение версии и сжатия

```bash
# Просто через file
file rootfs.squashfs
# rootfs.squashfs: Squashfs filesystem, little endian, version 4.0, compression:gzip,
# size: 6291456 bytes, 1204 inodes, blocksize: 131072 bytes, created: ...

# Детально через unsquashfs -s (superblock info)
unsquashfs -s rootfs.squashfs
# Found a valid SQUASHFS 4:0 superblock on rootfs.squashfs.
# Creation or last append time ...
# Filesystem size 6291456 bytes
# Compression gzip
# Block size 131072
# Number of fragments 412
# Number of inodes 1204
# Number of ids 1
```

Для старых образов с LZMA (SquashFS 4.0 non-standard LZMA) нужен `unsquashfs-lzma` — обычный не поймёт: выдаст «Filesystem uses unknown compression».

## Точная распаковка

Если у вас чистый squashfs-образ:

```bash
unsquashfs -d rootfs/ rootfs.squashfs
# Parallel unsquashfs: Using 8 processors
# 1204 inodes (1500 blocks) to write
# created 1204 files
# created 300 directories
# created 200 symlinks
```

Если squashfs внутри большого дампа — найдите смещение и размер:

```bash
binwalk dump.bin | grep -i squashfs
# 131072  0x20000  Squashfs filesystem, little endian, version 4.0, size: 15073280 bytes

# Вариант A: вырезать dd (используйте bs=1M для скорости)
dd if=dump.bin of=rootfs.squashfs bs=1 skip=131072 count=15073280 status=progress

# Вариант B: указать смещение прямо unsquashfs
unsquashfs -o 131072 -d rootfs/ dump.bin
```

Флаг `-o <offset>` избавляет от `dd`. Полезные флаги: `-l` (список без распаковки), `-ll` (длинный список с правами), `-stat` (inode-таблица), `-f` (перезаписать выход), `-no-xattrs`.

## Что искать после распаковки

```bash
cd rootfs
# Учётки
grep -vE 'nologin|false|sync' etc/passwd
cat etc/shadow 2>/dev/null
# Инициализация и автозапуск
ls -la etc/init.d/ etc/rc.d/ 2>/dev/null
grep -rE 'telnetd|dropbear|nc -l|/bin/sh' etc/ | head
# Ключи и сертификаты
find . -type f \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' \) 2>/dev/null
# CGI и веб
ls -la www/ usr/lib/cgi-bin/ 2>/dev/null
# Бэкдоры по строкам
grep -rIn 'hardcoded\|backdoor\|magic' etc/ 2>/dev/null | head
```

## Модификация rootfs

Часто цель — добавить свой пользователя/ключ и вернуть образ. Порядок:

```bash
# 1. Распаковать
unsquashfs -d rootfs/ rootfs.squashfs

# 2. Добавить root-учётку с известным паролем (для лаборатории!)
#    Сгенерировать хэш md5crypt: openssl passwd -1 -salt x secret
NEWHASH=$(openssl passwd -1 -salt abc 'hunter2')
echo "pentest:$NEWHASH:0:0::/root:/bin/sh" >> rootfs/etc/passwd
#    или положить SSH-ключ
mkdir -p rootfs/root/.ssh
cat id_rsa.pub > rootfs/root/.ssh/authorized_keys

# 3. Собрать обратно тем же сжатием и блоками
mksquashfs rootfs/ rootfs_new.squashfs -comp gzip -b 131072 -noappend

# 4. Узнать размер и вшить обратно в дамп по тому же смещению
ls -l rootfs_new.squashfs
dd if=rootfs_new.squashfs of=dump_new.bin bs=1 seek=131072 conv=notrunc
```

Ключевой момент — **сохранить размер или меньше** исходного squashfs и то же сжатие. Если новый образ больше — он затрёт следующий раздел (JFFS2/UBI) и устройство не загрузится. Часто приходится освобождать место: удалять ненужные пакеты, `-comp xz` даёт меньший размер.

## Сборка с нужными параметрами

| Параметр | Значение по умолчанию | Рекомендация |
|----------|----------------------|--------------|
| `-comp` | gzip | повторить исходное (gzip/xz/lzo) |
| `-b` | 131072 | как в суперблоке |
| `-noappend` | — | всегда, чтобы не дописывать в существующий |
| `-no-xattrs` | выкл | если устройство не поддерживает xattr |
| `-all-root` | выкл | выставить root:root на все файлы |
| `-noI -noD -noF` | выкл | не сжимать (отладка) |

Для big-endian устройств `mksquashfs` принимает `-be` (на некоторых сборках) — иначе образ не смонтируется.

## Проверка и эмуляция результата

Перед прошивкой собранный образ стоит проверить локально:

```bash
# Монтирование на хосте
mkdir -p mnt && sudo mount -o loop,ro rootfs_new.squashfs mnt
ls mnt/etc/passwd
sudo umount mnt

# Или распаковать обратно и сверить
unsquashfs -l rootfs_new.squashfs | wc -l
```

Если устройство поддерживает обновление через веб/`sysupgrade`, можно залить модифицированный образ штатным путём — но убедитесь, что контрольная сумма/подпись обновления не проверяется (иначе нужен обход secure boot, см. `hardware-secure-boot`).

## Частые ошибки и подводные камни

- **Неверный `count` при `dd`**: обрезает образ → «failed to read fragment table».
- **Пропущены xattrs/symlinks**: распаковка «в текущую папку» с абсолютными симлинками может затереть систему — всегда `-d dir`.
- **Другой `-comp`**: если собрать xz там, где ядро ждёт gzip, монтирование упадёт с «unsupported compression».
- **Размер больше исходного**: затирание соседнего раздела.
- **LZMA 4.0**: обычный `unsquashfs` не читает; нужен `-lzma` сборка.
- **Права**: `mksquashfs` без `-all-root` сохранит владельца хоста — на устройстве это может дать неработающие сервисы.

## Сжатие: выбор и влияние на размер

Тип сжатия в squashfs влияет и на размер образа, и на то, сможет ли устройство его смонтировать. Ядро встраиваемой системы должно быть собрано с поддержкой выбранного алгоритма. Если производитель использовал xz, а вы пересоберёте gzip — образ будет больше; наоборот, xz там, где ядро знает только gzip, вообще не смонтируется.

Ориентировочные коэффициенты (от исходного размера файлов):

| Алгоритм | Степень сжатия | Скорость распаковки | Поддержка в ядре |
|----------|----------------|---------------------|------------------|
| gzip | ~2.5× | высокая | почти всегда |
| lzo | ~2× | очень высокая | часто (для роутеров) |
| lz4 | ~1.8× | максимальная | современные ядра |
| xz | ~3.5× | низкая | требует `CONFIG_SQUASHFS_XZ` |
| zstd | ~3× | средняя | новые ядра |

Практический приём: чтобы уместить модифицированный rootfs в тот же раздел, сначала попробуйте собрать с `-comp xz` — это даёт максимальную экономию. Если и этого мало, удалите из rootfs ненужные локали, документацию, лишние бинарники, `opkg`/`apk` кэш.

## Работа без root и в контейнере

`unsquashfs` не требует root — это важное преимущество перед монтированием. В изолированном контейнере без `CAP_SYS_ADMIN` команда `mount -o loop` не сработает, а `unsquashfs -d` работает всегда. Для сборки обратно `mksquashfs` тоже не требует привилегий, но нужно сохранить владельца: флаг `-all-root` выставит `root:root` на все файлы, что обычно и нужно для прошивки. Если устройство использует нестандартного владельца сервиса (например, uid 1000 для веб-демона), не применяйте `-all-root` слепо — сверьтесь с распакованным оригиналом через `unsquashfs -ll` и `stat`.

## SquashFS 3.x и нестандартные сборки

Иногда встречаются образы SquashFS 3.x (более старый формат с другой раскладкой inode). `unsquashfs` 4.x может их не понять. Признак — в `file` указано `version 3.0`. Для таких образов ищут статический `unsquashfs3` или собирают `squashfs-tools` старой версии. Ещё один нюанс — **non-standard LZMA**: производитель патчит squashfs-tools и кладёт LZMA вместо официально поддерживаемых алгоритмов. Определяется по ошибке `Filesystem uses unknown compression`. Решение — статический `unsquashfs-lzma` (часто есть в репозиториях прошивочных утилит). Если образ не читается вообще, стоит проверить, не завёрнут ли он в собственный контейнер производителя (иногда squashfs сдвинут на несколько байт или XOR-нут по заголовку).

## Что дальше / решение

- Нужны учётки → гнать хэши в `hashcat -m 500`/`-m 1800`.
- Нужен доступ → модифицировать rootfs и пересобрать (следите за размером).
- Нужна динамика → эмулировать бинарники в QEMU (`hardware-firmware-emulation`).
- Образ зашифрован → вернуться к анализу заголовков и ключей в загрузчике.

## Квиз

```quiz
- question: "Какая магия у SquashFS?"
  options:
    - "hsqs"
    - "UBI#"
    - "0x1985"
    - "sqsh только в конце"
  answer: 0
  explanation: "Образ начинается с hsqs; sqsh встречается в конце."
- question: "Что произойдёт, если новый squashfs больше исходного?"
  options:
    - "Ничего"
    - "Он затрёт следующий раздел и устройство не загрузится"
    - "Ядро его обрежет"
    - "Он сожмётся автоматически"
  answer: 1
  explanation: "Размер образа ограничен отведённым разделом флеша."
- question: "Чем распаковать образ с нестандартным LZMA?"
  options:
    - "обычным unsquashfs"
    - "unsquashfs-lzma"
    - "jefferson"
    - "7z"
  answer: 1
  explanation: "Нестандартный LZMA читает только патченая сборка unsquashfs-lzma."
- question: "Какой флаг mksquashfs не дописывает в существующий образ?"
  options:
    - "-noappend"
    - "-all-root"
    - "-be"
    - "-noI"
  answer: 0
  explanation: "-noappend создаёт новый образ вместо дописывания."
- question: "Как указать unsquashfs смещение squashfs внутри дампа?"
  options:
    - "-d dir"
    - "-o 131072"
    - "-stat"
    - "-l"
  answer: 1
  explanation: "-o задаёт смещение образа в файле."
```

## Где пригодится

- **CTF:** Hardware-задачи, где надо найти флаг в rootfs прошивки.
- **Пентест IoT:** добавление тестовой учётки/бэкдора для последующей проверки.
- **Реверс:** изучение того, как производитель собирает rootfs.
- **Работа:** анализ обновлений и проверка целостности прошивок.
- **Дальше по дереву:** `hardware-filesystems`, `hardware-firmware-extract`, `hardware-secure-boot`.
