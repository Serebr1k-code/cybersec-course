---
id: hardware-yaffs-romfs
title: "YAFFS и ROMFS"
category: hardware
parent: hardware-mod-embedded-fs
difficulty: medium
order: 1
tags: [yaffs, romfs, nand, filesystem]
prerequisites: [hardware-cramfs, hardware-filesystems]
useful_for:
  - "Реверс прошивок NAND-устройств"
  - "CTF Hardware/Forensics"
  - "Извлечение rootfs из дампа"
estimated_minutes: 40
summary: "Редкие встраиваемые ФС: YAFFS/YAFFS2 для NAND, минимальная ROMFS, их сигнатуры, извлечение, монтирование и подводные камни."
---

Squashfs, JFFS2 и UBIFS покрывают большинство прошивок, но встречаются и более редкие файловые системы. **YAFFS** (Yet Another Flash File System) — журнальная ФС, спроектированная специально под NAND-флеш, где каждый чип имеет «сырые» страницы с областью OOB (out-of-band) для служебных данных. **ROMFS** — минимальная read-only ФС, придуманная для экономии места в ядре Linux (её часто используют initramfs в embedded). Понимание обеих критично, когда стандартный `binwalk`/`unsquashfs` ничего не находит, а дамп NAND лежит на столе.

Этот урок — про то, как распознать YAFFS и ROMFS в сыром дампе, как их извлечь и смонтировать, и какие грабли поджидают. Мы разберём структуру обеих ФС, инструменты (`unyaffs`, `yaffs2utils`, `genromfs`) и два end-to-end примера: извлечение YAFFS из дампа NAND и ROMFS из прошивки.

## YAFFS: NAND-ориентированная ФС

NAND-флеш организован в блоки (erase blocks), каждый из которых делится на страницы (обычно 2048 или 4096 байт), а у каждой страницы есть дополнительная область **OOB/spare** (64-128 байт). NAND не умеет перезаписывать страницу — только стирать целый блок. Это порождает потребность в журнальных ФС с износоуравниванием (wear leveling) и учётом «плохих блоков».

YAFFS2 — именно такая ФС: каждый файл разбит на **chunks** (обычно размером со страницу, часто 2048 байт), а метаданные каждого chunk'а лежат в OOB-области страницы. Метаданные (tags) содержат: object ID, chunk ID (номер части файла), количество байт, тип объекта (файл/директория/symlink), а также ECC. Такая схема делает YAFFS очень устойчивой к обрывам питания, но крайне чувствительной к тому, как извлечён дамп: если OOB-данные потеряны (а многие дамперы их отбрасывают), YAFFS не собирается.

Ключевой момент для реверса: YAFFS существует **только** внутри NAND. Если у вас образ в формате «чистые данные без OOB», извлечение YAFFS невозможно без восстановления OOB. Если OOB на месте — нужен инструмент, который знает раскладку (например, `unyaffs`).

## Структура YAFFS/YAFFS2

Разберём элементы:

- **Chunk** — единица хранения данных, соответствует странице NAND (2048 байт для большого NAND, 512 для малого).
- **Tags / metadata** — лежат в OOB: `objectId`, `chunkId`, `byteCount`, `objectType`, `parentObjectId`, `checksum`, `ECC`.
- **Object header** — первый chunk объекта (chunkId=0) содержит заголовок: тип (файл/дир/symlink), права, uid/gid, размер, имя (в случае short name) и т.д.
- **Root** — objectId 1 (для root-директории).
- **Sequence number** — для wear leveling и определения актуальной версии блока.

YAFFS2 отличается от YAFFS1 тем, что поддерживает большие страницы (2048+) и хранит `chunkId` в более широком формате. Ошибка «взять YAFFS1-инструмент для YAFFS2-образа» приводит к мусору.

## ROMFS: минимальная read-only ФС

ROMFS появилась в Linux как максимально простая read-only ФС: у неё почти нет метаданных, а структура — плоский список inode'ов, ссылающихся друг на друга по смещению. Каждый inode ROMFS начинается с заголовка (magic `-rom1fs-`, размер, контрольная сумма, имя, выравнивание), за которым следуют данные (для файла) или ссылки на детей (для директории). Нет дат, нет прав в привычном виде — минимум.

Применение в embedded: initramfs, маленькие rootfs, recovery-разделы, UEFI/BIOS-образы, прошивки роутеров и IP-камер. Преимущество — крошечный размер кода парсера (ROMFS может читаться даже из bootloader). Недостаток — read-only и никаких журналов.

Сигнатура ROMFS: строка `-rom1fs-` в начале образа (8 байт), затем big-endian размер. Это отличный маркер для `binwalk` и ручного поиска.

## Инструменты: полный набор с флагами

```bash
# --- YAFFS ---
# unyaffs (классический, YAFFS1/YAFFS2):
unyaffs image.bin outdir/
unyaffs -v image.bin outdir/          # verbose
unyaffs -d image.bin outdir/          # debug

# yaffs2utils (более новый набор):
unyaffs2 image.bin outdir/            # извлечение YAFFS2
mkyaffs2image -f outdir/ new.bin      # сборка образа
mkyaffs2image -f -c 2048 -s 64 outdir/ new.bin   # chunk/spare size
yaffs2ls image.bin                    # листинг без извлечения

# --- ROMFS ---
# genromfs (создание):
genromfs -f romfs.img -d outdir/ -V "vol"     # -V: метка тома
genromfs -f romfs.img -d outdir/ -a 16        # -a: выравнивание

# ядро Linux умеет монтировать romfs:
mount -t romfs romfs.img /mnt/romfs

# --- binwalk / unblob (общий пайплайн) ---
binwalk image.bin
binwalk -eM image.bin            # -e: extract, -M: matryoshka (рекурсивно)
unblob image.bin -o outdir/      # современный автокаскад
```

Для NAND-дампов с OOB: **`nanddump`** (на устройстве), **`binwalk`** (определяет раскладку), **`ubireader`** (если поверх UBI). Для ROMFS — **`dumprom`**, **`romfs`** из `genromfs`, и монтирование средствами ядра.

## Разобранный пример: извлечение YAFFS из дампа NAND

Дано: `nand.bin` — сырой дамп NAND (страницы 2048 байт + 64 байта OOB), снятый `nanddump`.

**Шаг 1 — определение.** Смотрим, есть ли сигнатуры и как выровнены страницы:

```bash
binwalk nand.bin
# DECIMAL       HEXADECIMAL     DESCRIPTION
# 0             0x0             YAFFS filesystem, little endian
```

**Шаг 2 — проверка раскладки OOB.** YAFFS2 использует OOB; убеждаемся, что dump включает spare:

```bash
python3 - <<'EOF'
data = open('nand.bin','rb').read()
page, spare = 2048, 64
print("pages:", len(data)//(page+spare))
print("first OOB:", data[page:page+16].hex())
EOF
# OUTPUT: pages: 512
# first OOB: ffffffff00000001...   (tags присутствуют)
```

**Шаг 3 — извлечение.** Прогоняем unyaffs2:

```bash
unyaffs2 nand.bin outdir/
ls outdir/
# bin  dev  etc  lib  proc  sbin  usr  var  www
```

**Шаг 4 — разбор.** Ищем интересное: `/etc/shadow`, `/etc/passwd`, приватные ключи, конфиги:

```bash
ls -la outdir/etc/ | head
cat outdir/etc/passwd
# root:x:0:0:root:/root:/bin/sh
# admin:$1$abc$...:1000:1000::/home/admin:/bin/sh
```

**Шаг 5 — вывод.** Rootfs извлечён. Дальше — поиск уязвимых бинарников и секретов.

## Разобранный пример: ROMFS внутри прошивки

Дано: `firmware.bin` от IP-камеры; `binwalk` показывает squashfs и что-то странное.

**Шаг 1 — поиск сигнатуры ROMFS.**

```bash
grep -aboP '\-rom1fs\-' firmware.bin
# 0x00310000:-rom1fs-
```

**Шаг 2 — определение размера.** ROMFS-заголовок: 8 байт magic + 4 байта big-endian полного размера:

```bash
xxd -s 0x310000 -l 32 firmware.bin
# 00000000: 2d72 6f6d 3166 732d 000c 0000 0000 0000  -rom1fs-........
# размер = 0x000c0000 = 786432 байт
```

**Шаг 3 — вырезание и монтирование.**

```bash
dd if=firmware.bin of=romfs.img bs=1 skip=$((0x310000)) count=$((0x0c0000))
mkdir -p /mnt/romfs
sudo mount -t romfs romfs.img /mnt/romfs
ls /mnt/romfs
# bin  etc  lib  sbin  www
```

**Шаг 4 — вывод.** ROMFS — read-only, но содержимое доступно; часто содержит скрипты инициализации и CGI-бинарники веб-интерфейса.

## Монтирование и работа

- **YAFFS в Linux.** Модуль `yaffs2` (out-of-tree) умеет монтировать образы, но требует правильных параметров `mtd`/`chunk`. На практике чаще извлекают в каталог инструментом, а не монтируют.
- **ROMFS в Linux.** Встроен в ядро: `mount -t romfs` работает из коробки.
- **Loop-устройства.** Для обоих можно использовать `losetup`, но YAFFS нестандартен и требует спец-модуль.
- **Права.** При извлечении из NAND uid/gid берутся из заголовков объектов; для ROMFS прав как таковых нет.

## Частые ошибки и подводные камни

- **Потерянные OOB.** Если дампер отбросил spare-область, YAFFS не восстановить. Проверьте `nanddump` без `--oob` по ошибке.
- **YAFFS1 vs YAFFS2.** Разные раскладки chunkId. Используйте правильный инструмент; `unyaffs2` обычно справляется с обоими.
- **Неверный размер страницы.** 2048 vs 4096 vs 512. Если страница угадана неверно, извлекается мусор.
- **ECC/bit-flips.** Сырой NAND содержит ошибки; без ECC-коррекции часть данных битая.
- **ROMFS big-endian.** Размер и поля — big-endian; не путайте с little-endian.
- **Перекрытие с squashfs.** ROMFS может лежать внутри squashfs или наоборот; используйте `binwalk -eM` для рекурсии.
- **Монтирование YAFFS на хосте.** Out-of-tree модуль часто не собирается; извлекайте инструментом.

## Справочные таблицы

| ФС | Magic/сигнатура | Ориентация | Инструмент |
|----|-----------------|------------|------------|
| YAFFS1 | (нет явной, по OOB) | NAND, small page | unyaffs |
| YAFFS2 | (нет явной, по OOB) | NAND, large page | unyaffs2, yaffs2utils |
| ROMFS | `-rom1fs-` | read-only | mount -t romfs, dumprom |
| JFFS2 | `0x1985` в узле | NOR | jefferson |
| UBIFS | UBI (`UBI#`) | NAND (UBI) | ubireader |
| squashfs | `hsqs` | read-only | unsquashfs |

Размеры страниц NAND:

| NAND | Page | OOB |
|------|------|-----|
| Small-block | 512 | 16 |
| Large-block | 2048 | 64 |
| Large-block+ | 4096 | 128/224 |

## Что дальше / решение

После извлечения YAFFS/ROMFS переходите к: (1) анализу `/etc` на секреты (пароли, ключи, Wi-Fi PSK); (2) поиску SUID-бинарников и сервисов, стартующих при загрузке (`/etc/init.d`); (3) если ROMFS — read-only, ищите, где хранится записываемая конфигурация (часто JFFS2/UBI-раздел поверх). Для защиты: не храните секреты в rootfs в открытом виде, шифруйте разделы с ключами, ограничивайте доступ к debug-UART/JTAG. В авторизованном пентесте зафиксируйте тип ФС, метод извлечения и найденные секреты — это основа дальнейшего анализа прошивки.

## Квиз

```quiz
- question: "Где YAFFS хранит метаданные чанков?"
  options:
    - "В OOB/spare-области каждой страницы NAND"
    - "В отдельном файле-таблице в начале образа"
    - "В конце каждого файла"
    - "В загрузочной записи"
  answer: 0
- question: "Что произойдёт, если дамп NAND снят без OOB-области?"
  options:
    - "YAFFS не восстановить — метаданные потеряны"
    - "YAFFS извлечётся лучше"
    - "Образ автоматически расшифруется"
    - "Ничего не изменится"
  answer: 0
- question: "Какая сигнатура у ROMFS?"
  options:
    - "-rom1fs-"
    - "hsqs"
    - "UBI#"
    - "0x1985"
  answer: 0
- question: "Чем ROMFS принципиально ограничена?"
  options:
    - "Она read-only и почти без метаданных"
    - "Работает только с NAND"
    - "Требует 128-битного шифрования"
    - "Не поддерживается Linux"
  answer: 0
- question: "Какой инструмент извлекает YAFFS2?"
  options:
    - "unyaffs2 / yaffs2utils"
    - "unsquashfs"
    - "jefferson"
    - "ubireader"
  answer: 0
```

## Где пригодится

- **Реверс:** извлечение rootfs из NAND-устройств (камеры, роутеры, NAS).
- **CTF:** Hardware/Forensics-задачи с нестандартными ФС.
- **Пентест:** поиск секретов и уязвимых бинарников в прошивке.
- **Работа:** аудит встраиваемого ПО и forensics устройств.
