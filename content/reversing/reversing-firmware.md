---
id: reversing-firmware
title: "Реверс прошивок (firmware)"
category: reversing
parent: reversing-static-targets
difficulty: hard
order: 1
tags: [reversing, firmware, binwalk, squashfs, uboot, iot, emulation]
prerequisites: [reversing-static-analysis, reversing-file-formats]
useful_for:
  - "CTF Reversing / IoT"
  - "Пентест IoT и роутеров"
  - "Анализ прошивок"
estimated_minutes: 55
summary: "Извлечение и анализ прошивок: binwalk, файловые системы, u-boot, эмуляция, поиск секретов."
---

## Задача

Тебе дали файл `firmware.bin` — образ прошивки роутера или IoT-устройства. Нужно найти
внутри секреты (пароли, токены), понять, какие сервисы там крутятся, и где могут быть
уязвимости. Проблема: это **не один** файл, а конкатенация загрузчика, ядра, файловой
системы и конфигов. Прежде чем что-то анализировать, образ надо **разобрать на части**.

## Данные: что это за файл

```bash
$ file firmware.bin
firmware.bin: data
$ ls -la firmware.bin
-rw-r--r-- 1 ... 4160 ... firmware.bin
```

`file` говорит «data» — формат не распознан. Это типично: прошивка — сырой образ
флеш-памяти. Смотрим на байты:

```bash
$ xxd firmware.bin | head -4
00000000: 3f0a 8e1c ... (случайные байты заголовка)
00000040: 6873 7173 ... 
```

На смещении `0x40` видно `hsqs` — это **сигнатура SquashFS**, популярной сжатой файловой
системы embedded-устройств (байты `hsqs` = «sqsh» наоборот). Значит, начиная с этого места
лежит ФС, а первые 64 байта — заголовок (часто u-boot/uImage).

## Шаг 1: находим и вырезаем разделы

Штатный инструмент для этого — **`binwalk`**: он сканирует образ по сигнатурам и извлекает
найденные компоненты (`binwalk -Me firmware.bin` — рекурсивно). Но полезно уметь сделать то
же вручную, когда сигнатуры нестандартные. Найдём смещение магии:

```bash
$ grep -abo 'hsqs' firmware.bin
64:hsqs
```

`grep -abo` печатает смещение (64) совпадения. Вырезаем ФС с этого смещения:

```bash
$ dd if=firmware.bin of=fw_sqfs.img bs=1 skip=64
4096+0 records in
4096+0 records out
```

## Шаг 2: распаковываем SquashFS

```bash
$ unsquashfs -d fw_extract fw_sqfs.img
Parallel unsquashfs: Using 8 processors
6 inodes (1.05K blocks) to write
created 6 files
$ find fw_extract -type f
fw_extract/etc/config.ini
fw_extract/etc/passwd
fw_extract/usr/bin/gatekeeper
```

Файловая система распакована. Для других ФС инструменты свои: CramFS — `cramfsck -x`,
JFFS2 — `jefferson`, UBI/UBIFS — `ubireader_extract_images`, initramfs (cpio+gzip) —
`zcat initramfs.cpio.gz | cpio -idmv`.

## Шаг 3: ищем секреты

Вот почему важно распаковать ФС: SquashFS **сжат**, поэтому `strings` по сырому образу
почти ничего не даёт.

```bash
$ strings -a firmware.bin | grep -iE 'token|passwd|flag'
(пусто)
```

А внутри извлечённой ФС секреты лежат открыто:

```bash
$ grep -rniE 'password|secret|token|api_key' fw_extract
fw_extract/etc/config.ini:1:BACKDOOR_TOKEN=sup3rs3cr3t_flag{fw_1}
$ cat fw_extract/etc/passwd
root:x:0:0:root:/root:/bin/sh
admin:$1$S4lt$deadbeefdeadbeefdeadbeef:1000:1000::/home/admin:/bin/sh
```

Два вывода: **бэкдор-токен** в `config.ini` и учётка `admin` с хешем пароля в `passwd`.
Типичные находки: хардкод-пароли (`admin:admin`), приватные ключи, лишние аккаунты.

## Шаг 4: определяем архитектуру и анализируем бинарники

Embedded — это часто MIPS/ARM, а не x86. Смотрим целевой бинарник:

```bash
$ file fw_extract/usr/bin/gatekeeper
...: ELF 64-bit LSB executable, x86-64, ... not stripped
```

Здесь x86-64 (в реальных роутерах ты увидишь `MIPS`, `ARM`, `AArch64`). Архитектура важна:
она определяет, как эмулировать и как декомпилировать. Дальше — обычный статический анализ
(строки, дизассемблер), плюс поиск веб-сервера и CGI:

```bash
$ find fw_extract -name '*httpd*' -o -name '*.cgi' -o -name 'lighttpd*'
$ grep -rn 'system(' fw_extract/www 2>/dev/null
```

**CGI-скрипты** — главный источник command injection в IoT: они часто вызывают
`system()`/`popen()` с пользовательским вводом без фильтрации.

## Шаг 5: эмуляция и динамика

Чтобы проверить уязвимость живьём, прошивку (или отдельный бинарник) запускают под QEMU:

```bash
# один бинарник: qemu-user с указанием sysroot
$ qemu-mips -L fw_extract fw_extract/usr/sbin/httpd
# ядро + ФС целиком: qemu-system
$ qemu-system-mips -M malta -kernel vmlinux -hda rootfs.ext2 -nographic
```

Обрати внимание на endianness: `qemu-mips` — big-endian, `qemu-mipel` — little-endian; ошибка
здесь — самая частая причина «не запускается». Для отладки QEMU отдаёт **GDB stub**:

```bash
$ qemu-mips -g 1234 -L fw_extract fw_extract/usr/sbin/httpd
$ gdb-multiarch fw_extract/usr/sbin/httpd -ex 'target remote :1234'
(gdb) b *0x400abc
(gdb) c
```

Так ставят точки останова в прошивочном коде без физического устройства.

## Инструменты

| Инструмент | Назначение | Пример |
|---|---|---|
| `binwalk` | сканирование/извлечение по сигнатурам | `binwalk -Me fw.bin` |
| `unsquashfs` | SquashFS | `unsquashfs -d rootfs fs.sqsh` |
| `jefferson` | JFFS2 | `jefferson -d out img` |
| `ubireader_extract_images` | UBI/UBIFS | `ubireader_extract_images ubi` |
| `qemu-*` | user/system-эмуляция | `qemu-mips -L rootfs bin` |
| `firmadyne`/`FirmAE` | авто-распаковка+эмуляция | `./run.sh` |

`firmadyne`/`FirmAE` автоматизируют весь конвейер: распаковка → определение NVRAM → запуск
под QEMU → доступ к веб-интерфейсу. Это экономит часы при анализе веб-уязвимостей.

## Разделы MTD и зашифрованные образы

Большинство прошивок — это конкатенация разделов с таблицей **MTD** (Memory Technology
Device). Раскладку часто можно увидеть прямо в строках ядра/загрузчика:

```bash
$ strings -a firmware.bin | grep -iE 'mtd|partition|kernel|rootfs|nvram'
# типичная раскладка:
# 0x000000 bootloader
# 0x040000 kernel
# 0x200000 rootfs (squashfs)
# 0x700000 nvram
```

Тогда раздел вырезается по смещению через `dd` (`dd if=fw.bin of=rootfs.sqsh bs=1 skip=$((0x200000))`).
Это спасает, когда `binwalk` даёт «мусор» из-за нестандартных заголовков.

Если образ **зашифрован** (высокая энтропия, нет сигнатур), вариантов несколько: ключ
расшифровки иногда лежит в загрузчике (U-Boot/CFE) открытым текстом; у семейства устройств
ключ может повторяться между моделями; а самый надёжный путь — снять дамп с живого
устройства (расшифровка идёт на лету, дамп уже «чистый»).

## UART/JTAG: доступ к устройству

Когда образ зашифрован или нужен рантайм, помогает физический доступ. UART-консоль часто
даёт shell прямо на устройстве:

```bash
$ picocom -b 115200 /dev/ttyUSB0
```

Если видишь U-Boot — можно дампить флеш из памяти (`md.b 0x80000000 0x100000`). JTAG/SWD даёт
доступ к отладке CPU через `openocd`: чтение/запись памяти и точки останова в прошивке даже
при включённой защите. Это уже уровень `reversing-hardware-debug`.

## Если не сработало

- **`file` не распознаёт образ / `binwalk` даёт мусор** — режьте по известным смещениям
  вручную (`dd` + `grep -abo`), как мы и сделали.
- **ФС не распаковывается** — возможно, корневая ФС внутри `initramfs.cpio.gz`, а не в squashfs.
- **Бинарник не запускается под QEMU** — проверь `readelf -h`: не тот endianness или нужен `-L sysroot`.
- **Образ зашифрован** — высокая энтропия (`binwalk -E`), нет сигнатур. Тогда ключ ищут в
  загрузчике (U-Boot/CFE) или снимают дамп с устройства (UART/JTAG) — он уже расшифрован.

## Что мы теперь знаем

- Прошивка — конкатенация разделов; ФС ищут по сигнатуре (`hsqs` для SquashFS) и вырезают по смещению.
- SquashFS сжат — `strings` по сырому образу бесполезен, нужна распаковка (`unsquashfs`).
- Секреты (токены, пароли, ключи) обычно лежат в `/etc` извлечённой ФС.
- Архитектура embedded (MIPS/ARM) определяет эмуляцию; `qemu-*` + GDB stub дают динамический анализ.

## Квиз

Проверь себя.

```quiz
- question: "Какая сигнатура соответствует SquashFS?"
  options:
    - "`\\x1f\\x8b`"
    - "`hsqs`"
    - "`UBI#`"
    - "`cramfs`"
  answer: 1
  explanation: "SquashFS начинается с магии `hsqs`."
- question: "Что делает `binwalk -Me firmware.bin`?"
  options:
    - "Рекурсивно извлекает все распознанные слои"
    - "Только показывает карту без извлечения"
    - "Прошивает устройство"
    - "Эмулирует образ"
  answer: 0
  explanation: "`-M` (Matryoshka) — рекурсия, `-e` — извлечение."
- question: "Почему `strings` по сырому образу почти ничего не нашёл?"
  options:
    - "В образе нет строк"
    - "Файловая система (SquashFS) сжата — содержимое нужно сначала распаковать"
    - "`strings` не поддерживает firmware"
    - "Строки зашифрованы паролем"
  answer: 1
  explanation: "Сжатие прячет содержимое; секреты видны только после `unsquashfs`."
- question: "Где чаще всего лежат hardcoded-пароли в прошивке?"
  options:
    - "В ядре Linux"
    - "В `/etc/shadow`, `/etc/passwd`, конфигах и бинарниках веб-приложения"
    - "В заголовке SquashFS"
    - "В загрузчике u-boot всегда"
  answer: 1
  explanation: "Учётные записи и токены — в конфигах/`passwd` извлечённой ФС."
- question: "Чем `qemu-mips` отличается от `qemu-mipsel`?"
  options:
    - "Endianness: `mips` — big-endian, `mipsel` — little-endian"
    - "`qemu-mipsel` устарел"
    - "`qemu-mips` быстрее"
    - "Разницы нет"
  answer: 0
  explanation: "Буква `el` = little-endian; перепутать — типичная ошибка."
```

## Куда дальше

Мы разобрали прошивку и нашли секреты. Но что делать, если внутри образа лежит **не обычный
бинарник**, а зашифрованный blob или загрузчик, который что-то расшифровывает в памяти?
Следующий шаг — динамический анализ: эмуляция и отладка прошивочного кода. Об этом — в уроке
про эмуляцию firmware. А пока главное запомни: **прошивка — это разделы; сначала вырежи ФС,
потом ищи внутри.**

## Где пригодится

- **CTF Reversing/IoT:** задачи с образами прошивок, флаг в ФС или бинарнике.
- **Пентест IoT:** анализ роутеров/камер/NAS, поиск бэкдоров и command injection.
- **Malware analysis:** разбор IoT-ботнетов, встроенных в прошивки.
- **Работа (embedded security):** аудит firmware, supply chain, поиск уязвимых библиотек.
- **Собес:** вопросы про squashfs, binwalk, u-boot — типичны для embedded-позиций.
