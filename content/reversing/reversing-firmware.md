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
**Реверс прошивок (firmware)** — это анализ встроенного ПО роутеров, IP-камер, IoT-устройств, NAS и другой embedded-техники. Прошивка — это образ флеш-памяти, содержащий загрузчик, ядро, корневую ФС и приложения. Задачи: найти веб-интерфейс и его уязвимости, извлечь секреты (ключи, пароли), понять логику протоколов, обнаружить бэкдоры. Урок даёт полный практический workflow: от получения образа до распаковки, определения архитектуры, эмуляции и анализа с разобранными примерами.

## Что такое прошивка и зачем её реверсить

Прошивка обычно содержит:

- **Bootloader** (U-Boot, CFE) и **ядро** (Linux, RTOS).
- **Корневую ФС** — BusyBox, веб-сервер (lighttpd/boa/goahead), CGI-скрипты.
- **Приложения** — проприетарные бинарники, реализующие функции устройства.
- **Конфиги и ключи** — сертификаты, пароли, API-токены.

Цели реверса: аудит безопасности (CVE в веб-интерфейсе), извлечение секретов, поиск бэкдоров, подготовка эксплойта, понимание протокола.

## Получение прошивки

- **OTA-обновление.** Скачать с сайта вендора (часто `.bin`/`.img`/`.trx`); проверить подпись/шифрование.
- **Дамп флеша.** Выпаять SPI-флеш и снять через `flashrom`, либо через UART/JTAG.
- **UART-консоль.** Часто даёт shell/uboot с доступом к памяти (`md`/`dump`).
- **Из сети.** Некоторые устройства отдают образ по TFTP/HTTP.
- **Vendor CDN.** Поиск по `sha256`/модели на сайтах обновлений.

```bash
# определение типа образа
file firmware.bin
binwalk firmware.bin
# поиск строк о версии/модели
strings -a firmware.bin | grep -iE 'version|model|build|openwrt|linux'
```

## binwalk: распаковка

`binwalk` — основной инструмент. Сигнатуры: squashfs, cramfs, jffs2, ubifs, gzip, lzma, uImage.

```bash
# сканирование
binwalk firmware.bin
# рекурсивное извлечение
binwalk -e firmware.bin
# принудительно по сигнатурам + Matryoshka (рекурсия)
binwalk -Me firmware.bin
# извлечь конкретный тип
binwalk -D 'squashfs:raw:0' firmware.bin
```

Ключевые флаги:

| Флаг | Смысл |
|---|---|
| `-e` | извлечь известные типы |
| `-M` | Matryoshka (рекурсивно) |
| `-D <type:ext:cmd>` | извлечь конкретный тип |
| `-A` | только «опознать», без ложных срабатываний |
| `-E` | энтропийный анализ (найти сжатие/шифр) |
| `--run-as=root` | извлечь с сохранением прав |

## Файловые системы embedded

| ФС | Признак | Инструмент распаковки |
|---|---|---|
| SquashFS | `hsqs`/`sqsh` | `unsquashfs` |
| CramFS | `0x28cd3d45` | `cramfsck -x` |
| JFFS2 | `0x1985` (big/little endian) | `jefferson` |
| UBIFS | UBI-заголовок | `ubireader_extract_images` |
| ext2/3/4 | `0x53ef` | `mount -o loop` |
| initramfs/cpio | `070701` | `cpio -idmv` |

```bash
unsquashfs -d rootfs squashfs-root.squashfs
ubireader_extract_images firmware.ubi
jefferson -d out jffs2.img
# cpio (initramfs), часто gzip сжат
zcat initramfs.cpio.gz | cpio -idmv
```

## Определение архитектуры

Embedded — это часто MIPS, ARM, ARM64, PowerPC, а не x86.

```bash
file rootfs/usr/sbin/httpd
# ELF 32-bit LSB executable, MIPS, MIPS32, dynamically linked
readelf -h rootfs/usr/sbin/httpd | grep -E 'Machine|Class|Endian'
```

Типовые архитектуры: `MIPS` (big/little endian), `ARM` (EABI, hard-float), `AArch64`, `PowerPC`. От этого зависит эмуляция и декомпиляция.

## Эмуляция: QEMU и firmadyne

Запустить прошивку целиком или отдельный бинарник.

```bash
# QEMU user-mode: запустить один бинарник
qemu-mips -L rootfs rootfs/usr/sbin/httpd
# QEMU system-mode: запустить ядро+ФС
qemu-system-mips -M malta -kernel vmlinux -hda rootfs.ext2 -nographic
# firmadyne: автоматизация (распаковка+эмуляция)
sudo ./sources/extractor/extractor.py -b brand -sql db -np -nk firmware.bin images
./scripts/run.sh
```

`firmadyne`/`FirmAE` автоматизируют: распаковка → определение NVRAM → запуск под QEMU → доступ к веб-интерфейсу. Для анализа веб-уязвимостей это экономит часы.

## Анализ бинарников и веб-интерфейса

```bash
# найти веб-сервер и CGI
find rootfs -name '*httpd*' -o -name '*.cgi' -o -name 'lighttpd*'
# посмотреть конфиг и точки входа
cat rootfs/etc/lighttpd.conf 2>/dev/null
cat rootfs/etc/init.d/rcS 2>/dev/null
# секреты и ключи
grep -rniE 'password|passwd|secret|token|api_key' rootfs/etc rootfs/www 2>/dev/null
find rootfs -name '*.pem' -o -name '*.key' -o -name 'shadow' -o -name 'passwd'
```

Особое внимание: **CGI-скрипты** (shell/C), которые вызывают `system()`/`popen()` с пользовательским вводом — классический command injection в IoT.

## Поиск секретов и бэкдоров

- **Хардкод паролей**: `admin:admin`, строки в бинарниках.
- **Приватные ключи** SSH/TLS.
- **Бэкдор-аккаунты**: нестандартные записи в `passwd`/`shadow`.
- **Скрытые вызовы**: `system`, `popen`, `execve` с фиксированными строками.
- **Отладочные интерфейсы**: telnet/ssh с фиксированным паролем.

```bash
strings -a rootfs/usr/sbin/* | grep -iE 'telnet|backdoor|debug|root:'
grep -rniE 'system\(|popen\(' rootfs/www/cgi-bin/
```

## Разобранный пример: от образа до command injection

**Шаг 1. Распаковать.**

```bash
binwalk -Me firmware.bin
ls _firmware.bin.extracted/
```

**Шаг 2. Определить arch и найти веб-сервер.**

```bash
file _firmware.bin.extracted/squashfs-root/usr/sbin/httpd
# ELF 32-bit LSB, MIPS, MIPS32
```

**Шаг 3. Найти CGI и уязвимость.**

```bash
grep -rn 'system(' _firmware.bin.extracted/squashfs-root/www/
# www/cgi-bin/diag.cgi: system("ping " + user_input);
```

**Шаг 4. Эмуляция и проверка.**

```bash
qemu-mips -L squashfs-root squashfs-root/usr/sbin/httpd &
curl 'http://127.0.0.1/cgi-bin/diag.cgi?host=127.0.0.1;id'
```

**Шаг 5. Вывод.** Параметр `host` не фильтруется → RCE на устройстве.

## Инструменты (таблица)

| Инструмент | Назначение | Пример |
|---|---|---|
| `binwalk` | распаковка/сканирование | `binwalk -Me fw.bin` |
| `unsquashfs` | SquashFS | `unsquashfs -d rootfs fs.sqsh` |
| `jefferson` | JFFS2 | `jefferson -d out img` |
| `ubireader_extract_images` | UBI/UBIFS | `ubireader_extract_images ubi` |
| `firmadyne`/`FirmAE` | авто-эмуляция | `./run.sh` |
| `qemu-*` | user/system эмуляция | `qemu-mips -L rootfs bin` |
| `flashrom` | дамп флеша | `flashrom -r dump.bin` |

## Частые ошибки и подводные камни

- **Шифрование/подпись образа.** Часть прошивок шифрована — нужен ключ или дамп с устройства.
- **Не та архитектура QEMU.** MIPS big-endian vs little-endian — частая путаница; смотрите `readelf`.
- **Пропуск initramfs.** Корневая ФС может быть внутри `initramfs.cpio.gz`, а не в squashfs.
- **Отсутствие NVRAM.** firmadyne-эмуляция падает без корректного NVRAM — заполняйте вручную.
- **Игнорирование CGI.** Именно shell-CGI чаще всего содержат RCE.
- **Только финальная ФС.** В `-Me` Matryoshka вложенные образы распаковываются рекурсивно — не пропустите их.

## Что дальше / решение

Маршрут: **получить образ → binwalk -Me → определить arch → распаковать ФС → найти веб/CGI и секреты → эмуляция (QEMU/firmadyne) → анализ уязвимостей**. Для CTF — ищите флаг в секретах/бэкдорах; для аудита — CGI/веб-интерфейс. Дальше — `reversing-firmware-emulation` (глубокая эмуляция), `reversing-embedded-rtos` (RTOS) и `reversing-hardware-debug` (UART/JTAG/SWD).

## UART/JTAG: доступ к консоли устройства

Физический доступ часто даёт shell, что радикально упрощает анализ.

```bash
# найти UART-пины (TX/RX/GND), подключить USB-UART
picocom -b 115200 /dev/ttyUSB0
# или screen
screen /dev/ttyUSB0 115200
```

Если видите U-Boot — можно дампить флеш прямо из памяти:

```
# в U-Boot
md.b 0x80000000 0x100000      # дамп 1MB из RAM
# или через tftp загрузку образа
```

JTAG/SWD даёт доступ к отладке CPU: с `openocd` можно читать/писать память, ставить точки останова в прошивке, снять дамп флеша при включённой защите. Это уровень `reversing-hardware-debug`.

## Расшифровка зашифрованных прошивок

Часть вендоров шифрует OTA-образы. Признаки: высокая энтропия (`binwalk -E`), отсутствие сигнатур.

- **Ключ в загрузчике.** Иногда ключ расшифровки лежит в U-Boot/CFE открытым.
- **Общий ключ у семейства.** Ключ повторяется между моделями — ищите по другим прошивкам.
- **Дамп с устройства.** Дамп флеша уже расшифрован (расшифровка на лету) — самый надёжный путь.
- **Анализ процедуры загрузки.** Точка расшифровки в bootloader подскажет алгоритм/ключ.

## Практика: анализ NVRAM и конфигов

NVRAM хранит настройки устройства (пароли Wi-Fi, учётки, ключи). В эмуляции её нужно воссоздать.

```bash
# найти NVRAM-разделы
binwalk firmware.bin | grep -i nvram
# часто это отдельный раздел с парами key=value
strings -a firmware.bin | grep -E '^[a-z_]+=' | head
# конфиги в ФС
find rootfs -name '*.conf' -o -name '*.cfg' | xargs grep -liE 'passwd|key'
```

Для firmadyne создаётся файл NVRAM (`libnvram`-совместимый), иначе веб-сервер падает.

## Ключевые выводы по реверсу прошивок

Итог: **binwalk -Me** — точка входа; далее определяйте архитектуру (`readelf`) и распаковывайте ФС (`unsquashfs`/`ubireader`). Ищите секреты и CGI с `system()`. Эмуляция (QEMU/firmadyne) позволяет проверить уязвимость живьём. UART/JTAG — когда образ зашифрован или нужен рантайм. Дальше — `reversing-firmware-emulation` и `reversing-hardware-debug`.

## Разделение образа на разделы и таблица MTD

Большинство прошивок — это конкатенация разделов с таблицей MTD (Memory Technology Device). Понимание раскладки помогает извлечь каждый компонент.

```bash
# сигнатура таблицы разделов встречается в строках ядра/bootloader
strings -a firmware.bin | grep -iE 'mtd|partition|kernel|rootfs|nvram'
# пример раскладки:
# 0x000000 bootloader
# 0x040000 kernel
# 0x200000 rootfs (squashfs)
# 0x700000 nvram
```

Извлечь конкретный раздел можно `dd` по смещению:

```bash
dd if=firmware.bin of=rootfs.sqsh bs=1 skip=$((0x200000)) count=$((0x500000))
unsquashfs -d rootfs rootfs.sqsh
```

Это особенно полезно, когда `binwalk -Me` даёт «мусор» из-за нестандартных заголовков — вы режете по известным смещениям вручную.

## Динамическая отладка embedded через GDB stub

QEMU умеет отдавать GDB stub, что позволяет отлаживать прошивочный бинарник почти как обычный ELF.

```bash
# запустить бинарник с GDB stub на порту 1234
qemu-mips -g 1234 -L rootfs rootfs/usr/sbin/httpd
# подключиться мультиархитектурным gdb
gdb-multiarch rootfs/usr/sbin/httpd -ex 'target remote :1234'
(gdb) b *0x400abc
(gdb) c
```

Для system-mode — `-s -S` у `qemu-system-*`. Это даёт точки останова, стек, память — то, что нужно для разбора уязвимого CGI в рантайме, без физического устройства.

## Квиз

```quiz
- question: "Какая сигнатура соответствует squashfs?"
  options:
    - "`\x1f\x8b`"
    - "`hsqs`"
    - "`UBI#`"
    - "`cramfs`"
  answer: 1
- question: "Что делает `binwalk -Me firmware.bin`?"
  options:
    - "Рекурсивно извлекает все распознанные слои"
    - "Только показывает карту без извлечения"
    - "Прошивает устройство"
    - "Эмулирует образ"
  answer: 0
- question: "Почему для MIPS BE нужен именно `qemu-mips`, а не `qemu-mipsel`?"
  options:
    - "Endianness различается: `mips` — big-endian, `mipsel` — little-endian"
    - "`qemu-mipsel` устарел"
    - "`qemu-mips` быстрее"
    - "Разницы нет"
  answer: 0
- question: "Где чаще всего лежат hardcoded-пароли в прошивке?"
  options:
    - "В ядре Linux"
    - "В `/etc/shadow`, конфигах и бинарниках веб-приложения"
    - "В загрузчике u-boot всегда"
    - "В squashfs-заголовке"
  answer: 1
- question: "Что нужно указать `qemu-user` для запуска бинарника из rootfs?"
  options:
    - "`-cpu`"
    - "`-L rootfs/` (sysroot)"
    - "`-kernel`"
    - "`-net`"
  answer: 1
```

## Где пригодится

- **CTF Reversing/IoT:** задачи с образами прошивок, извлечение флага из ФС или бинарника.
- **Пентест IoT:** анализ роутеров/камер/NAS, поиск бэкдоров и command injection.
- **Malware analysis:** разбор IoT-ботнетов, встроенных в прошивки.
- **Работа (embedded security):** аудит firmware, supply chain, поиск уязвимых библиотек.
- **Собес:** вопросы про squashfs, binwalk, u-boot — типичны для embedded/security-позиций.
