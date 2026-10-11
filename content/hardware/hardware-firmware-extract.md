---
id: hardware-firmware-extract
title: "Извлечение прошивки: binwalk, unblob и файловые системы"
category: hardware
parent: hardware-spi
difficulty: medium
order: 2
tags: [firmware, binwalk, unblob, squashfs, jffs2, ubifs, extraction]
prerequisites: [hardware-spi, hardware-uart]
useful_for:
  - "CTF-задачи категории Hardware/Forensics"
  - "Пентест IoT: анализ содержимого прошивки"
  - "Поиск паролей, ключей и бэкдоров"
estimated_minutes: 40
summary: "Как разобрать дамп прошивки на составные части: найти ядро, rootfs, распаковать squashfs/jffs2/ubifs и найти секреты внутри."
---

Дамп флеша — это «сырой» бинарник, в котором последовательно лежат загрузчик, ядро и файловые системы. Задача этого урока — превратить этот блоб в читаемое дерево файлов: тогда пароли, ключи и бэкдоры находятся обычным grep'ом. Это самая продуктивная фаза hardware-анализа.

## Теория

Прошивка обычно собрана из нескольких образов, идущих друг за другом со смещениями, кратными размеру сектора флеша (4 КБ, 64 КБ):

| Область | Что внутри | Типичное смещение |
|---------|-----------|-------------------|
| Bootloader | U-Boot, CFE, U-Boot SPL | 0x0 |
| Env / config | переменные загрузчика, настройки | 0x10000 |
| Kernel | `uImage`, `zImage`, FIT | 0x40000 |
| RootFS | squashfs, jffs2, ubifs, cramfs | 0x200000 |
| Data / overlay | JFFS2, UBIFS, ext4 | конец |

Основные форматы корневой ФС:
- **Squashfs** — read-only сжатая ФС, самый частый вариант. Магия `hsqs` (little-endian) или `sqsh` (big-endian).
- **JFFS2** — журнальная ФС для NOR, часто для overlay. Магия `0x1985`.
- **UBIFS/UBI** — для NAND, требует разбора UBI-контейнера.
- **Cramfs** — старая сжатая ФС, магия `0x28cd3d45`.
- **CPIO/initramfs** — начальный rootfs внутри ядра.
- **ext4** — на новых устройствах.

**Порядок байт** важен: MIPS-роутеры бывают big-endian, ARM — little-endian. `binwalk` иногда путает squashfs из-за эндианности — помогает `-e` с явным указанием или `sasquatch`.

## Инструменты и команды

- **binwalk** — классический сканер сигнатур и экстрактор.
- **unblob** — современная замена, точнее режет и поддерживает больше форматов.
- **sasquatch** — патченый `unsquashfs` для нестандартных squashfs.
- **jefferson** — распаковка JFFS2 (Python).
- **ubi_reader** — разбор UBI/UBIFS.
- **firmware-mod-kit (FMK)** — набор скриптов для распаковки/сборки прошивок.
- **binwalk -Me / -e**, `unsquashfs`, `mount -t squashfs`.

```bash
# Установка
pip install binwalk unblob jefferson
sudo apt install squashfs-tools mtd-utils

# Скан без распаковки
binwalk firmware.bin

# Извлечение с рекурсией (иногда нужно -M)
binwalk -eM firmware.bin
# unblob — предпочтительнее
unblob -e /tmp/out firmware.bin

# Если binwalk не берёт squashfs — используем sasquatch
sasquatch -d rootfs -p 1 extracted.squashfs

# JFFS2
jefferson -d rootfs_jffs2 filesystem.jffs2

# UBI
ubireader_extract_images firmware.bin
ubireader_extract_files ubi_image.ubifs
```

## Разобранный пример: от дампа до `/etc/shadow`

**Дано:** `dump1.bin` (16 МБ) от роутера.

**Шаг 1 — скан:**
```bash
binwalk dump1.bin
```
```text
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             uImage header, ... (U-Boot)
131072        0x20000         Squashfs filesystem, little endian, size: 7340032 bytes
8519680       0x820000        JFFS2 filesystem, little endian
```

**Шаг 2 — извлечение rootfs:**
```bash
dd if=dump1.bin of=rootfs.sqfs bs=1 skip=$((0x20000)) count=$((7340032))
unsquashfs -d rootfs rootfs.sqfs
```

**Шаг 3 — поиск секретов:**
```bash
# Пароли и хэши
grep -r "root:" rootfs/etc/shadow rootfs/etc/passwd 2>/dev/null
# Конфиги с паролями
grep -rEi "password|passwd|secret|api[_-]?key|token" rootfs/etc/ 2>/dev/null | head -50
# Приватные ключи и сертификаты
find rootfs -name "*.pem" -o -name "*.key" -o -name "id_rsa"
# Интересные бинарники и скрипты
find rootfs -type f -perm -u+x | head -50
```

**Шаг 4 — анализ инициализации:**
```bash
cat rootfs/etc/init.d/* 2>/dev/null | head -100
# Ищем запуск telnetd/sshd с дефолтным паролем, watchdog, кастомные сервисы
grep -rn "telnetd\|sshd\|dropbear" rootfs/etc/ 2>/dev/null
```

**Шаг 5 — снятие хэшей.** Если в `shadow` лежит `$1$...` (MD5-crypt), он вскрывается:
```bash
# Сохраняем хэш в hash.txt и ломаем
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 500 hash.txt rockyou.txt   # $1$ = md5crypt
```

**Шаг 6 — что ещё искать.** Сертификаты/ключи для облачных сервисов, скрипты с хардкод-паролями, отладочные учётки, бэкдоры (странные бинарники, слушающие порт).

## Частые ошибки

- **binwalk не распаковывает squashfs.** Причина — big-endian или нестандартный формат. Используйте `sasquatch` или `unblob`.
- **Неверное смещение/размер.** Всегда берите значения из вывода `binwalk`/`unblob`, а не на глаз.
- **Забыли про overlay.** Пользовательские данные и изменённые конфиги лежат в JFFS2/UBIFS, а не в squashfs. Извлекайте оба.
- **Игнорирование ядра/initramfs.** Иногда секреты и пароль консоли прописаны в `bootargs` внутри ядра или в initramfs (CPIO).
- **grep по всему подряд.** Ограничивайте области (`/etc`, `/usr/bin`, `/www`) — иначе тонете в выводе.
- **Эксплуатация «в живую» вместо офлайн.** Сначала полностью разберите образ, потом трогайте устройство.

## Теория: от дампа к файлам

Прошивка — контейнер: заголовки загрузчика, ядро, rootfs (squashfs/jffs2/ubifs/cramfs), иногда шифрование. Извлечение — цепочка: найти сигнатуры → распаковать → смонтировать ФС. Binwalk ищет сигнатуры и рекурсивно распаковывает; unblob делает то же, но лучше покрывает современные форматы.

## Инструменты и команды

```bash
binwalk firmware.bin
binwalk -Me firmware.bin
binwalk -E firmware.bin        # энтропия
unblob firmware.bin -o out/
# монтирование
unsquashfs squashfs-root.sqsh
jefferson rootfs.jffs2 -d out/   # jffs2
ubireader_extract_files ubifs.img
# cramfs
cramfsck -x out/ rootfs.cramfs
```

## Разобранный пример 2: от дампа до /etc/shadow

1. `binwalk -Me dump.bin` — извлекаем всё.
2. Определяем тип rootfs (squashfs).
3. `unsquashfs` монтируем.
4. Ищем `/etc/shadow`, `/etc/passwd`, ключи, скрипты.
5. Расшифровываем хеши (john/hashcat) или находим hardcoded-пароли.

## Частые проблемы

- Шифрованный rootfs (нет ключа) — нужен ключ из загрузчика.
- Вложенные форматы (binwalk не всегда рекурсивен) — используйте unblob.
- Повреждённый дамп — проверьте процесс снятия.

## Файловые системы: особенности

| ФС | Признак | Инструмент | Особенности |
|----|---------|-----------|-------------|
| squashfs | `hsqs` | unsquashfs | read-only, сжатие |
| jffs2 | `0x1985` | jefferson | NAND/NOR, wear-level |
| ubifs | UBI | ubireader | NAND, LEB |
| cramfs | `0x28cd3d45` | cramfsck | read-only, старый |
| ext2/4 | суперблок | mount | если не сжата |

Определите тип по сигнатуре (binwalk) и монтируйте соответствующей утилитой. Для UBI сначала извлекают UBI-образ, затем UBIFS.

## Практика 2

Возьмите прошивку с UBIFS, извлеките UBI (`ubireader_extract_images`), затем файлы (`ubireader_extract_files`). Найдите конфигурацию, пароли и ключи. Сравните с squashfs-прошивкой другого устройства — увидите различия форматов и подходов к извлечению.

## Быстрая проверка

```bash
binwalk firmware.bin
binwalk -Me firmware.bin
unblob firmware.bin -o out/
unsquashfs squashfs-root.sqsh
```

Начните с `binwalk -Me`, при неполной распаковке — `unblob`. Определите ФС по сигнатуре и монтируйте. Ищите `/etc/shadow`, ключи и hardcoded-пароли.

## Итог

Извлечение прошивки — цепочка «сигнатура → распаковка → монтирование ФС». binwalk и unblob находят и распаковывают; unsquashfs/jefferson/ubireader монтируют конкретные ФС. Цель — `/etc/shadow`, ключи и hardcoded-пароли. Шифрованный rootfs требует ключа из загрузчика.

## Сводка

| Сигнатура | ФС | Инструмент |
|-----------|----|-----------|
| hsqs | squashfs | unsquashfs |
| 0x1985 | jffs2 | jefferson |
| UBI# | ubifs | ubireader |
| 0x28cd3d45 | cramfs | cramfsck |

## Квиз

```quiz
- question: "Какой формат корневой ФС в прошивках встречается чаще всего?"
  options:
    - "Squashfs"
    - "NTFS"
    - "HFS+"
    - "exFAT"
  answer: 0
- question: "Что делает команда `binwalk -eM firmware.bin`?"
  options:
    - "Извлекает вложенные файловые системы с рекурсией"
    - "Записывает прошивку во флеш"
    - "Шифрует прошивку"
    - "Считает контрольную сумму"
  answer: 0
- question: "binwalk не может распаковать squashfs. Что попробовать?"
  options:
    - "sasquatch или unblob (другая эндианность/формат)"
    - "Записать дамп обратно"
    - "Увеличить бод-рейт"
    - "Подключить JTAG"
  answer: 0
- question: "Где в распакованном rootfs искать хэши паролей Linux?"
  options:
    - "/etc/shadow (и /etc/passwd)"
    - "/var/log/messages"
    - "/proc/cpuinfo"
    - "/boot/uImage"
  answer: 0
- question: "Почему важно извлекать не только squashfs, но и JFFS2/UBIFS?"
  options:
    - "Там лежат изменённые конфиги, пользовательские данные и overlay"
    - "Там хранится ядро"
    - "JFFS2 содержит загрузчик"
    - "Это одно и то же"
  answer: 0
```

## Где пригодится

- **CTF:** Hardware/Forensics — извлечение флага из прошивки.
- **Пентест IoT:** поиск паролей, ключей, бэкдоров в образе.
- **Bug bounty:** анализ прошивок устройств в рамках hardware-программ.
- **Работа:** reverse engineering прошивок, анализ цепочек поставок, поиск закладок.
- **Дальше по дереву:** `hardware-firmware-emulation` (запуск бинарников из rootfs), `hardware-crypto` (поиск ключей шифрования).
