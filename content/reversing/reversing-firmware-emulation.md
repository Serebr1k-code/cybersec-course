---
id: reversing-firmware-emulation
title: "Эмуляция прошивок: FirmAE, firmadyne и QEMU"
category: reversing
parent: reversing-firmware-basics
difficulty: hard
order: 2
tags: [reversing, firmware, emulation, qemu, firmadyne, firmae, iot]
prerequisites: [reversing-firmware, reversing-embedded-rtos]
useful_for:
  - "CTF Reversing / IoT"
  - "Firmware vulnerability research"
  - "IoT pentest"
estimated_minutes: 60
summary: "Автоматическая эмуляция прошивок: извлечение ФС, QEMU user/system, FirmAE/firmadyne, отладка сервисов."
---
Эмуляция прошивок позволяет запустить встроенные сервисы (web-панели, демоны, бинарники) в контролируемой среде **без реального устройства** — чтобы искать уязвимости, реверсить логику и отлаживать. Прошивка IoT-устройства — это образ флеш-памяти с загрузчиком, ядром Linux, корневой ФС и набором бинарников под MIPS/ARM. Запуск в QEMU даёт интерактивную систему, где можно исследовать сервисы, но требует ручной доработки: подмены NVRAM, сети, библиотек. Инструменты вроде firmadyne и FirmAE автоматизируют этот процесс. В этом уроке — полный workflow эмуляции прошивок.

## Зачем эмулировать прошивки

Реальное устройство может быть недоступно, дорого, рискованно (можно «кирпичить») или одноразово. Эмуляция даёт: повторяемость (снапшот), инструментацию (gdbserver, strace), масштаб (десятки образов), безопасность. Типовые цели: найти RCE в web-панели, разобрать протокол, извлечь ключи, проверить обновление прошивки. Эмуляция — мост между статическим разбором бинарников и тестированием на живом устройстве.

## Извлечение файловой системы

Первый шаг — распаковать образ. `binwalk` определяет структуру и извлекает вложенные ФС:

```bash
binwalk firmware.bin
binwalk -eM firmware.bin
binwalk --dd='.*' firmware.bin
```

Для SquashFS — `unsquashfs`:

```bash
unsquashfs -d rootfs squashfs-root.sqsh
unsquashfs -l image.sqsh | head
```

Другие форматы: JFFS2 (`jefferson -d out image.jffs2`), UBIFS (`ubireader_extract_images`, `ubireader_extract_files`), CramFS (`cramfsck -x out image.cramfs`), ext (`debugfs`). Часто образ зашифрован или упакован вендорским загрузчиком — тогда распаковку делают вручную, анализируя заголовок. После извлечения проверяют архитектуру бинарников:

```bash
file squashfs-root/bin/busybox
readelf -h squashfs-root/usr/sbin/httpd | grep Machine
```

## QEMU user-mode vs system-mode

**User-mode** (`qemu-mips`, `qemu-arm`) запускает один бинарник, транслируя сисколлы в хостовые. Быстро, но нет ядра, сети и полной ФС. Пример:

```bash
sudo cp /usr/bin/qemu-mips-static squashfs-root/
sudo chroot squashfs-root ./qemu-mips-static ./bin/busybox
sudo chroot squashfs-root ./qemu-mips-static -g 1234 ./usr/sbin/httpd
```

Флаг `-g 1234` открывает gdbserver на порту 1234 — подключаемся `gdb-multiarch -ex 'target remote :1234'`. **System-mode** (`qemu-system-mips`) эмулирует целую машину с ядром, сетью и устройствами. Требует подходящего ядра (`vmlinux`) и правильной машины (`-M malta` для MIPS):

```bash
qemu-system-mips -M malta -kernel vmlinux -hda rootfs.ext2 \
  -append "root=/dev/sda console=ttyS0" -nographic \
  -netdev user,id=n0 -device e1000,netdev=n0
```

## firmadyne: автоматизация

firmadyne автоматизирует извлечение и запуск: определяет архитектуру, собирает ядро, создаёт образ диска, настраивает сеть и NVRAM. Основные скрипты:

```bash
sudo ./sources/extractor/extractor.py -b brand -sql 127.0.0.1 -np -nk image.bin images
./scripts/getArch.sh ./images/1234.tar.gz
./scripts/makeImage.sh 1234
./scripts/inferNetwork.sh 1234
./scratch/1/run.sh
```

firmadyne хранит NVRAM в эмуляции (`libnvram.so`) и патчит бинарники для подмены железа. Минус: старые зависимости, много образов не запускаются «из коробки».

## FirmAE: улучшения и практика

FirmAE — форк с эвристиками для повышения успеха: автоматический ремонт (`repair`), несколько попыток запуска, более умная сеть, поддержка большего числа архитектур. Запуск:

```bash
sudo ./run.sh -r <brand> -c <firmware.bin> <output_dir>
./run.sh -a <arch> -f <kernel> <image>
```

FirmAE сам подбирает ядро, чинит `init`, настраивает интерфейсы и в итоге запускает сервисы, публикуя их на хосте. В отчёте — какие демоны поднялись и на каких портах. Это самый практичный инструмент для массовой эмуляции.

## Ручная настройка: сеть, NVRAM, init

Автоматика часто не справляется, и тогда эмуляцию допиливают руками. **Сеть**: в user-mode QEMU пробрасывают порты `-netdev user,hostfwd=tcp::8080-:80`; в system-mode настраивают `br0` через `-netdev tap`. **NVRAM**: многие сервисы читают конфиг через `nvram_get`; библиотеку `libnvram` подменяют своей, возвращающей нужные значения, или подсовывают файл конфига. **init**: правят `/etc/init.d/rcS`, чтобы запустить только нужный сервис, а не всю систему. **Библиотеки**: если бинарник не стартует из-за `GLIBC`/`uClibc`, подкладывают совместимую или патчат. **Пользователи/группы**: создают недостающие в `/etc/passwd`.

## Отладка сервисов

После запуска сервис отлаживают:

```bash
# запустить сервис с gdbserver
sudo chroot rootfs ./qemu-mips-static -g 1234 ./usr/sbin/httpd -f /etc/httpd.conf
# подключиться
gdb-multiarch ./rootfs/usr/sbin/httpd \
  -ex 'set architecture mips' -ex 'target remote :1234' \
  -ex 'b *0x400000' -ex 'c'
```

Дополнительно: `strace` (если есть), `ltrace`, перехват через QEMU-плагины, дампы памяти. Для web-сервиса удобно пробросить порт на хост и тестировать `curl`/`ffuf` извне. Логи сервиса — в консоль QEMU (`-nographic`) или в файл.

## Полный разбор: запуск веб-панели роутера

**Шаг 1 — распаковка:** `binwalk -eM fw.bin` → `squashfs-root`. **Шаг 2 — архитектура:** `file bin/httpd` → MIPS LE. **Шаг 3 — запуск user-mode:** копируем `qemu-mips-static`, `chroot`, запускаем `httpd` с `-g` и пробросом порта. **Шаг 4 — NVRAM:** если сервис падает на `nvram_get`, подкладываем `libnvram.so` или конфиг. **Шаг 5 — доступ:** `curl http://127.0.0.1:8080/` → видим панель. **Шаг 6 — тестирование:** `ffuf -u http://127.0.0.1:8080/FUZZ -w list`, ищем `cgi`-скрипты и инъекции. **Шаг 7 — отладка найденного бага:** ставим bp в gdb на обработчик.

## Проблемы и обходы

- **Ядро не подходит:** подбирают `vmlinux` из SDK вендора или собирают под ту же версию/архитектуру.
- **Паника при загрузке:** правят `init`, `fstab`, отключают модули; `-append "init=/bin/sh"`.
- **Нет сети:** настраивают tap/bridge или hostfwd.
- **Сервис читает железо:** подменяют `/dev`, `gpio`, NVRAM заглушками.
- **uClibc/GLIBC несовместимость:** подкладывают библиотеки из ФС, патчат динамический линкер.
- **Анти-эмуляция:** проверки CPU/железа; патчат или подменяют значения.

## Шпаргалка

| Задача | Команда |
|---|---|
| Определить формат | `binwalk firmware.bin` |
| Извлечь | `binwalk -eM`, `unsquashfs`, `jefferson` |
| Архитектура | `file bin/*`, `readelf -h` |
| User-mode запуск | `qemu-mips-static -g 1234 ./bin` |
| System-mode | `qemu-system-mips -M malta -kernel ...` |
| Автоэмуляция | `firmadyne`, `FirmAE run.sh` |
| Отладка | `gdb-multiarch -ex 'target remote :1234'` |
| Проброс порта | `-netdev user,hostfwd=tcp::8080-:80` |

## Что дальше / решение

Маршрут: распакуйте образ (`binwalk -eM`), определите архитектуру, попробуйте автоматику (FirmAE), при неудаче — запустите вручную в QEMU user/system, подлатайте NVRAM/сеть/init, поднимите сервис и пробросьте порт, затем тестируйте и отлаживайте. Дальше изучайте сборку ядер под вендорские SDK, эмуляцию железа (периферия, GPIO) и автоматический фаззинг сервисов (AFL в QEMU-режиме).

## Сборка ядра из вендорского SDK

Часто ни одно готовое ядро не подходит, и его приходится собирать из SDK производителя. SDK содержит toolchain (например, `mips-linux-gnu-gcc`), исходники ядра (обычно Linux 2.x/3.x/4.x с патчами вендора), конфигурацию (`config`/`defconfig`) и иногда rootfs. Порядок: распаковать SDK, экспортировать `PATH` к toolchain, выбрать `ARCH` и `CROSS_COMPILE`:

```bash
export ARCH=mips
export CROSS_COMPILE=mips-linux-gnu-
export PATH=$PWD/toolchain/bin:$PATH
make defconfig          # или make menuconfig
make -j$(nproc) vmlinux
```

Готовый `vmlinux` передают QEMU через `-kernel`. Если ядро требует initramfs, его собирают отдельно (`gen_init_cpio`). Для ARM используют `ARCH=arm CROSS_COMPILE=arm-linux-gnueabi-`. Важно совпадение endianness (MIPS BE vs LE) и версии ядра с ожиданиями прошивки — иначе модули не загрузятся.

## Эмуляция конкретного сервиса и работа с NVRAM

NVRAM — большая боль эмуляции: сервисы читают конфигурацию через `nvram_get`/`nvram_set` из `/dev/nvram` или shared library. Решения:

1. **Подмена libnvram.so**: написать свою библиотеку, реализующую `nvram_get`/`nvram_set` поверх файла-конфига, и подложить её через `LD_PRELOAD` или заменив файл.
2. **Файл конфига**: некоторые прошивки хранят NVRAM в текстовом файле — достаточно создать его с нужными ключами.
3. **Эмуляция железа**: QEMU-плагин или заглушка для `/dev/mtd`.

Типичный workflow: запустить сервис, увидеть в strace/логах, какой ключ не найден, добавить его в конфиг, повторить. Так итеративно доводят сервис до старта. Для web-панели затем пробрасывают порт (`hostfwd`) и тестируют HTTP из хоста.

## Полный разбор: system-mode эмуляция роутера

**Шаг 1:** `binwalk -eM fw.bin` → `squashfs-root` + `vmlinux`. **Шаг 2:** `file vmlinux` → MIPS BE; проверяем `readelf -h`. **Шаг 3:** собираем ext2-образ из rootfs: `dd if=/dev/zero of=rootfs.ext2 bs=1M count=64 && mkfs.ext2 rootfs.ext2 && mount -o loop ... && cp -a squashfs-root/* /mnt && umount`. **Шаг 4:** запускаем: `qemu-system-mips -M malta -kernel vmlinux -hda rootfs.ext2 -append "root=/dev/sda console=ttyS0" -nographic -netdev user,id=n0,hostfwd=tcp::8080-:80 -device e1000,netdev=n0`. **Шаг 5:** в консоли логинимся, поднимаем `ifconfig br0 192.168.0.1`, запускаем сервисы. **Шаг 6:** с хоста `curl http://127.0.0.1:8080/` — панель доступна. **Шаг 7:** фаззим CGI и отлаживаем найденные баги в gdb-multiarch.

## Инструменты и автоматизация распаковки

Помимо `binwalk`, полезны: `unblob` (современный распаковщик с десятками форматов и рекурсией), `firmware-mod-kit` (`extract-firmware.sh`), `sasquatch` (SquashFS с патчами вендоров), `ubireader`, `jefferson`. `unblob` особенно хорош, когда `binwalk` не распознаёт кастомные форматы. Для поиска «интересного» после распаковки:

```bash
grep -rIl "password\|admin" squashfs-root/etc 2>/dev/null
find squashfs-root -name "*.cgi" -o -name "*.conf" | head
strings -a squashfs-root/usr/sbin/httpd | grep -iE "system|popen|sprintf"
```

Так быстро находят потенциальные уязвимости до эмуляции.

## Работа с несколькими образами и бенчмарки

Для массового анализа прошивок (например, при поиске 1-day в устройствах) эмуляцию автоматизируют: скрипт обходит каталог образов, для каждого запускает `binwalk`/`unblob`, определяет архитектуру, пытается `FirmAE run.sh`, собирает результат (какие сервисы поднялись, на каких портах) и логи. Так строят бенчмарк покрытия эмуляции (какой процент образов удалось запустить). Полезно фиксировать причины неудач (нет ядра, паника, отсутствие NVRAM) — они подсказывают, что доработать вручную. Для отладки конкретного образа удобно вести журнал шагов и держать снапшоты диска, чтобы откатываться.

## Проверка уязвимостей после запуска

Когда сервис поднят в эмуляции, переходят к поиску уязвимостей: фаззинг CGI/HTTP-обработчиков (`ffuf`, `wfuzz`, AFL в QEMU-режиме), ручное тестирование инъекций (command injection в `system`/`popen`, path traversal, переполнения в `strcpy`/`sprintf`). Отладка найденного бага ведётся в `gdb-multiarch` с `target remote`, брейкпоинтами на опасные функции и анализом регистров. Эмуляция даёт повторяемость и позволяет проверить эксплойт, не рискуя реальным устройством. Итог — PoC и рекомендации по прошивке.

## Квиз

```quiz
- question: "Что делает binwalk -Me?"
  options:
    - "Рекурсивно извлекает файлы из прошивки"
    - "Запускает прошивку"
    - "Шифрует прошивку"
    - "Сканирует порты"
  answer: 0
  explanation: "binwalk извлекает вложенные ФС/архивы из образа."
- question: "Чем FirmAE лучше firmadyne?"
  options:
    - "Решает больше проблем (NVRAM, init, kernel) при запуске"
    - "Он только для ARM"
    - "Он не эмулирует"
    - "Он компилятор"
  answer: 0
  explanation: "FirmAE улучшает成功率 эмуляции по сравнению с firmadyne."
- question: "Что нужно для сетевого сервиса прошивки?"
  options:
    - "QEMU system (с ядром/сетью)"
    - "QEMU user"
    - "Только binwalk"
    - "Только nm"
  answer: 0
  explanation: "Полноценная сеть/ядро даёт system-режим."
- question: "Почему важна архитектура?"
  options:
    - "Нужен правильный QEMU (MIPS BE/LE, ARM и т.д.)"
    - "Она влияет на ASLR"
    - "Она определяет порт"
    - "Она не важна"
  answer: 0
  explanation: "Эмулятор и анализ зависят от ISA/endianness."
- question: "Как отлаживать сервис прошивки?"
  options:
    - "qemu -g <порт> и gdb-multiarch"
    - "nm"
    - "ldd"
    - "objdump -h"
  answer: 0
  explanation: "QEMU предоставляет gdbstub; подключается gdb-multiarch."
```

## Где пригодится

- **CTF:** Reversing/IoT — прошивки.
- **Firmware research:** поиск уязвимостей.
- **IoT pentest:** анализ устройств.
- **Работа:** embedded security.
