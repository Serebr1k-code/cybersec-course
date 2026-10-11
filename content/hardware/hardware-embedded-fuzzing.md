---
id: hardware-embedded-fuzzing
title: "Фаззинг встраиваемых бинарников"
category: hardware
parent: hardware-mod-embedded-fs
difficulty: hard
order: 3
tags: [fuzzing, afl, qemu, firmadyne]
prerequisites: [hardware-firmware-entropy, hardware-firmware-emulation]
useful_for:
  - "Поиск уязвимостей в прошивках"
  - "CTF Hardware/Pwn"
  - "Автоматический анализ бинарников IoT"
estimated_minutes: 50
summary: "Как перенести прошивочный бинарник на хост, настроить AFL++/QEMU, эмулировать устройство через FirmAE/Firmadyne и триажить краши."
---

Извлечь файловую систему прошивки — половина дела. Вторая половина — найти в её бинарниках уязвимости. Ручной реверс в Ghidra эффективен, но медленный; фаззинг автоматизирует поиск падений в парсерах (HTTP, конфиги, сетевые протоколы). Сложность в том, что встраиваемые бинарники собраны под MIPS/ARM и не запускаются на x86-хосте «как есть». Решение — эмуляция: `qemu-user` для одного бинарника, `Firmadyne`/`FirmAE` для целой прошивки.

Этот урок — практический пайплайн «бинарник → хост → AFL++ → краш → триаж». Мы разберём перенос бинарника, AFL++ с QEMU-режимом, полную эмуляцию через FirmAE и написание harness для сетевого демона.

## Зачем фаззить прошивочные бинарники

Прошивки роутеров, камер, NAS содержат десятки бинарников: `httpd`, `upnpd`, `dnsmasq`, `telnetd`, `cwmp` (TR-069). Большинство написано на C без современных защит (нет ASLR на MIPS, часто нет stack canary, NX выключен). Парсеры сетевых запросов — классическая цель: переполнение стека/кучи, format string, integer overflow.

Фаззинг даёт:
- Автоматическое нахождение падений (потенциальных RCE/DoS).
- Покрытие кода (какие функции достижимы).
- Воспроизводимые PoC (crash-инпуты).

Ограничение: падение ≠ уязвимость. Нужен триаж — понять, контролируем ли мы поток исполнения.

## Перенос бинарника на хост

Первый шаг — определить архитектуру и попробовать запустить через `qemu-user`.

```bash
file usr/sbin/httpd
# ELF 32-bit LSB executable, MIPS, MIPS32 rel2, dynamically linked
# interpreter /lib/ld-uClibc.so.0

# qemu-user с chroot в извлечённую rootfs
sudo cp /usr/bin/qemu-mips-static squashfs-root/usr/bin/
sudo chroot squashfs-root /usr/bin/qemu-mips-static /usr/sbin/httpd
# httpd: can't load library 'libc.so.0'
```

Проблема: динамические библиотеки. Решения:
1. **chroot в rootfs** — библиотеки на месте (`/lib`, `/usr/lib`).
2. **Копировать libc + ld** и запускать с `-L`:

```bash
qemu-mips -L ./squashfs-root ./squashfs-root/usr/sbin/httpd
# или
QEMU_LD_PREFIX=./squashfs-root qemu-mips ./squashfs-root/usr/sbin/httpd
```

3. **Статическая сборка AFL-QEMU** — если бинарник статический, `qemu-user` не нужен.

## AFL++: установка и базовый запуск

```bash
# установка
sudo apt install afl++        # или сборка из исходников

# проверка
afl-fuzz -V
# afl-fuzz++4.x.x

# подготовка: instrumented-сборка (для исходников) или QEMU mode (для готовых бинарников)
# --- QEMU mode (для встраиваемых бинарников) ---
afl-fuzz -Q -i in/ -o out/ -- ./usr/sbin/httpd @@

# --- QEMU mode с chroot-окружением ---
afl-fuzz -Q -i in/ -o out/ -- ./qemu-mips -L ./squashfs-root ./squashfs-root/usr/sbin/httpd @@
```

Ключевые флаги AFL++:

```bash
-i dir       # входной каталог с seed-инпутами
-o dir       # выходной каталог (queue, crashes, hangs)
-Q           # QEMU mode (бинарь без инструментации)
-m none      # лимит памяти (none = без лимита; для MIPS нужно)
-t 2000      # таймаут на запуск (мс)
-d           # «dumb» режим (без детерминированного этапа — быстрее)
-x dict      # словарь токенов (для HTTP/JSON)
-c program   # cmplog-бинарь
-M / -S      # master/slave для параллельного фаззинга
```

## QEMU user-mode и AFL: режим QEMU

AFL++ QEMU mode (`-Q`) запускает бинарник под патченным `afl-qemu-trace`, который собирает покрытие. Для встраиваемых это основной режим, потому что исходников нет.

```bash
# собрать QEMU-режим (если нет)
cd aflplusplus/qemu_mode && ./build_qemu_support.sh

# запуск с конкретной архитектурой
AFL_QEMU_ARCH=mips afl-fuzz -Q -i in/ -o out/ -- ./target @@

# переменные окружения
AFL_QEMU_PERSISTENT_ADDR=0x400000   # persistent mode по адресу
AFL_QEMU_DEBUG_MAPS=1                # отладка загрузки библиотек
AFL_INST_RATIO=30                    # доля инструментированных блоков
```

## Firmadyne / FirmAE: полная эмуляция

Для фаззинга сетевых демонов одного бинарника мало — нужна работающая система (сеть, NVRAM, `/proc`). `Firmadyne` и его форк `FirmAE` запускают всю прошивку в QEMU с эмуляцией периферии.

```bash
# --- FirmAE ---
git clone https://github.com/pr0v3rbs/FirmAE
cd FirmAE && ./download.sh && sudo ./install.sh
sudo ./run.sh -c <brand> -a <arch> firmware.bin
# -c: компания, -a: архитектура, результат: IP эмулированного устройства

# --- Firmadyne (классика) ---
sudo ./sources/extractor/extractor.py -b <brand> -sql 127.0.0.1 -np -nk firmware.bin images/
./scripts/getArch.sh ./images/1.tar.gz
./scripts/makeImage.sh 1
./scripts/inferNetwork.sh 1
sudo ./scratch/1/run.sh
```

После запуска устройство получает IP (например, 192.168.0.1), и его веб-интерфейс доступен с хоста. Дальше — обычный веб-пентест + фаззинг CGI.

## Написание harness для сетевого демона

Если фаззим функцию-парсер, нужен harness — маленькая программа, которая читает вход и вызывает целевую функцию. Для сетевого демона проще фаззить через сеть (AFL с `-Q` и запуском демона, либо `afl-net`).

Пример harness на C для функции `parse_config(buf, len)`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int parse_config(char *buf, int len);

int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(n);
    fread(buf, 1, n, f);
    fclose(f);
    parse_config(buf, n);   // целевая функция
    free(buf);
    return 0;
}
```

Компиляция с инструментацией и запуск:

```bash
afl-cc -o harness harness.c -L ./squashfs-root/lib -lconfig
afl-fuzz -i seeds/ -o out/ -- ./harness @@
```

Для сетевого демона — harness, который поднимает сокет, принимает запрос и передаёт его в парсер.

## Разобранный пример: фаззинг парсера конфига

Дано: бинарник `cfgmgr` (MIPS), читает файл конфигурации.

**Шаг 1 — подготовка seed'ов.** Кладём в `seeds/` реальные конфиги:

```bash
mkdir -p seeds out
cp squashfs-root/etc/config/* seeds/
ls seeds/
# network  wireless  dhcp
```

**Шаг 2 — запуск AFL++ в QEMU-режиме.**

```bash
AFL_QEMU_ARCH=mips afl-fuzz -Q -i seeds/ -o out/ -m none -t 2000 -- \
  ./qemu-mips -L ./squashfs-root ./squashfs-root/usr/sbin/cfgmgr @@
```

**Шаг 3 — наблюдение.**

```
american fuzzy lop ++4.10
[+] Found 3 initial seeds
[+] Fuzzing... exec speed: 850/s
[+] Crashes saved: out/default/crashes/
```

**Шаг 4 — анализ краша.**

```bash
ls out/default/crashes/
# id:000000,sig:11,src:000002,time:12345,execs:98765,op:havoc,rep:4
./qemu-mips -L ./squashfs-root ./squashfs-root/usr/sbin/cfgmgr out/default/crashes/id:000000...
# Segmentation fault (core dumped)
```

**Шаг 5 — триаж в GDB.**

```bash
qemu-mips -g 1234 -L ./squashfs-root ./squashfs-root/usr/sbin/cfgmgr crash_input &
gdb-multiarch ./squashfs-root/usr/sbin/cfgmgr
(gdb) target remote :1234
(gdb) c
# Program received signal SIGSEGV
(gdb) info registers
# ra: 0x41414141   <- контроль регистра возврата = переполнение
```

Если `ra` перезаписан нашими байтами — это exploitable-переполнение, а не просто DoS.

## Триаж крашей

Классификация падений:
- **SIGSEGV с контролем PC/ra** — потенциальный RCE (переполнение стека).
- **SIGSEGV по адресу из ввода** — управляемая запись/чтение.
- **SIGABRT/assert** — не уязвимость (проверка).
- **Timeout/hang** — DoS.
- **OOM** — утечка памяти.

Инструменты: `gdb-multiarch`, `qemu-mips -g`, `afl-analyze`, `valgrind` (если x86), `ASAN` (если пересобрать). Для автоматизации триажа — `afl-collect`, `exploitable` (gdb-плагин).

## Частые ошибки и подводные камни

- **Запуск без библиотек.** `can't load library` — копируйте libc/ld или используйте chroot/`-L`.
- **Не тот QEMU-бинарь.** Для MIPS little-endian — `qemu-mipsel`; для big-endian — `qemu-mips`. Перепутаете — не запустится.
- **Нет seed'ов.** Без качественных seed'ов AFL топчется. Дайте реальные конфиги/запросы.
- **`-m` слишком мал.** MIPS-эмуляция требует памяти; ставьте `-m none`.
- **Фаззинг без harness.** Демон с сетью нужно либо оборачивать в harness, либо фаззить через сеть.
- **Игнорировать NVRAM.** Многие бинарники зависят от переменных NVRAM — без эмуляции падают сразу.
- **Считать любой краш уязвимостью.** Триаж обязателен.
- **Не сохранять окружение.** Краш должен воспроизводиться — фиксируйте версию QEMU и параметры.

## Справочные таблицы

QEMU-бинари по архитектуре:

| Архитектура | qemu-user | AFL_QEMU_ARCH |
|-------------|-----------|---------------|
| MIPS BE | qemu-mips | mips |
| MIPS LE | qemu-mipsel | mipsel |
| ARM BE | qemu-armeb | armeb |
| ARM LE | qemu-arm | arm |
| AArch64 | qemu-aarch64 | aarch64 |
| PowerPC | qemu-ppc | ppc |

Инструменты эмуляции:

| Инструмент | Уровень | Назначение |
|------------|---------|------------|
| qemu-user | один бинарник | быстрый запуск |
| qemu-system | вся система | ядро + периферия |
| Firmadyne | прошивка | сеть + NVRAM |
| FirmAE | прошивка | улучшенный Firmadyne |
| AFL++ -Q | бинарник | фаззинг без исходников |

## Что дальше / решение

Дальнейшие шаги: (1) после краша с контролем PC — переходите к разработке эксплойта (ROP для MIPS/ARM); (2) фаззите сетевые демоны через FirmAE с реальным IP; (3) расширяйте покрытие словарями (`-x`) и persistent-режимом; (4) автоматизируйте триаж через `afl-collect` + exploitable. Для защиты: собирайте прошивки с ASLR/stack canary/NX, не используйте `strcpy`/`sprintf`, проверяйте границы парсеров. В авторизованном пентесте фиксируйте: бинарник, harness, команду фаззинга, краш-инпут и вердикт триажа.

## Практикум: масштабирование фаззинга

Когда один бинарник фаззится, возникает вопрос: как покрыть всю прошивку и не утонуть в тысячах крашей. Работайте итеративно и приоритизируйте по достижимости. Сначала инвентаризируйте сетевые демоны: что слушает порты, что обрабатывает внешние запросы. Из них выбирайте парсеры с наибольшей поверхностью ввода — HTTP-обработчики, UPnP, TR-069, DNS. Для каждого готовьте harness или сетевой тест-драйвер и запускайте короткие кампании (10-30 минут), чтобы получить первые краши и понять, стоит ли углубляться.

Управляйте ресурсами. Параллельный фаззинг (`-M master` и несколько `-S slave`) повышает покрытие, но требует ядер; для MIPS-эмуляции каждое исполнение дорого, поэтому лучше несколько целевых кампаний, чем одна размазанная. Держите словарь токенов (`-x dict`) под конкретный протокол — для HTTP это методы, заголовки и статусы; для бинарных форматов — магические числа и размеры полей. Словарь часто ускоряет нахождение глубоких веток в разы.

Триаж ведите централизованно: `afl-collect` собирает краши, дедуплицирует по стеку и раскладывает по каталогам; плагин `exploitable` в GDB присваивает категорию (`EXPLOITABLE`, `PROBABLY_EXPLOITABLE`, `UNKNOWN`, `NOT_EXPLOITABLE`). Это спасает от «тысячи крашей, ноль уязвимостей». Из подтверждённых exploitable-случаев делайте минимальный PoC: входной файл или сетевой пакет, который воспроизводит падение на оригинальном устройстве. Для отчёта фиксируйте: целевой бинарник и его хэш, harness, точную команду запуска AFL++, seed-набор, словарь, краш-инпут и вердикт триажа. Воспроизводимость важнее количества — один доказанный RCE стоит сотни необъяснённых SIGSEGV.

## Квиз

```quiz
- question: "Зачем нужен qemu-user при фаззинге прошивочного бинарника?"
  options:
    - "Чтобы запустить бинарник другой архитектуры (MIPS/ARM) на x86-хосте"
    - "Чтобы ускорить компиляцию"
    - "Чтобы зашифровать образ"
    - "Чтобы смонтировать ФС"
  answer: 0
- question: "Что означает флаг -Q у afl-fuzz?"
  options:
    - "QEMU mode — фаззинг бинарника без инструментации"
    - "Quiet mode"
    - "Quick mode"
    - "Quarantine"
  answer: 0
- question: "Чем FirmAE отличается от qemu-user?"
  options:
    - "FirmAE эмулирует всю прошивку с сетью и NVRAM"
    - "FirmAE только компилирует"
    - "FirmAE работает только на MIPS"
    - "Ничем"
  answer: 0
- question: "Что говорит о потенциальном RCE при триаже краша?"
  options:
    - "Регистр возврата/PC содержит байты из нашего ввода"
    - "Процесс зависает"
    - "Выводится сообщение об ошибке"
    - "Файл не найден"
  answer: 0
- question: "Почему без seed'ов фаззинг неэффективен?"
  options:
    - "AFL стартует с пустого входа и почти не покрывает код"
    - "AFL требует 1000 seed'ов"
    - "Seed'ы нужны только для сборки"
    - "Без них не запустится QEMU"
  answer: 0
```

## Где пригодится

- **Пентест:** автоматический поиск уязвимостей в прошивках IoT.
- **CTF:** Hardware/Pwn-задачи на эмуляцию и фаззинг.
- **Работа:** аудит встраиваемого ПО, поиск 0-day в парсерах.
- **Исследования:** покрытие кода и воспроизведение крашей.
