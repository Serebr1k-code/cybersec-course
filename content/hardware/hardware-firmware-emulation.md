---
id: hardware-firmware-emulation
title: "Эмуляция прошивок: QEMU, firmadyne и запуск бинарников"
category: hardware
parent: hardware-firmware-extract
difficulty: hard
order: 2
tags: [emulation, qemu, firmadyne, firmAE, mips, arm, chroot]
prerequisites: [hardware-firmware-extract]
useful_for:
  - "CTF-задачи категории Hardware"
  - "Пентест IoT: динамический анализ без железа"
  - "Фаззинг бинарников прошивки"
estimated_minutes: 45
summary: "Как запустить извлечённую прошивку в QEMU: user-mode для отдельных бинарников, full-system через firmadyne/firmAE, настройка сети и NVRAM."
---
Извлечь файлы — половина дела. Динамический анализ требует запустить бинарники прошивки: так обнаруживаются уязвимости, которые не видны статически (переполнения, command injection в веб-интерфейсе, небезопасные вызовы). Эмуляция позволяет исследовать устройство без риска его «окирпичить» и без физического доступа.

## Теория

Два режима эмуляции:

1. **User-mode (qemu-user)** — запускает отдельный бинарник, транслируя системные вызовы. Быстро, но нет ядра, сети и части `ioctl`. Годится для анализа CLI-утилит и некоторых сервисов.
2. **Full-system (qemu-system)** — эмулирует целую машину (ядро + rootfs). Реалистично, но сложно: нужно ядро, device tree, настройка сети, NVRAM.

Ключевые сложности:

- **Архитектура.** MIPS (big/little-endian), ARM, ARM64, RISC-V. Нужно определить и подобрать эмулятор.
- **Ядро.** Нужно подходящее ядро для qemu-system; часто берут из самой прошивки (zImage/uImage) или собирают buildroot-ядро.
- **NVRAM.** Многие прошивки хранят конфиг в NVRAM, реализованной поверх флеша; без неё сервисы падают.
- **Сеть.** Надо «прокинуть» сеть внутрь эмулятора и настроить интерфейсы так, как ожидает прошивка.
- **Endianness.** `file` показывает `LSB` (little, обычно `mipsel`) или `MSB` (big, `mips`) — от этого зависит выбор `qemu-*`.

**firmadyne / firmAE** автоматизируют full-system эмуляцию: сами определяют архитектуру, распаковывают образ, патчат ядро и NVRAM, поднимают сеть. firmAE — улучшенная версия с большей успешностью.

**Почему это важно.** Статический анализ (Ghidra) находит «подозрительные» функции, но доказать эксплуатируемость можно только запустив сервис: command injection видно лишь при реальном вызове, а heap-переполнение требует среды выполнения.

## Инструменты и команды

- **qemu-user-static** + `binfmt_misc` — запуск бинарников без настройки ядра.
- **qemu-system-mips/arm/aarch64** — full-system.
- **firmadyne / firmAE** — автоматизированная эмуляция.
- **FAT (Firmware Analysis Toolkit)** — обёртка над firmadyne.
- **chroot / proot** — запуск rootfs как окружения.
- **buildroot** — сборка ядра/rootfs для сложных случаев.
- **gdb-multiarch** — удалённая отладка через gdb-стаб QEMU.
- **ghidra / radare2** — статика для сопоставления.

```bash
# --- USER-MODE ---
sudo apt install qemu-user-static binfmt-support
# Определить архитектуру бинарника
file rootfs/bin/busybox
# => ELF 32-bit LSB executable, MIPS, MIPS32, dynamically linked

# Запуск через qemu-user с указанием rootfs и интерпретатора
sudo chroot rootfs qemu-mipsel-static /bin/sh
# либо
qemu-mipsel-static -L rootfs rootfs/usr/sbin/telnetd

# --- FULL-SYSTEM через firmAE ---
git clone --recursive https://github.com/pr0v3rbs/FirmAE
cd FirmAE && ./download.sh && sudo ./install.sh
sudo ./run.sh -r <brand> firmware.bin       # -r = run
sudo ./run.sh -a <brand> firmware.bin       # -a = analyze, подсказывает эксплойты

# --- Вручную: qemu-system ---
qemu-system-mipsel -M malta -kernel vmlinux -hda rootfs.img \
  -append "root=/dev/sda console=ttyS0" -nographic \
  -netdev user,id=n0 -device e1000,netdev=n0
```

## Флаги QEMU, которые нужны чаще всего

| Флаг | Назначение |
|------|-----------|
| `-L <dir>` | путь к библиотекам/интерпретатору (user-mode) |
| `-g <port>` | открыть gdb-стаб на порту (user-mode) |
| `-strace` | трассировка системных вызовов |
| `-d in_asm,cpu` | лог трансляции/регистров (отладка) |
| `-M <machine>` | тип машины (`malta` для MIPS) |
| `-kernel <img>` | ядро |
| `-hda <img>` | образ диска/rootfs |
| `-append "..."` | cmdline ядра (`root=`, `console=`) |
| `-nographic` | вывод в терминал без окна |
| `-netdev user,...` | user-mode сеть (NAT) |
| `-device e1000,...` | сетевой адаптер |

## Разобранный пример: эмуляция роутера и доступ к вебу

**Дано:** распакованная прошивка MIPS-роутера, файл `fw.bin`.

**Шаг 1 — определить архитектуру:**
```bash
file squashfs-root/bin/busybox
# MIPS, MIPS32, LSB -> mipsel
```
Если `MSB` — big-endian (`mips`), `LSB` — little-endian (`mipsel`).

**Шаг 2 — быстрый user-mode тест.** Копируем `qemu-mipsel-static` в rootfs и chroot'им:
```bash
sudo cp /usr/bin/qemu-mipsel-static squashfs-root/
sudo chroot squashfs-root /qemu-mipsel-static /bin/sh
```
Теперь у нас шелл «внутри» прошивки. Запускаем веб-сервер:
```bash
/qemu-mipsel-static /usr/sbin/httpd
# Многие упадут из-за отсутствия NVRAM — это ожидаемо
```

**Шаг 3 — full-system через firmAE:**
```bash
sudo ./run.sh -r router fw.bin
# firmAE выведет IP эмулированного устройства, напр. 192.168.0.1
```
Затем:
```bash
# Проверяем, что веб поднялся
curl -s http://192.168.0.1/ | head
# Ищем интерфейсы и сервисы
nmap -sV 192.168.0.1
```

**Шаг 4 — динамический анализ.** Раз веб работает, запускаем фаззинг/тесты:
```bash
# Каталоги
ffuf -u http://192.168.0.1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
# Проверка на command injection в CGI (типовой класс для роутеров)
curl -s "http://192.168.0.1/cgi-bin/ping.cgi?host=127.0.0.1;id"
```

**Шаг 5 — отладка бинарника.** Запускаем сервис под gdb-multiarch:
```bash
# терминал 1: qemu с gdb-стабом
qemu-mipsel-static -g 1234 -L squashfs-root squashfs-root/usr/sbin/httpd
# терминал 2
gdb-multiarch -ex "set architecture mips" -ex "target remote :1234" \
  -ex "b main" -ex "c"
```

**Шаг 6 — NVRAM.** Если сервисы падают из-за NVRAM, эмулируем её (firmadyne делает это автоматически) или патчим бинарник, чтобы он читал конфиг из файла. Частая замена: подменяем вызовы `nvram_get` на чтение из подготовленного файла.

## Разобранный пример: трассировка падений через -strace

Когда сервис падает, `-strace` показывает, чего не хватает:
```bash
qemu-mipsel-static -strace -L squashfs-root squashfs-root/usr/sbin/httpd 2>&1 | head -30
# open("/dev/nvram", O_RDONLY) = -1 ENOENT (No such file or directory)
```
Видно точную причину — отсутствие `/dev/nvram`. Дальше создаём заглушку или патчим.

## Частые ошибки

- **Неверная архитектура/эндианность.** Симптом: `Exec format error`. Перепроверьте `file` и возьмите правильный `qemu-*`.
- **Отсутствие `-L rootfs`.** Без указания библиотек бинарник не найдёт интерпретатор/so. Используйте `-L` или chroot.
- **Сервис падает без NVRAM.** Не баг эмуляции — прошивка ждёт NVRAM. Эмулируйте её или патчите.
- **Нет сети.** В user-mode сети нет вообще; для сетевых сервисов нужен full-system.
- **Слишком старая/новая версия firmAE.** Зависимости (binwalk, ядра) чувствительны; используйте свежий клон и `./install.sh`.
- **Игнорирование того, что устройство «думает», что оно на железе.** Некоторые проверки (GPIO, watchdog) валят сервис — патчим или обходим.
- **Запуск под root без нужды.** Full-system требует root, но помните об изоляции: эмулятор — это код устройства, потенциально враждебный.

## firmadyne против firmAE: что выбрать

| Критерий | firmadyne | firmAE |
|----------|-----------|--------|
| Успешность запуска | ниже | выше (патчи для многих вендоров) |
| Автонастройка сети | базовая | улучшенная |
| NVRAM | эмуляция | эмуляция + патчи |
| Поддержка | архивная | активнее |
| Ядра | старые | обновлённые |
| Время запуска | быстрее | дольше (больше эвристик) |

**Порядок работы:** сначала firmAE (`./run.sh -r`), при неудаче — firmadyne, затем ручной qemu-system. Если и это не удаётся, переходите к статическому анализу в Ghidra и симуляции отдельных функций через Unicorn/Qiling.

## Типовые ошибки загрузки ядра

**Kernel panic — не найден root.** В cmdline ядра неверно указан `root=`. Посмотрите строку загрузки в оригинальном логе UART (`hardware-uart`) и повторите её в `-append`.

**Не тот `-M` (machine).** Для MIPS-роутеров чаще всего `malta`; для ARM — `vexpress-a9`/`virt`. Неверная машина = ядро не стартует.

**Нет консоли.** Добавьте `console=ttyS0` в cmdline и `-nographic`. Без этого вывод «теряется».

**initrd не найден.** Если прошивка использует initramfs, укажите `-initrd` и правильный `rdinit`.

**Watchdog убивает эмулятор.** Прошивка ждёт «пинков» watchdog. Патчите ядро (firmadyne это делает) или отключайте watchdog в конфиге.

**GPIO/ioctl возвращают ошибки.** В user-mode `ioctl` для неизвестных устройств падает — используйте full-system или патчите вызовы на заглушки.

**Файловая система только для чтения.** Некоторые squashfs монтируются ro; для сервисов, пишущих конфиг, нужен overlay или копия в ext4.

## Что дальше / решение

- **Веб поднялся** → фаззинг эндпоинтов, поиск command injection и авторизационных дыр.
- **Сервис падает** → `-strace`, ищем отсутствующие файлы/устройства, ставим заглушки.
- **Нужен отладчик** → `-g <port>` + `gdb-multiarch`, ставим брейкпоинты на подозрительные функции.
- **Эмуляция не удалась** → попробуйте firmadyne, затем ручной qemu-system с ядром из образа; если и это не вышло — переходите к статике.
- **Успех** → задокументируйте найденные уязвимости и воспроизводимые PoC.

## Справочные таблицы

**Соответствие архитектур эмуляторам:**

| `file` | qemu-user | qemu-system |
|--------|-----------|-------------|
| MIPS LSB | qemu-mipsel-static | qemu-system-mipsel |
| MIPS MSB | qemu-mips-static | qemu-system-mips |
| ARM | qemu-arm-static | qemu-system-arm |
| ARM64 | qemu-aarch64-static | qemu-system-aarch64 |
| RISC-V | qemu-riscv32-static | qemu-system-riscv32 |

**Сравнение режимов:**

| Критерий | user-mode | full-system |
|----------|-----------|-------------|
| Скорость | высокая | низкая |
| Сеть | нет | да |
| Ядро | не нужно | нужно |
| NVRAM/GPIO | нет | частично |
| Сложность | низкая | высокая |



## Квиз

```quiz
- question: "Чем user-mode эмуляция отличается от full-system?"
  options:
    - "User-mode запускает отдельный бинарник, full-system эмулирует целую машину с ядром"
    - "User-mode медленнее"
    - "User-mode работает только на ARM"
    - "Это одно и то же"
  answer: 0
- question: "Как определить эндианность бинарника?"
  options:
    - "По выводу `file`: MSB = big-endian, LSB = little-endian"
    - "По размеру файла"
    - "По имени файла"
    - "По дате сборки"
  answer: 0
- question: "Что автоматизирует firmAE?"
  options:
    - "Full-system эмуляцию: определение архитектуры, распаковку, патч ядра/NVRAM, настройку сети"
    - "Только распаковку squashfs"
    - "Запись прошивки во флеш"
    - "Подбор паролей"
  answer: 0
- question: "Почему сервис в эмуляции может падать, хотя на железе работает?"
  options:
    - "Не хватает NVRAM/GPIO/watchdog, которых нет в эмуляторе"
    - "Прошивка зашифрована"
    - "Неверный бод-рейт"
    - "Недостаточно RAM"
  answer: 0
- question: "Зачем нужен `-L rootfs` в qemu-user?"
  options:
    - "Указать путь к библиотекам и интерпретатору эмулируемой системы"
    - "Задать язык интерфейса"
    - "Ограничить память"
    - "Включить логирование"
  answer: 0
```

## Где пригодится

- **CTF:** Hardware-задачи, где нужно запустить прошивку и найти уязвимость в её сервисах.
- **Пентест IoT:** динамический анализ без физического устройства, поиск RCE.
- **Bug bounty:** воспроизведение уязвимостей устройств, фаззинг веб-интерфейса.
- **Работа:** malware/прошивка-анализ, разработка эксплойтов, research.
- **Дальше по дереву:** `hardware-iot-network` (атака сетевых сервисов), `hardware-crypto` (ключи внутри).
