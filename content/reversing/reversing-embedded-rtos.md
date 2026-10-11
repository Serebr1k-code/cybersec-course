---
id: reversing-embedded-rtos
title: "Реверс embedded/RTOS: FreeRTOS и bare-metal"
category: reversing
parent: reversing-firmware-basics
difficulty: hard
order: 1
tags: [reversing, embedded, rtos, freertos, bare-metal, cortex-m, iot]
prerequisites: [reversing-firmware, reversing-architectures]
useful_for:
  - "CTF Reversing"
  - "IoT security"
  - "Firmware analysis"
estimated_minutes: 60
summary: "Разбор прошивок embedded: Cortex-M, bare-metal, FreeRTOS, восстановление задач, символов и логики."
---
Прошивки embedded (ARM Cortex-M, ESP32/Xtensa, AVR, RISC-V) отличаются от обычных бинарей радикально: нет ОС (bare-metal) или работает простой RTOS (FreeRTOS/Zephyr/RT-Thread), свой layout памяти, memory-mapped периферия и **часто нет символов** в релизной сборке. Реверс таких прошивок — ключ к IoT-безопасности: уязвимость в обработчике UART/RF-команды или в ISR открывает путь к устройству. Этот урок — особенности, инструменты и полный workflow разбора embedded/RTOS от определения архитектуры до поиска уязвимостей.

## Особенности embedded, которые ломают привычный реверс

- **Архитектуры:** ARM Cortex-M (только Thumb/Thumb-2!), Xtensa (ESP32), AVR (8-бит), RISC-V, MIPS (роутеры). Дизассемблер обязан поддерживать конкретную ISA и режим.
- **Bare-metal:** нет `main` в привычном смысле; после сброса выполняется reset-handler, а «потоки» — это прерывания (ISR). Нет syscalls, нет libc (иногда — newlib/nano).
- **RTOS:** задачи (tasks), очереди, семафоры, мьютексы. Планировщик переключает контекст по прерыванию (обычно `PendSV` на Cortex-M).
- **Memory-mapped I/O:** периферия управляется регистрами по фиксированным адресам (например, `0x4000_0000+`); без SVD-описаний смысл регистров непонятен.
- **Vector table:** таблица векторов в начале flash: начальный SP, reset-handler, затем обработчики исключений и прерываний.
- **Нет символов** в release; имена восстанавливаются по строкам, SVD, сигнатурам библиотек.

## Определение архитектуры и загрузка

```bash
file firmware.bin
# firmware.bin: data            <- часто сырой .bin без заголовка

binwalk firmware.bin
# DECIMAL  HEXADECIMAL  DESCRIPTION
# 0        0x0          ARM executable code, 16-bit (Thumb), little endian
# 262144   0x40000      Squashfs filesystem, ...

# Если есть ELF — читаем заголовок
readelf -h firmware.elf | grep -E 'Machine|Entry|Flags'
# Machine: ARM, Flags: 0x5000200, Version5 EABI, soft-float ABI
```

Для Cortex-M выбирайте в Ghidra/IDA процессор **ARM:LE:32:Cortex** (little-endian, Thumb) — это автоматически включает Thumb-декодирование. Для ESP32 — Xtensa (LX6/LX7). Определить endianness и режим можно по байтам vector table: первые 4 байта — начальный SP (обычно `0x2000_xxxx` для SRAM), следующие 4 — reset-handler (нечётный адрес → Thumb, младший бит = 1).

## Vector table и точки входа

Vector table Cortex-M (адреса — фиксированные смещения от базы flash):

```text
0x00: initial SP        (например 0x20005000)
0x04: reset handler     (адрес | 1 для Thumb)
0x08: NMI handler
0x0C: HardFault handler
0x10: MemManage, 0x14: BusFault, 0x18: UsageFault
0x2C: SVC, 0x38: PendSV, 0x3C: SysTick
0x40+: внешние IRQ (GPIO, UART, SPI, таймеры...)
```

Анализ начинается так: найдите vector table (по первому значению-указателю на SRAM), прочитайте reset-handler, разберите инициализацию (`SystemInit`, копирование `.data`, обнуление `.bss`), затем найдите `main`/суперцикл. ISR-адреса берите прямо из таблицы — их можно дизассемблировать как функции.

```bash
# Быстро вытащить первые адреса (little-endian)
python3 - <<'EOF'
d = open('firmware.bin','rb').read()
import struct
for i in range(0, 0x40, 4):
    print(hex(i), hex(struct.unpack_from('<I', d, i)[0]))
EOF
```

## FreeRTOS: восстановление задач

FreeRTOS-прошивка строится вокруг `xTaskCreate`:

```c
BaseType_t xTaskCreate(TaskFunction_t pxTaskCode, const char *pcName,
                       uint16_t usStackDepth, void *pvParameters,
                       UBaseType_t uxPriority, TaskHandle_t *pxCreatedTask);
```

План восстановления:

```text
1) Найти xTaskCreate (по строкам имён задач или по сигнатуре вызова).
2) Из аргументов извлечь указатели на функции задач -> анализировать каждую.
3) Найти TCB-структуры (Task Control Block) — списки задач планировщика.
4) Определить точки ввода (UART/сеть/USB/RF) -> поверхность атаки.
5) Найти обработчики команд и проверить границы буферов.
```

Имена задач часто сохранены как строки — это лучший якорь:

```bash
strings -a firmware.bin | grep -iE "task|uart|cmd|shell|debug"
```

По `pcName` в `xTaskCreate` находят соответствующую функцию задачи через xref. Планировщик на Cortex-M переключает контекст в `PendSV_Handler` (обычно ассемблер, сохраняет R4–R11 в стек задачи).

## Memory-mapped I/O и SVD

Регистры периферии — просто адреса. Без имён они выглядят как `*(0x40011000) = 0x...`. SVD-файлы (CMSIS-SVD) содержат описания всех регистров и битовых полей:

```bash
# Ghidra: File -> Import -> SVD (плагин) -> применяет имена к адресам
# IDA: плагин svd2ida / ida-svd
# Ручной поиск базы периферии в декомпиляторе:
#   частые адреса: 0x40000000+ (APB), 0x50000000+ (AHB), 0xE000E000 (SysTick/NVIC)
```

Так вы превращаете `*(0x40004804) = 0x0D` в `USART1->BRR = 0x0D` — понятный код настройки UART.

## Практический workflow

```text
1) Идентифицировать архитектуру/endianness/режим (Thumb).
2) Найти vector table/reset-handler, восстановить инициализацию.
3) Импортировать SVD, восстановить периферию (регистры по адресам).
4) Найти задачи/ISR и разобрать логику каждой.
5) Найти протоколы/ввод (UART, RF, USB, BLE) -> поверхность атаки.
6) Искать уязвимости: переполнения буферов, command injection, слабая аутентификация.
7) Подтвердить на эмуляторе/железе.
```

## Инструменты

| Инструмент | Назначение |
|------------|------------|
| `binwalk` | извлечение образов/ФС, определение архитектуры |
| `Ghidra`/`IDA` | дизасм ARM/Xtensa, декомпиляция |
| `OpenOCD` + GDB | отладка на железе (JTAG/SWD) |
| SVD (CMSIS) | описания периферии для Ghidra/IDA |
| `QEMU` | эмуляция (Cortex-M ограниченно) |
| `Firmware Analysis Toolkit`/FAT | эмуляция Linux-прошивок |
| `renode` | эмуляция целых embedded-систем |

## Разобранный пример

```text
1) firmware.bin -> binwalk: ARM Cortex-M, Thumb.
2) Ghidra (ARM:LE:32:Cortex): vector table -> reset -> main.
3) В main находим xTaskCreate; строки: "uartTask", "cmdTask".
4) uartTask парсит команды через UART; видим strcpy(buf, input) без проверки длины.
5) Находим оверфлоу -> переполнение буфера в задаче с приоритетом планировщика.
6) Подтверждаем: OpenOCD+GDB на железе или QEMU (фрагментно) -> падение/контроль PC.
```

## Специфика других архитектур

Хотя Cortex-M — самый частый случай, другие платформы имеют свои особенности:

- **Xtensa (ESP32/ESP8266).** Проприетарная ISA, поддерживается в Ghidra (LX6) и IDA (плагин). Прошивки часто содержат flash-образ с `esptool`-заголовком (`0xE9` magic) и несколько сегментов; распаковывайте через `esptool.py image_info`/`esptool.py merge_bin`. Wi-Fi/BLE-логика идёт через SDK (ESP-IDF/Arduino), поверх — задачи FreeRTOS.
- **AVR (ATmega).** 8-битная архитектура, гарвардская память (код и данные — разные адресные пространства), регистры `R0..R31`, нет векторов в привычном виде, а есть таблица векторов-`jmp`. Дизасм — avr-objdump/Ghidra AVR.
- **RISC-V.** Открытая ISA; RV32IMC встречается во многих MCU. Дизасм — Ghidra/RISC-V, декомпиляция качественная.
- **MIPS (роутеры, IP-камеры).** Обычно Linux-прошивка (не bare-metal): SquashFS/JFFS2, ELF-бинари, BusyBox. Здесь работает обычный Linux-реверс, а поверх — `binwalk -e`, `sasquatch`, `firmwalker`.

Правило: сначала определите, **bare-metal или Linux** — это меняет весь пайплайн. Linux-прошивку извлекают `binwalk -eM` и анализируют как набор ELF; bare-metal лифтят целиком в Ghidra/IDA.

## Справочник команд и приёмов

| Задача | Команда/приём |
|--------|---------------|
| Определить архитектуру | `binwalk firmware.bin` |
| Извлечь ФС (Linux) | `binwalk -eM firmware.bin` |
| Заголовок ELF | `readelf -h firmware.elf` |
| Дизасм Thumb | `arm-none-eabi-objdump -d -M force-thumb fw.elf` |
| Строки/имена задач | `strings -a firmware.bin \| grep -iE 'task\|cmd'` |
| ESP32 образ | `esptool.py image_info firmware.bin` |
| Отладка на железе | `openocd -f interface/stlink.cfg -f target/stm32f4x.cfg` |
| Подключение GDB | `arm-none-eabi-gdb -ex 'target remote :3333' fw.elf` |
| Эмуляция Linux | `qemu-mipsel -L rootfs ./bin/httpd` |

## Восстановление символов и сигнатур библиотек

В release-прошивках символов нет, но их можно частично вернуть:

- **FLIRT/Lumina (IDA)** и **Function ID (Ghidra)** — сопоставление функций с базой сигнатур стандартных библиотек (newlib, FreeRTOS, CMSIS, ESP-IDF). Это автоматически называет `memcpy`, `xTaskCreate`, `vTaskDelay` и т.п.
- **Строки** — имена задач, assert-сообщения (`configASSERT`), пути к файлам.
- **Постоянные таблицы** — vector table (адреса ISR), таблицы планировщика FreeRTOS (`pxReadyTasksLists`), строки логов.
- **Даташит/референс-мануал MCU** — расшифровка регистров, если SVD недоступен.

Связка FLIRT + SVD превращает «анонимную» прошивку в читаемый код: вы видите вызовы известных функций и осмысленные обращения к периферии. Начните с FLIRT, затем уточняйте периферию по SVD.

## Частые ошибки

- **Неверный режим ARM.** Cortex-M работает только в Thumb; выбор ARM-режима даёт мусорную дизассембляцию.
- **Игнорирование vector table.** Reset — реальная точка входа; `main` вторична и может быть инлайнена.
- **Нет SVD.** Регистры периферии почти нечитаемы без описаний; половина времени уходит впустую.
- **Ожидание ОС.** Bare-metal не имеет syscalls/libc — не ищите их.
- **Пропуск ISR.** Существенная логика (в т.ч. уязвимая) часто именно в прерываниях.
- **Эмуляция всего образа.** QEMU не покрывает всю периферию; эмулируйте фрагментно или используйте Renode.
- **Игнорирование конца flash.** Часто в конце лежат таблицы/конфиги/ключи, а не код.

## Что делать дальше / решение

1. Определите ISA/режим/endianness (по vector table и binwalk).
2. Постройте карту памяти: flash, SRAM, периферия (из SVD/даташита).
3. Восстановите точку входа (reset) и `main`; импортируйте SVD.
4. Извлеките задачи (`xTaskCreate`) и ISR; разберите каждую.
5. Найдите поверхность атаки (UART/RF/USB/сеть) и проверьте обработчики на переполнения/injection.
6. Подтвердите находку на железе (OpenOCD) или в эмуляторе; оформите отчёт с адресами и PoC.

## Квиз

```quiz
- question: "Где находится точка входа Cortex-M-прошивки?"
  options:
    - "Reset handler из vector table"
    - "main напрямую"
    - "_start"
    - "DriverEntry"
  answer: 0
  explanation: "Vector table указывает reset-handler — реальную точку входа."
- question: "В каком режиме работает Cortex-M?"
  options:
    - "Thumb/Thumb-2"
    - "ARM (32-бит)"
    - "x86"
    - "MIPS"
  answer: 0
  explanation: "Cortex-M использует только Thumb; выбор ARM-режима даёт мусор."
- question: "Что создаёт задачи в FreeRTOS?"
  options:
    - "xTaskCreate"
    - "pthread_create"
    - "fork"
    - "CreateThread"
  answer: 0
  explanation: "xTaskCreate регистрирует задачу (функция, стек, приоритет)."
- question: "Что такое memory-mapped I/O?"
  options:
    - "Регистры периферии по фиксированным адресам"
    - "Сетевой протокол"
    - "Формат файла"
    - "Тип шифрования"
  answer: 0
  explanation: "Периферия управляется через регистры в адресном пространстве."
- question: "Зачем SVD-файлы?"
  options:
    - "Описания регистров периферии для анализа"
    - "Формат прошивки"
    - "Тип шифрования"
    - "Пакер"
  answer: 0
  explanation: "SVD даёт имена/адреса регистров для Ghidra/IDA."
```

## Где пригодится

- **CTF:** Reversing — embedded-задачи.
- **IoT security:** анализ прошивок.
- **Firmware analysis:** периферия/RTOS.
- **Работа:** embedded security.
