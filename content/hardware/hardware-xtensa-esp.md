---
id: hardware-xtensa-esp
title: "Xtensa / ESP32 / ESP8266: реверс и захват"
category: hardware
parent: hardware-mod-mcu-vendor
difficulty: medium
order: 1
tags: [hardware, xtensa, esp32, esp8266, esptool, secure-boot, flash]
prerequisites: [hardware-mod-mcu, hardware-firmware-extract]
useful_for:
  - "Реверс прошивок ESP"
  - "CTF Hardware/Embedded"
  - "Аудит IoT-устройств"
estimated_minutes: 50
summary: "Как разобрать прошивку ESP32/ESP8266: архитектура Xtensa, разделы флеша, esptool, secure boot и шифрование флеша — что реально защищает, а что нет."
lab:
  kind: shell
  title: "Практика: разделы флеша ESP32"
  toolset: [core]
  workdir: /home/student/esp32
  files: [task.md, esptool.log, notes.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Открой лог: `cat esptool.log`."
    - "Найди строку с флагом: `grep nto esptool.log`."
    - "Флаг идёт после `app_desc=`."
    - "Итог: `grep app_desc esptool.log | grep nto | cut -d= -f2 > found.txt`."
---

## Вопрос, с которого всё начинается

Дешёвые Wi-Fi-модули **ESP32/ESP8266** стоят в миллионах устройств: умные розетки, датчики, игрушки. Они построены на ядре **Xtensa** — не ARM и не RISC-V. Как выгрузить и разобрать их прошивку и что там за защита?

## Наш пример: лог работы с флешем ESP32

Перед нами `esptool.log` — вывод утилиты `esptool.py`, которая работает с флешем ESP32. Смотрим:

```
$ head -8 esptool.log
esptool.py v4.6
Chip is ESP32-D0WD (revision 1)
Flash size: 4MB
Detected flash size: 4MB
Reading flash 0x10000..0x1FFFF
Partition table: nvs, otadata, app0, app1
app_desc=nto{3sp32_fl4sh_3ncrypt}
```

Здесь видно, как `esptool` определяет чип, читает флеш и находит **разделы**. Разберём.

## Шаг 1: что такое Xtensa

**Xtensa** — конфигурируемое ядро компании Tensilica (принадлежит Cadence). Оно не ARM и не RISC-V: у него собственная система команд с переменной длиной и опциональными расширениями. Espressif лицензировала Xtensa для ESP8266 (L106) и ESP32 (LX6/LX7), а в ESP32-C/S добавила RISC-V.

Для реверса это значит: нужен дизассемблер с поддержкой **Xtensa** (Ghidra имеет модуль, есть `xtensa-esp32-elf-objdump` в ESP-IDF).

## Шаг 2: карта флеша и разделы

ESP-прошивка — это не один бинарник, а **набор разделов** на флеше:

| Раздел | Назначение |
|--------|-----------|
| bootloader | первичная загрузка |
| partition table | карта разделов |
| nvs | энергонезависимое хранилище (настройки, Wi-Fi-креды) |
| otadata | выбор активного приложения (OTA) |
| app0/app1 | приложения (A/B для обновлений) |

Карта задаётся по смещению **0x8000**. Зная её, можно выгрузить каждый раздел отдельно.

## Шаг 3: esptool

`esptool.py` — основной инструмент:

- `esptool.py chip_id` — определить чип;
- `esptool.py read_flash 0 0x400000 dump.bin` — выгрузить весь флеш;
- `esptool.py read_flash 0x10000 0x100000 app.bin` — выгрузить приложение;
- `esptool.py write_flash ...` — записать (модификация).

Если флеш не зашифрован и secure boot выключен, выгрузка даёт полный дамп с кодом и настройками.

## Шаг 4: где искать секреты

В прошивке ESP часто лежат:

- **Wi-Fi SSID/пароли** (в nvs или в коде);
- **ключи API**, токены облака;
- **конфигурация** и адреса серверов;
- **отладочные строки** и версии.

Инструменты: `strings`, `binwalk`, `Ghidra`. NVS хранит ключ-значение; её тоже можно распарсить.

## Шаг 5: secure boot и flash encryption

Espressif предлагает две защиты:

- **Secure Boot** — bootloader и приложение подписаны; проверка подписи при загрузке. Версия v1 была уязвима (можно было обойти), v2 использует RSA/ECDSA и надёжнее.
- **Flash Encryption** — содержимое флеша зашифровано (AES); ключ в eFuse. Тогда дамп бесполезен без ключа.

Важно: обе защиты **включаются через eFuse**, и ошибки в конфигурации оставляют щели. Известны случаи, когда secure boot можно было обойти из-за доступной отладки или утечки ключей.

## Шаг 6: что мы нашли в логе

В файле есть строка с описанием приложения:

```
$ grep app_desc esptool.log
app_desc=nto{3sp32_fl4sh_3ncrypt}
```

Мы извлекли флаг из вывода `esptool`. Смысл: если flash encryption не включён, дамп флеша даёт всё — код, настройки, секреты. Поэтому проверяют именно статус защиты.

## Шаг 7: типовые векторы атаки

- **UART bootloader** — если не заблокирован, `esptool` читает флеш.
- **eFuse не прошиты** — secure boot/encryption выключены.
- **OTA-канал** — подмена обновления при слабой подписи.
- **Сторонние библиотеки** — уязвимости в Wi-Fi/HTTP-стеке.
- **Отладочный UART** — вывод логов с чувствительными данными.

## Шаг 8: защита

- **Включить secure boot v2** и **flash encryption**.
- **Прошить eFuse** (запретить доступ к отладке и чтению ключей).
- **Отключить debug-логи** в релизе.
- **Проверять OTA-подпись**.
- **Обновлять ESP-IDF** и библиотеки.

## Что мы теперь знаем

1. ESP32/ESP8266 построены на **Xtensa** (не ARM/RISC-V).
2. Прошивка — набор **разделов** (bootloader, table, nvs, otadata, app0/1).
3. **esptool** читает/пишет флеш; без защиты дамп даёт всё.
4. **Secure Boot v2** и **flash encryption** защищают, но включаются через eFuse.
5. Секреты (Wi-Fi, токены) лежат в nvs или коде.

## Квиз

Проверь себя.

```quiz
- question: "На каком ядре построен ESP32 (классический)?"
  options:
    - "Xtensa"
    - "ARM Cortex-M"
    - "x86"
    - "MIPS"
  answer: 0
  explanation: "Espressif использует Xtensa (в C/S — RISC-V)."
- question: "Какой инструмент читает/пишет флеш ESP?"
  options:
    - "esptool.py"
    - "nmap"
    - "sqlmap"
    - "openssl"
  answer: 0
  explanation: "esptool — основной инструмент Espressif."
- question: "Что такое flash encryption?"
  options:
    - "Шифрование содержимого флеша ключом из eFuse"
    - "Сжатие прошивки"
    - "Ускорение Wi-Fi"
    - "Замена корпуса"
  answer: 0
  explanation: "Без ключа дамп флеша бесполезен."
- question: "Где ESP хранит настройки и Wi-Fi-креды?"
  options:
    - "В разделе nvs"
    - "В bootloader"
    - "В otadata"
    - "В partition table"
  answer: 0
  explanation: "NVS — энергонезависимое key-value хранилище."
- question: "Как включаются secure boot и flash encryption?"
  options:
    - "Через eFuse"
    - "Через Wi-Fi"
    - "Через UART-консоль"
    - "Автоматически"
  answer: 0
  explanation: "Настройки защиты фиксируются в eFuse."
```

## Куда дальше

ESP — это современные ядра. Но огромный пласт дешёвой электроники до сих пор на **8-битных AVR/PIC/8051**. О них — следующий урок. А пока главное: **у ESP защита существует, но держится на eFuse и конфигурации — и ошибка в них открывает всю прошивку.**

## Где пригодится

- **CTF:** Hardware/Embedded-задачи по ESP.
- **Пентест:** анализ IoT-устройств.
- **Работа:** разработка и защита ESP-прошивок.
- **Дальше по дереву:** `hardware-avr-pic`, `hardware-firmware-extract`.
