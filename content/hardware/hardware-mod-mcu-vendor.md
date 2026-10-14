---
id: hardware-mod-mcu-vendor
title: "Модуль: Вендорные MCU-ядра"
category: hardware
parent: hardware-mod-mcu
difficulty: medium
order: 1
tags: [hardware, xtensa, esp32, esp8266, avr, pic, 8051, module, roadmap]
prerequisites: [hardware-mod-mcu, hardware-firmware-extract]
useful_for:
  - "Реверс прошивок ESP и 8-битных MCU"
  - "CTF Hardware/Embedded"
  - "Аудит IoT-устройств"
estimated_minutes: 12
summary: "Подмодуль о не-ARM ядрах, которые встречаются в массовых устройствах: Xtensa (ESP32/ESP8266) и классических 8-битных AVR/PIC/8051."
---

ARM доминирует, но не покрывает всё. Дешёвые Wi-Fi-модули Espressif построены на ядре **Xtensa**, а огромный пласт мелкой электроники — на 8-битных **AVR/PIC/8051**. Это другой набор инструментов и другой взгляд на защиту.

## Что покрывает подмодуль

1. **Xtensa / ESP32 / ESP8266** (`hardware-xtensa-esp`) — архитектура Espressif, карта флеша, secure boot, шифрование флеша и работа с `esptool`.
2. **AVR / PIC / 8051** (`hardware-avr-pic`) — 8-битные ядра, fuse-биты, AVRISP/PICkit и обход защиты чтения.

## Почему такой порядок

Xtensa сложнее и современнее: у ESP есть Wi-Fi-стек, RTOS и полноценная защита загрузки. Разобрав её, вы увидите, как на маленьком ядре умещается целая платформа. Затем AVR/PIC — минимализм: там защита почти целиком в fuse-битах, а логика — в паре килобайт кода.

## Как проходить

- Для ESP: `esptool.py`, `esp-idf`, `Ghidra` с модулем Xtensa, разбор разделов флеша.
- Для AVR/PIC: `avrdude`, `pk2cmd`, `binwalk`, дизассемблеры для 8-битных ISA.
- Каждый пример ведите от «получить дамп» до «понять, где хранится секрет».

## Чему вы научитесь

- Разбирать флеш ESP по разделам и находить bootloader/приложение.
- Понимать, как secure boot и flash encryption меняют картину.
- Читать 8-битный код и оценивать fuse-защиту.
- Выбирать правильный инструмент под конкретный чип.

## Квиз

```quiz
- question: "На каком ядре построены ESP32/ESP8266?"
  options:
    - "Xtensa"
    - "ARM Cortex-A"
    - "x86"
  answer: 0
  explanation: "Espressif использует Xtensa."
- question: "Что ограничивает чтение прошивки AVR чаще всего?"
  options:
    - "Fuse-биты защиты (lock bits)"
    - "Пароль в EEPROM"
    - "Отсутствие тактового генератора"
  answer: 0
  explanation: "Lock-биты запрещают чтение и дальнейшую запись."
- question: "Зачем нужен esptool при работе с ESP32?"
  options:
    - "Для чтения/записи флеша и разбора разделов прошивки"
    - "Для программирования на Python"
    - "Для настройки Wi-Fi-роутера"
  answer: 0
  explanation: "esptool — основной инструмент работы с флешем Espressif."
```

## Где пригодится

- **CTF:** Hardware/Embedded-задачи по ESP и 8-битным MCU.
- **Пентест:** анализ недорогих IoT-устройств.
- **Работа:** разработка прошивок и оценка их защищённости.
- **Дальше по дереву:** `hardware-mod-silicon`, `hardware-firmware-extract`.
