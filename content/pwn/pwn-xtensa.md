---
id: pwn-xtensa
title: "Xtensa / ESP32: оконные регистры и эксплуатация прошивок"
category: pwn
parent: pwn-arch-embedded
difficulty: hard
order: 2
tags: [pwn, xtensa, esp32, embedded, windows, firmware, wifi]
prerequisites: [pwn-buffer-overflow, pwn-architectures]
useful_for:
  - "Эксплуатация ESP32 / IoT-устройств"
  - "Анализ Wi-Fi-прошивок"
estimated_minutes: 60
summary: "Xtensa: 32-битное ядро ESP32 с оконными регистрами и регистром возврата a0; реверс и эксплуатация прошивок IoT."
lab:
  kind: shell
  title: "Практика: определение ядра Xtensa"
  toolset: [core, elf]
  workdir: /home/student/task
  files: [task.md, xtensa.elf, xtensa.readelf.txt]
  check: "grep -q 'machine=Xtensa' answer.txt"
  hints:
    - "Xtensa — 32-битная архитектура, ядро ESP32 (little-endian)."
    - "`readelf --file-header` печатает `Machine:`."
    - "В строке `Machine:` есть `Xtensa`."
    - "Запиши `machine=Xtensa`."
---

## Вопрос, с которого всё начинается

ESP32 — самый популярный Wi-Fi-микроконтроллер для IoT. Под капотом —
архитектура **Tensilica Xtensa**, непохожая ни на ARM, ни на AVR: 32 бита,
оконные регистры и регистр возврата `a0`. Если ты нашёл переполнение в прошивке
ESP32, надо понимать её ABI. Разберём.

## Наш пример

```
$ file xtensa.elf
xtensa.elf: ELF 32-bit LSB relocatable, Tensilica Xtensa
$ readelf --file-header xtensa.elf
  Class:                             ELF32
  Data:                              2's complement, little endian
  Machine:                           Tensilica Xtensa Processor
```

32 бита, little-endian (ESP32). Дальше — модель вызовов.

## Шаг 1: регистры a0..a15

Xtensa даёт функции 16 «оконных» регистров `a0`..`a15`. Регистры `a0`..`a7`
используются для аргументов и временных значений, `a8`..`a15` — для локальных.
Главное: **адрес возврата лежит в `a0`**. Инструкция `call` кладёт адрес
возврата в `a0` (точнее, `call0`/`call4`/`call8`/`call12` — разные варианты
оконного вызова), а `ret` возвращается по `a0`.

## Шаг 2: окна и call/entry

Как SPARC, Xtensa умеет **оконные вызовы**: `call8`/`call12` «перекрывают»
регистры, передавая часть `a`-регистров вызываемому как аргументы. Это
оптимизация под embedded: меньше сохранений на стек.

Пролог не-leaf функции сохраняет `a0` на стек, потому что вложенный `call`
перезапишет его:

```
entry a1, 32          # открыть кадр 32 байта
s32i a0, a1, 0        # сохранить адрес возврата (a0) на стек
...
l32i a0, a1, 0        # восстановить a0
retw.n                # вернуться (с учётом окна)
```

Инструкция `entry` открывает кадр, `retw.n` — возврат с «retw» (rotate window).

## Шаг 3: точка перезаписи

Сохранённый `a0` на стеке — цель переполнения. Перезаписав его, ты управляешь
адресом возврата: после `l32i a0, ...; retw.n` процессор прыгнет туда. Смещение
считается от `a1` (указатель стека) до позиции `a0`. Для `entry a1, 32` это
обычно смещение 0 (самый низ кадра), поэтому аккуратно считай размер буфера.

## Шаг 4: little-endian и упаковка

В отличие от PowerPC/SPARC, Xtensa на ESP32 — little-endian:

```python
from pwn import *
context.arch = 'xtensa'
p = process('./challenge')
offset = 64
payload  = b'A' * offset
payload += p32(ret2win_addr)   # перезаписанный a0
p.sendline(payload)
p.interactive()
```

Если в твоём инструменте нет профиля `xtensa`, упаковывай вручную через
`struct.pack('<I', addr)`.

## Шаг 5: ESP32-специфика

Прошивки ESP32 (ESP-IDF или Arduino) собираются с линкер-скриптами, которые
раскладывают код в IRAM/DRAM/Flash. Отладка — через UART (`esptool`,
`esp-idf-monitor`) или JTAG. Поскольку устройство часто доступно по Wi-Fi,
поверхность атаки шире: переполнения в обработчиках HTTP, MQTT, BLE и т.п.
Реверс удобно вести в Ghidra с модулем Xtensa (или `objdump` из
`xtensa-esp32-elf-binutils`).

## Шаг 6: собираем эксплойт

1. Достаём прошивку (`esptool.py read_flash`) или OTA-образ.
2. Находим уязвимую функцию обработки ввода и размер буфера.
3. Вычисляем offset до сохранённого `a0`.
4. Подбираем адрес цели (существующая функция/гаджет в IRAM).
5. Формируем payload, доставляем через сетевой интерфейс и проверяем результат.

## Шаг 7: защитные особенности

На ESP32 есть **Secure Boot** и **Flash Encryption** — они мешают модифицировать
прошивку, но не обязательно мешают эксплуатации уже работающего кода. Также
доступен **Memory Protection Unit (MPU)**, но не полноценный MMU. Всё это
переносится на общий принцип: сначала обойти изоляцию, потом перехватить
управление.

## Что мы теперь знаем

- Xtensa — 32-битная little-endian архитектура с оконными регистрами.
- Адрес возврата — в `a0`; не-leaf функции сохраняют его на стек.
- Возврат — `retw.n` (с ротацией окна).
- ESP32 добавляет Wi-Fi-поверхность и Secure Boot/Flash Encryption.

## Квиз

Проверь себя.

```quiz
- question: В каком регистре Xtensa лежит адрес возврата?
  options:
    - "a15"
    - "a0"
    - "sp"
    - "pc"
  answer: 1
  explanation: call кладёт адрес возврата в a0; ret/retw.n возвращается по нему.
- question: Что делает инструкция entry?
  options:
    - "Открывает кадр стека"
    - "Вызывает систему"
    - "Обнуляет регистры"
    - "Возвращается"
  answer: 0
  explanation: entry a1, N открывает кадр размером N байт.
- question: Какой порядок байт у ESP32 (Xtensa)?
  options:
    - "big-endian"
    - "little-endian"
    - "смешанный"
    - "нет порядка"
  answer: 1
  explanation: ESP32 — little-endian, в отличие от PowerPC/SPARC.
- question: Какие защиты есть у ESP32?
  options:
    - "Только NX"
    - "Secure Boot и Flash Encryption"
    - "Никаких"
    - "Только ASLR"
  answer: 1
  explanation: ESP32 поддерживает Secure Boot и шифрование флеша.
```

## Куда дальше

На этом embedded-блок заканчивается. Дальше — современные ISA: **RISC-V 64** и
**AArch64 deep**. А пока запомни: **на Xtensa адрес возврата — сохранённый `a0`,
а вызовы могут быть оконными**.

## Где пригодится

- Эксплуатация ESP32 и других Xtensa-устройств.
- Анализ Wi-Fi/BLE-прошивок IoT.
- Понимание оконных архитектур (SPARC, Xtensa).
