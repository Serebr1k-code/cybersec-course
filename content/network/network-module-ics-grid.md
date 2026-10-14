---
id: network-module-ics-grid
title: "Модуль: энергетика, здания и модель АСУ ТП — IEC 61850/104, BACnet, HART-IP, Purdue"
category: network
parent: network-module-industrial
difficulty: hard
order: 2
tags: [network, ics, ot, scada, module]
prerequisites: [network-module-industrial]
useful_for:
  - "CTF Network (ICS-дампы)"
  - "Пентест: АСУ ТП"
  - "Работа: анализ ICS"
estimated_minutes: 50
summary: "Навигационный модуль про отраслевые протоколы энергетики и зданий, а также про модель сегментации АСУ ТП и системы безопасности (SIS)."
---

## Вопрос, с которого всё начинается

Разные отрасли используют разные протоколы: энергетика — IEC 61850/104, здания — BACnet, приборы — HART-IP. Плюс есть общая модель сегментации и отдельный класс систем безопасности.

## Что покрывает

- [`network-iec61850`](network-iec61850) — подстанции (MMS/GOOSE/SV).
- [`network-iec104`](network-iec104) — телемеханика IEC 60870-5-104.
- [`network-bacnet`](network-bacnet) — автоматизация зданий.
- [`network-hart-ip`](network-hart-ip) — процессные приборы.
- [`network-ics-purdue`](network-ics-purdue) — модель сегментации.
- [`network-ics-safety`](network-ics-safety) — системы безопасности (SIS).

## Что мы теперь знаем

- ICS-протоколы часто без аутентификации.
- Чтение и запись имеют разный физический риск.
- Ключевая защита — сегментация (Purdue, зоны/кондуиты).

## Квиз

Проверь себя.

```quiz
- question: "Чем ICS отличается от IT по риску?"
  options:
    - "Ничем"
    - "Ошибка влияет на физический процесс"
    - "Только скоростью"
    - "Только ценой"
  answer: 1
  explanation: "Физический процесс."
- question: "Что часто отсутствует в ICS-протоколах?"
  options:
    - "Аутентификация"
    - "Адресация"
    - "CRC"
    - "Порты"
  answer: 0
  explanation: "Нет аутентификации."
- question: "Что такое Purdue-модель?"
  options:
    - "Шифр"
    - "Уровневая модель сегментации АСУ ТП"
    - "Протокол"
    - "Антенна"
  answer: 1
  explanation: "Модель уровней/зон."
```

## Куда дальше

Смотри уроки модуля по порядку.

## Где пригодится

- CTF: ICS-дампы.
- Пентест: АСУ ТП.
- Работа: анализ.
