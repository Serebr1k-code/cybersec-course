---
id: network-module-ics-deep
title: "Модуль: промышленные протоколы глубоко — Modbus, DNP3, S7, PROFINET, EtherCAT, OPC UA"
category: network
parent: network-module-industrial
difficulty: hard
order: 1
tags: [network, ics, ot, scada, module]
prerequisites: [network-module-industrial]
useful_for:
  - "CTF Network (ICS-дампы)"
  - "Пентест: АСУ ТП"
  - "Работа: анализ ICS"
estimated_minutes: 50
summary: "Навигационный модуль про промышленные протоколы: детальный разбор Modbus, DNP3, S7comm, PROFINET, EtherCAT и OPC UA."
---

## Вопрос, с которого всё начинается

АСУ ТП говорит на десятках протоколов, каждый — со своими особенностями. Чтобы анализировать промышленную сеть, нужно понимать конкретный протокол: его функции, кадры и слабости.

## Что покрывает

- [`network-modbus-deep`](network-modbus-deep) — Modbus/TCP детально.
- [`network-dnp3`](network-dnp3) — DNP3 и Secure Auth.
- [`network-s7comm`](network-s7comm) — Siemens S7.
- [`network-profinet`](network-profinet) — PROFINET.
- [`network-ethercat`](network-ethercat) — EtherCAT.
- [`network-opcua`](network-opcua) — OPC UA.

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
