---
id: network-module-ics-proto
title: "Модуль: Классические протоколы АСУ ТП"
category: network
parent: network-module-ics-deep
difficulty: medium
order: 1
tags: [network, module, roadmap]
prerequisites: [network-module-ics-deep]
useful_for:
- Аудит АСУ ТП.
- Пентест ICS.
- CTF ICS.
estimated_minutes: 10
summary: "Modbus/tcp глубоко, dnp3, s7comm и profinet"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Классические протоколы АСУ ТП»: Modbus/TCP глубоко, DNP3, S7comm и PROFINET.

- **network-modbus-deep** — Modbus/TCP глубоко: функции, регистры и запись.
- **network-dnp3** — DNP3: кадры, unsolicited и Secure Authentication.
- **network-s7comm** — S7comm / S7comm-plus: протокол Siemens PLC.
- **network-profinet** — PROFINET: RT/IRT, DCP и обнаружение устройств.

## Почему такой порядок

Классические протоколы доминируют на действующих объектах, поэтому идут первыми.

## Что вы сможете после этапа

- Разбирать функции Modbus и кадры DNP3.
- Понимать S7comm и PROFINET.

## Квиз

Проверь себя.

```quiz
- question: Что позволяет функция записи Modbus?
  options:
    - "Изменять регистры/катушки контроллера"
    - "Читать логи"
    - "Шифровать"
    - "Резервировать"
  answer: 0
  explanation: Запись меняет состояние ПЛК.
- question: Чем опасен DNP3 без Secure Authentication?
  options:
    - "Подделкой и повтором кадров"
    - "Ускорением"
    - "Шифрованием"
    - "Сжатием"
  answer: 0
  explanation: Без SA кадры можно подделать/повторить.
- question: Какой протокол использует Siemens PLC?
  options:
    - "S7comm"
    - "Modbus"
    - "BACnet"
    - "OCPP"
  answer: 0
  explanation: S7comm — протокол Siemens.
```

## Где пригодится

- Аудит АСУ ТП.
- Пентест ICS.
- CTF ICS.
