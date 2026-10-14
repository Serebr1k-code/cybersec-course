---
id: network-module-iot-wire
title: "Модуль: IoT на проводе"
category: network
parent: network-module-msg-wire
difficulty: medium
order: 2
tags: [network, module, roadmap]
prerequisites: [network-module-msg-wire]
useful_for:
- Пентест IoT.
- CTF Network.
- Анализ протоколов.
estimated_minutes: 10
summary: "Coap (методы, observe, dtls) и modbus rtu/ascii поверх tcp"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «IoT на проводе»: CoAP (методы, observe, DTLS) и Modbus RTU/ASCII поверх TCP.

- **network-coap-deep** — CoAP: методы, observe и DTLS.
- **network-modbus-encap** — Modbus RTU/ASCII поверх TCP: инкапсуляция.

## Почему такой порядок

IoT-протоколы компактны и специфичны, поэтому разбираются отдельным этапом.

## Что вы сможете после этапа

- Разбирать CoAP и его DTLS.
- Понимать инкапсуляцию Modbus в TCP.

## Квиз

Проверь себя.

```quiz
- question: Что такое CoAP?
  options:
    - "Облегчённый REST-протокол для IoT"
    - "Протокол зданий"
    - "Формат файла"
    - "Тип шины"
  answer: 0
  explanation: CoAP — компактный UDP-протокол для устройств.
- question: Что даёт DTLS в CoAP?
  options:
    - "Защиту датаграмм"
    - "Сжатие"
    - "Резервирование"
    - "Логирование"
  answer: 0
  explanation: DTLS шифрует и аутентифицирует UDP.
- question: Зачем Modbus инкапсулируют в TCP?
  options:
    - "Чтобы переносить RTU/ASCII по сети"
    - "Чтобы шифровать"
    - "Чтобы сжать"
    - "Чтобы логировать"
  answer: 0
  explanation: Инкапсуляция переносит последовательный Modbus по IP.
```

## Где пригодится

- Пентест IoT.
- CTF Network.
- Анализ протоколов.
