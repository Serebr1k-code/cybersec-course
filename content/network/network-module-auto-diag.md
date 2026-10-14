---
id: network-module-auto-diag
title: "Модуль: Диагностика и подключённость"
category: network
parent: network-module-automotive-net
difficulty: medium
order: 1
tags: [network, module, roadmap]
prerequisites: [network-module-automotive-net]
useful_for:
- Пентест connected car.
- CTF Automotive.
- Аудит ECU.
estimated_minutes: 10
summary: "Obd-ii, doip (iso 13400), some/ip и automotive ethernet"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Диагностика и подключённость»: OBD-II, DoIP (ISO 13400), SOME/IP и Automotive Ethernet.

- **network-obd2** — OBD-II: PID, DTC и режимы диагностики.
- **network-doip** — DoIP: диагностика поверх IP (ISO 13400).
- **network-someip** — SOME/IP: сервис-ориентированная шина в автомобиле.
- **network-automotive-ethernet** — Automotive Ethernet: 100BASE-T1 и TSN.

## Почему такой порядок

Диагностика и сервисные шины — основная точка входа в автомобиль, поэтому идут первыми.

## Что вы сможете после этапа

- Читать диагностические сервисы OBD-II/DoIP.
- Разбирать SOME/IP поверх Ethernet.

## Квиз

Проверь себя.

```quiz
- question: Что такое DoIP?
  options:
    - "Диагностика поверх IP (ISO 13400)"
    - "Протокол Wi-Fi"
    - "Формат файла"
    - "Тип шины LIN"
  answer: 0
  explanation: DoIP переносит диагностику UDS по IP.
- question: Что даёт OBD-II?
  options:
    - "Доступ к PID/DTC и режимам диагностики"
    - "Шифрование CAN"
    - "Прошивку ЭБУ"
    - "GPS-координаты"
  answer: 0
  explanation: OBD-II стандартизует диагностические запросы.
- question: Что такое SOME/IP?
  options:
    - "Сервис-ориентированный middleware поверх Ethernet"
    - "Тип разъёма"
    - "Протокол зарядки"
    - "Формат токена"
  answer: 0
  explanation: SOME/IP — SOA-протокол Automotive Ethernet.
```

## Где пригодится

- Пентест connected car.
- CTF Automotive.
- Аудит ECU.
