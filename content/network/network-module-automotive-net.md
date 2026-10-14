---
id: network-module-automotive-net
title: "Модуль: авто-сети, диагностика и подключённость"
category: network
parent: network-module-embedded
difficulty: hard
order: 4
tags: [network, automotive, can, module]
prerequisites: [network-module-automotive]
useful_for:
  - "CTF Network (авто-дампы)"
  - "Пентест: автомобильная электроника"
  - "Работа: анализ авто-сетей"
estimated_minutes: 50
summary: "Навигационный модуль про современные автомобильные сети, диагностику и связь с внешним миром: automotive Ethernet, DoIP, OBD-II, keyless, EV-зарядка и телематика."
---

## Вопрос, с которого всё начинается

Современная машина — это Ethernet, IP-диагностика, беспроводные ключи, зарядка и постоянная связь с облаком. Каждый из этих каналов — отдельная поверхность атаки.

## Что покрывает

- [`network-automotive-ethernet`](network-automotive-ethernet) — Ethernet в авто.
- [`network-doip`](network-doip) — диагностика поверх IP.
- [`network-obd2`](network-obd2) — OBD-II, PID и DTC.
- [`network-keyless-relay`](network-keyless-relay) — бесключевой доступ.
- [`network-ev-charging`](network-ev-charging) — зарядка EV (CCS/OCPP).
- [`network-automotive-telematics`](network-automotive-telematics) — телематика и OTA.

## Что мы теперь знаем

- Автомобильные сети — набор шин и протоколов разного уровня.
- CAN — основа; поверх него UDS/DoIP.
- Защита в CAN опциональна и часто отсутствует.

## Квиз

Проверь себя.

```quiz
- question: "Какая шина — основа автомобильных сетей?"
  options:
    - "CAN"
    - "Wi-Fi"
    - "GTP"
    - "SIP"
  answer: 0
  explanation: "CAN — основная шина."
- question: "Что работает поверх CAN для диагностики?"
  options:
    - "UDS"
    - "AIS"
    - "APRS"
    - "SCTP"
  answer: 0
  explanation: "UDS — диагностика."
- question: "Есть ли в классическом CAN аутентификация?"
  options:
    - "Да"
    - "Нет"
    - "Только ночью"
    - "Только на грузовиках"
  answer: 1
  explanation: "В CAN нет аутентификации."
```

## Куда дальше

Смотри уроки модуля по порядку.

## Где пригодится

- CTF: авто-дампы.
- Пентест: авто.
- Работа: анализ.
