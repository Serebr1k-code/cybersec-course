---
id: network-module-automotive-buses
title: "Модуль: автомобильные шины — CAN-FD, J1939, FlexRay, MOST"
category: network
parent: network-module-embedded
difficulty: hard
order: 3
tags: [network, automotive, can, module]
prerequisites: [network-module-automotive]
useful_for:
  - "CTF Network (авто-дампы)"
  - "Пентест: автомобильная электроника"
  - "Работа: анализ авто-сетей"
estimated_minutes: 50
summary: "Навигационный модуль про шины автомобиля за пределами классического CAN: расширенный CAN-FD, грузовой J1939, детерминированный FlexRay и мультимедийный MOST."
---

## Вопрос, с которого всё начинается

Классический CAN — не единственная шина в машине. Есть расширенный CAN-FD, грузовой J1939, детерминированный FlexRay и мультимедийный MOST. Понимание их различий нужно для полного анализа.

## Что покрывает

- [`network-can-fd`](network-can-fd) — расширенные кадры CAN-FD.
- [`network-can-injection`](network-can-injection) — инъекция и фаззинг.
- [`network-j1939`](network-j1939) — грузовые машины.
- [`network-flexray`](network-flexray) — детерминированные циклы.
- [`network-most-bus`](network-most-bus) — мультимедийное кольцо.

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
