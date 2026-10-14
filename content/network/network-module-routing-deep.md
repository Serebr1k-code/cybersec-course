---
id: network-module-routing-deep
title: "Модуль: динамическая маршрутизация глубоко — OSPF, IS-IS, FHRP, multicast, PTP"
category: network
parent: network-module-routing
difficulty: hard
order: 3
tags: [network, routing, module]
prerequisites: [network-module-routing]
useful_for:
  - "CTF Network (маршрутизация)"
  - "Пентест: инъекции маршрутов"
  - "Работа: анализ маршрутизации"
estimated_minutes: 50
summary: "Навигационный модуль про протоколы динамической маршрутизации и смежные механизмы: OSPF, IS-IS, FHRP, IGMP/multicast и PTP."
---

## Вопрос, с которого всё начинается

Маршрутизаторы обмениваются информацией о топологии автоматически. Чтобы атаковать или защищать сеть, нужно понимать эти протоколы и смежные механизмы.

## Что покрывает

- [`network-ospf-deep`](network-ospf-deep) — OSPF, LSA, аутентификация.
- [`network-isis`](network-isis) — IS-IS и TLV.
- [`network-vrrp-hsrp`](network-vrrp-hsrp) — FHRP-захват.
- [`network-igmp-multicast`](network-igmp-multicast) — multicast.
- [`network-ptp-1588`](network-ptp-1588) — точное время.

## Что мы теперь знаем

- IGP (OSPF/IS-IS) и EGP (BGP) — разные протоколы.
- Аутентификация часто отсутствует или слабая.
- FHRP даёт захват шлюза и MITM.

## Квиз

Проверь себя.

```quiz
- question: "Что такое IGP?"
  options:
    - "Внутренний протокол маршрутизации"
    - "Внешний"
    - "Шифр"
    - "Порт"
  answer: 0
  explanation: "Interior Gateway Protocol."
- question: "Чем опасен захват FHRP?"
  options:
    - "Ничем"
    - "MITM для подсети"
    - "Ускорением"
    - "Цветом"
  answer: 1
  explanation: "Резервный шлюз."
- question: "Что часто отсутствует в протоколах маршрутизации?"
  options:
    - "Аутентификация"
    - "Адресация"
    - "Метрики"
    - "Порты"
  answer: 0
  explanation: "Аутентификация."
```

## Куда дальше

Смотри уроки модуля по порядку.

## Где пригодится

- CTF: маршрутизация.
- Пентест: сеть.
- Работа: анализ.
