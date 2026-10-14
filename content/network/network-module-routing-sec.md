---
id: network-module-routing-sec
title: "Модуль: маршрутизация и L2 — MPLS, BGPsec, SDN, DHCP snooping, private VLAN"
category: network
parent: network-module-routing
difficulty: hard
order: 4
tags: [network, routing, module]
prerequisites: [network-module-routing]
useful_for:
  - "CTF Network (маршрутизация)"
  - "Пентест: инъекции маршрутов"
  - "Работа: анализ маршрутизации"
estimated_minutes: 50
summary: "Навигационный модуль про безопасность маршрутизации и L2-механизмы: атаки MPLS, RPKI/BGPsec, SDN/OpenFlow, DHCP snooping и private VLAN."
---

## Вопрос, с которого всё начинается

Помимо базовых протоколов есть механизмы безопасности и «экзотика»: MPLS, RPKI, SDN, а также L2-защиты, которые можно обойти.

## Что покрывает

- [`network-mpls-attacks`](network-mpls-attacks) — MPLS/LDP.
- [`network-bgp-security`](network-bgp-security) — RPKI/ROA.
- [`network-sdn-openflow`](network-sdn-openflow) — SDN/OpenFlow.
- [`network-dhcp-snooping`](network-dhcp-snooping) — snooping/DAI.
- [`network-private-vlan`](network-private-vlan) — PVLAN escapes.

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
