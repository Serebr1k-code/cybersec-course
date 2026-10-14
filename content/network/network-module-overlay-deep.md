---
id: network-module-overlay-deep
title: "Модуль: оверлеи и контейнерные сети — GENEVE, TUN/TAP, netns, Docker"
category: network
parent: network-gre-vxlan
difficulty: hard
order: 1
tags: [network, datacenter, overlay, module]
prerequisites: [network-gre-vxlan]
useful_for:
  - "CTF Network (ЦОД/оверлеи)"
  - "Пентест: контейнеры/ЦОД"
  - "Работа: анализ"
estimated_minutes: 50
summary: "Навигационный модуль про оверлеи и контейнерные сети: GENEVE, TUN/TAP, сетевые неймспейсы и Docker-сети."
---

## Вопрос, с которого всё начинается

ЦОД и облака строятся на оверлеях: логические сети поверх физических. Плюс контейнеры создают свои сети. Это отдельный мир инкапсуляции и неймспейсов.

## Что покрывает

- [`network-geneve`](network-geneve) — GENEVE-инкапсуляция.
- [`network-tun-tap`](network-tun-tap) — TUN/TAP.
- [`network-network-namespaces`](network-network-namespaces) — netns/veth/bridge.
- [`network-docker-network`](network-docker-network) — Docker-сети.

## Что мы теперь знаем

- Underlay и overlay — разные уровни.
- Контейнерные сети имеют свою маршрутизацию.
- Storage-сети часто без аутентификации.

## Квиз

Проверь себя.

```quiz
- question: "Что такое overlay?"
  options:
    - "Логическая сеть поверх физической"
    - "Кабель"
    - "Шифр"
    - "Порт"
  answer: 0
  explanation: "Overlay."
- question: "Чем опасна плоская сеть ЦОД?"
  options:
    - "Ничем"
    - "Одна точка входа = много систем"
    - "Ускорением"
    - "Цветом"
  answer: 1
  explanation: "Плоскостность."
- question: "Что часто не защищено в storage?"
  options:
    - "iSCSI/NVMe-oF"
    - "DNS"
    - "HTTP"
    - "SMTP"
  answer: 0
  explanation: "Storage."
```

## Куда дальше

Смотри уроки модуля по порядку.

## Где пригодится

- CTF: ЦОД.
- Пентест: контейнеры.
- Работа: анализ.
