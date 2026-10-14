---
id: network-module-wifi-sec
title: "Модуль: безопасность Wi-Fi — enterprise, WIDS, геолокация"
category: network
parent: network-evil-twin
difficulty: hard
order: 1
tags: [network, wireless, wifi, module]
prerequisites: [network-evil-twin]
useful_for:
  - "CTF Network (Wi-Fi)"
  - "Пентест: беспроводные сети"
  - "Работа: анализ эфира"
estimated_minutes: 50
summary: "Навигационный модуль про безопасность Wi-Fi: enterprise-аутентификация, системы обнаружения и геолокация."
---

## Вопрос, с которого всё начинается

В корпоративных сетях Wi-Fi — это enterprise-аутентификация, системы обнаружения rogue-точек и даже геолокация. Отдельный пласт.

## Что покрывает

- [`network-wifi-enterprise`](network-wifi-enterprise) — 802.1X/EAP.
- [`network-wireless-ids`](network-wireless-ids) — WIDS.
- [`network-wigle-geolocation`](network-wigle-geolocation) — WiGLE.

## Что мы теперь знаем

- Управляющие кадры — основа Wi-Fi-атак.
- Enterprise-вектор — перехват учёток, а не взлом шифра.
- Transition-режимы оставляют слабости.

## Квиз

Проверь себя.

```quiz
- question: "На чём строятся deauth/evil twin?"
  options:
    - "На данных"
    - "На управляющих кадрах"
    - "На пароле"
    - "На порту"
  answer: 1
  explanation: "Management frames."
- question: "Что главное в enterprise Wi-Fi?"
  options:
    - "Взлом шифра"
    - "Перехват учёток"
    - "Цвет"
    - "GPS"
  answer: 1
  explanation: "Креды."
- question: "Чем опасен transition-режим?"
  options:
    - "Ничем"
    - "Совместимость со слабым WPA2"
    - "Ускорением"
    - "Цветом"
  answer: 1
  explanation: "Слабость."
```

## Куда дальше

Смотри уроки модуля по порядку.

## Где пригодится

- CTF: Wi-Fi.
- Пентест: беспроводные.
- Работа: анализ.
