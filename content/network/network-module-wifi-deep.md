---
id: network-module-wifi-deep
title: "Модуль: Wi-Fi нового поколения — 6/6E/7, Direct, mesh, WPA3"
category: network
parent: network-wpa3
difficulty: hard
order: 1
tags: [network, wireless, wifi, module]
prerequisites: [network-wpa3]
useful_for:
  - "CTF Network (Wi-Fi)"
  - "Пентест: беспроводные сети"
  - "Работа: анализ эфира"
estimated_minutes: 50
summary: "Навигационный модуль про современный Wi-Fi: 802.11ax/be, Wi-Fi Direct, mesh/roaming и WPA3."
---

## Вопрос, с которого всё начинается

Wi-Fi быстро развивается: новые стандарты (6/6E/7), новые режимы (Direct, mesh) и новый шифр (WPA3). У каждого — свои особенности и слабости.

## Что покрывает

- [`network-wifi-6e7`](network-wifi-6e7) — Wi-Fi 6/6E/7.
- [`network-wifi-direct`](network-wifi-direct) — P2P.
- [`network-wifi-mesh`](network-wifi-mesh) — mesh/roaming.
- [`network-wpa3-deep`](network-wpa3-deep) — WPA3/SAE.

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
