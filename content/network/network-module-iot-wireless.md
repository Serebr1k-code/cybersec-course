---
id: network-module-iot-wireless
title: "Модуль: IoT-радио — Thread/Matter и Z-Wave"
category: network
parent: network-zigbee-zwave
difficulty: hard
order: 1
tags: [network, wireless, wifi, module]
prerequisites: [network-zigbee-zwave]
useful_for:
  - "CTF Network (Wi-Fi)"
  - "Пентест: беспроводные сети"
  - "Работа: анализ эфира"
estimated_minutes: 50
summary: "Навигационный модуль про умный дом: Thread/Matter и Z-Wave."
---

## Вопрос, с которого всё начинается

Умный дом строится на специализированных радио-протоколах: Thread/Matter и Z-Wave. У них своя модель безопасности.

## Что покрывает

- [`network-thread-matter`](network-thread-matter) — Thread/Matter.
- [`network-zwave-deep`](network-zwave-deep) — Z-Wave S0/S2.

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
