---
id: network-module-wireless-extra
title: "Модуль: LoRa и BLE Audio"
category: network
parent: network-mitm-wireless
difficulty: hard
order: 4
tags: [network, radio, sdr, module]
prerequisites: [network-module-rf]
useful_for:
  - "CTF Network (радио)"
  - "Пентест: беспроводные системы"
  - "Работа: анализ эфира"
estimated_minutes: 50
summary: "Небольшой модуль про дальнюю LPWAN-связь LoRa/LoRaWAN и про аудио по BLE."
---

## Вопрос, с которого всё начинается

За пределами Wi-Fi есть LPWAN для дальних датчиков (LoRa) и аудио поверх BLE. У обоих свои протоколы и риски.

## Что покрывает

- [`network-lora-lorawan`](network-lora-lorawan) — join-процедура, ключи, реплей.
- [`network-bluetooth-ble-audio`](network-bluetooth-ble-audio) — LE Audio и атаки.

## Что мы теперь знаем

- Радио — отдельный мир протоколов поверх физического уровня.
- SDR позволяет принимать и (с HackRF) передавать сигнал.
- Декодирование требует знания модуляции и структуры пакетов.

## Квиз

Проверь себя.

```quiz
- question: "Что такое SDR?"
  options:
    - "Программно-определяемое радио"
    - "Тип SIM"
    - "Антенна"
    - "Шифр"
  answer: 0
  explanation: "SDR — Software-Defined Radio."
- question: "Зачем нужна антенна под диапазон?"
  options:
    - "Для красоты"
    - "Для эффективного приёма слабых сигналов"
    - "Для зарядки"
    - "Для шифрования"
  answer: 1
  explanation: "Резонансная антенна критична для приёма."
- question: "Почему передача требует осторожности?"
  options:
    - "Она дорогая"
    - "Она может мешать и нарушать закон"
    - "Она медленная"
    - "Она не работает"
  answer: 1
  explanation: "Передача в чужих диапазонах незаконна."
```

## Куда дальше

Смотри уроки этого модуля по порядку.

## Где пригодится

- CTF: радио-задачи.
- Пентест: беспроводные системы.
- Работа: анализ эфира.
