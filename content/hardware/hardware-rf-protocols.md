---
id: hardware-rf-protocols
title: "Протоколы ближнего действия"
category: hardware
parent: hardware-rf
difficulty: easy
order: 1
tags: [hardware, rfid, bluetooth, zigbee]
prerequisites: [hardware-rf]
useful_for:
  - "CTF: Hardware"
  - "Пентест: IoT/умный дом"
  - "Работа: RF-безопасность"
estimated_minutes: 12
summary: "Этап RFID/NFC, Bluetooth/BLE и Zigbee/Z-Wave."
---

Этот урок — **этап-навигатор** в ветке. Он короткий: его задача — объяснить, что вы будете изучать на этом этапе, почему темы идут именно в таком порядке и что вы сможете делать после прохождения.

## О чём этот этап

Второй этап радио — про протоколы ближнего действия: RFID/NFC (чтение, клонирование, Mifare), Bluetooth/BLE (сниффинг, спаривание, GATT) и Zigbee/Z-Wave (сниффинг, replay).

## Что вы освоите

- RFID и NFC: чтение, клонирование и атаки на Mifare
- Bluetooth и BLE: сниффинг, спаривание, GATT-атаки
- Zigbee и Z-Wave: сниффинг, спаривание, replay

## Как проходить

Начните с RFID/NFC — самый доступный инструментарий (Proxmark). Затем BLE (нужен адаптер) и Zigbee/Z-Wave (нужен сниффер соответствующего диапазона).

## Квиз

```quiz
- question: "Какой инструмент используют для работы с RFID/NFC?"
  options:
    - "Proxmark3"
    - "RTL-SDR"
    - "Bus Pirate"
    - "JTAGulator"
  answer: 0
  explanation: "Proxmark3 — стандартный инструмент для RFID/NFC."
- question: "Чем опасно незащищённое BLE-спаривание?"
  options:
    - "Возможен перехват и MITM соединения"
    - "Оно ускоряет передачу"
    - "Оно шифрует данные"
    - "Оно отключает Wi-Fi"
  answer: 0
  explanation: "Слабое спаривание позволяет перехватить обмен."
- question: "Что часто атакуют в Zigbee/Z-Wave?"
  options:
    - "Команды управления устройством (replay)"
    - "DNS-запросы"
    - "TLS-сертификаты"
    - "SMTP"
  answer: 0
  explanation: "Replay команд включает чужие устройства."
```

## Где пригодится

- **CTF:** Hardware
- **Пентест:** IoT/умный дом
- **Работа:** RF-безопасность
