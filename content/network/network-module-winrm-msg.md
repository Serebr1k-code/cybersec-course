---
id: network-module-winrm-msg
title: "Модуль: WinRM и обмен сообщениями — Kafka, AMQP, MQTT"
category: network
parent: network-ntlm-relay
difficulty: hard
order: 3
tags: [network, app-protocols, module]
prerequisites: [network-ntlm-relay]
useful_for:
  - "CTF Network (разбор протоколов)"
  - "Пентест: прикладные сервисы"
  - "Работа: анализ трафика"
estimated_minutes: 50
summary: "Навигационный модуль про WinRM/WS-Man и брокеры сообщений: Kafka, AMQP, MQTT."
---

## Вопрос, с которого всё начинается

WinRM управляет Windows по сети, а брокеры (Kafka, AMQP, MQTT) переносят сообщения между сервисами и устройствами. У каждого — свой «провод» и свои риски.

## Что покрывает

- [`network-winrm-wire`](network-winrm-wire) — SOAP/WS-Man.
- [`network-kafka-wire`](network-kafka-wire) — брокеры, ACL.
- [`network-amqp-deep`](network-amqp-deep) — AMQP 0-9-1/1.0.
- [`network-mqtt-deep`](network-mqtt-deep) — QoS, retained, wildcard.

## Что мы теперь знаем

- Прикладные протоколы — надёжная поверхность атаки.
- Фрейминг и заголовки задают границы сообщений.
- Авторизацию проверяют по полям, а не по «доверию».

## Квиз

Проверь себя.

```quiz
- question: "Что задаёт границы сообщений в бинарных протоколах?"
  options:
    - "Цвет"
    - "Фрейминг (длина)"
    - "Порт"
    - "DNS"
  answer: 1
  explanation: "Длина/фрейминг."
- question: "Почему важны метаданные?"
  options:
    - "Они бесполезны"
    - "Показывают методы/пути/коды"
    - "Только для красоты"
    - "Для зарядки"
  answer: 1
  explanation: "Разведка."
- question: "Где чаще всего ошибки авторизации?"
  options:
    - "В TLS"
    - "В прикладных API"
    - "В кабеле"
    - "В батарее"
  answer: 1
  explanation: "Прикладной уровень."
```

## Куда дальше

Смотри уроки модуля по порядку.

## Где пригодится

- CTF: разбор протоколов.
- Пентест: сервисы.
- Работа: анализ.
