---
id: network-module-msg-wire
title: "Модуль: брокеры и IoT на проводе — Redis, Memcached, CoAP, Modbus-encap"
category: network
parent: network-quic
difficulty: hard
order: 3
tags: [network, app-protocols, module]
prerequisites: [network-quic]
useful_for:
  - "CTF Network (разбор протоколов)"
  - "Пентест: прикладные сервисы"
  - "Работа: анализ трафика"
estimated_minutes: 50
summary: "Навигационный модуль про протоколы брокеров/кэшей и IoT: Redis, Memcached, CoAP и Modbus-инкапсуляция."
---

## Вопрос, с которого всё начинается

Брокеры и кэши (Redis, Memcached) и IoT-протоколы (CoAP) часто оказываются открытыми. Их «провод» стоит знать.

## Что покрывает

- [`network-redis-wire`](network-redis-wire) — RESP.
- [`network-memcached`](network-memcached) — протокол и амплификация.
- [`network-coap-deep`](network-coap-deep) — CoAP/observe/DTLS.
- [`network-modbus-encap`](network-modbus-encap) — RTU/ASCII поверх TCP.

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
