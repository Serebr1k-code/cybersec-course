---
id: network-module-appprotos-deep
title: "Модуль: современные прикладные протоколы — gRPC, WebSocket, WebRTC, TLS 1.3"
category: network
parent: network-module-appprotos
difficulty: hard
order: 4
tags: [network, app-protocols, module]
prerequisites: [network-module-appprotos]
useful_for:
  - "CTF Network (разбор протоколов)"
  - "Пентест: прикладные сервисы"
  - "Работа: анализ трафика"
estimated_minutes: 50
summary: "Навигационный модуль про современные прикладные протоколы поверх HTTP/2 и TLS: gRPC, WebSocket, WebRTC и детали TLS 1.3."
---

## Вопрос, с которого всё начинается

Современные приложения ушли от простого HTTP/1.1: gRPC, WebSocket, WebRTC и TLS 1.3 — это другой обмен, другое фреймирование, другие риски.

## Что покрывает

- [`network-grpc`](network-grpc) — gRPC/protobuf поверх HTTP/2.
- [`network-websocket`](network-websocket) — upgrade, фреймы, hijack.
- [`network-webrtc`](network-webrtc) — STUN/TURN/ICE.
- [`network-tls13-deep`](network-tls13-deep) — 0-RTT, PSK, ECH.

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
