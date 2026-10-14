---
id: network-module-broker-wire
title: "Модуль: Брокеры и messaging"
category: network
parent: network-module-msg-wire
difficulty: medium
order: 1
tags: [network, module, roadmap]
prerequisites: [network-module-msg-wire]
useful_for:
- Пентест сервисов.
- CTF Network.
- Анализ протоколов.
estimated_minutes: 10
summary: "Resp/redis, memcached, stomp и xmpp"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Брокеры и messaging»: RESP/Redis, Memcached, STOMP и XMPP.

- **network-redis-wire** — RESP / Redis wire: протокол и открытый доступ.
- **network-memcached** — Memcached: протокол и амплификация.
- **network-stomp** — STOMP: текстовый messaging, подписка на всё и инъекция.
- **network-xmpp** — XMPP: XML-станзы, федерация и перечисление JID.

## Почему такой порядок

Текстовые протоколы брокеров просты для ручного разбора и потому идут первыми.

## Что вы сможете после этапа

- Работать с RESP и Memcached.
- Искать подписку-на-всё в STOMP/XMPP.

## Квиз

Проверь себя.

```quiz
- question: Чем опасен открытый Redis?
  options:
    - "Записью данных и потенциальным RCE"
    - "Ускорением"
    - "Шифрованием"
    - "Логированием"
  answer: 0
  explanation: Redis без пароля даёт доступ к данным и конфигу.
- question: Чем опасен Memcached в сети?
  options:
    - "Амплификацией трафика"
    - "Шифрованием"
    - "Сжатием"
    - "Логированием"
  answer: 0
  explanation: Memcached используют для amplification-атак.
- question: Что даёт STOMP-брокер?
  options:
    - "Простую текстовую подписку на очереди/топики"
    - "Шифрование"
    - "DNS"
    - "Резервирование"
  answer: 0
  explanation: STOMP — текстовый messaging-протокол.
```

## Где пригодится

- Пентест сервисов.
- CTF Network.
- Анализ протоколов.
