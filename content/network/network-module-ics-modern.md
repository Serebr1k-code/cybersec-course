---
id: network-module-ics-modern
title: "Модуль: Современные шины"
category: network
parent: network-module-ics-deep
difficulty: medium
order: 2
tags: [network, module, roadmap]
prerequisites: [network-module-ics-deep]
useful_for:
- Аудит АСУ ТП.
- Пентест ICS.
- CTF ICS.
estimated_minutes: 10
summary: "Opc ua (security policies, сертификаты) и ethercat (датаграммы, mailbox)"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Современные шины»: OPC UA (security policies, сертификаты) и EtherCAT (датаграммы, mailbox).

- **network-opcua** — OPC UA: бинарный/JSON, security policies и сертификаты.
- **network-ethercat** — EtherCAT: датаграммы, mailbox и мастер-ведомый.

## Почему такой порядок

Современные шины несут больше структуры и криптографии — их разбирают после классики.

## Что вы сможете после этапа

- Разбирать security policies OPC UA.
- Понимать мастер-ведомый обмен EtherCAT.

## Квиз

Проверь себя.

```quiz
- question: Что важно проверить в OPC UA?
  options:
    - "Какой security policy выбран"
    - "Цвет интерфейса"
    - "Размер БД"
    - "Логи"
  answer: 0
  explanation: Слабый policy (None) снимает защиту.
- question: Чем характерен EtherCAT?
  options:
    - "Обмен датаграммами на лету (processing on the fly)"
    - "Шифрованием"
    - "DNS"
    - "СУБД"
  answer: 0
  explanation: EtherCAT обрабатывает кадр по мере прохождения.
- question: Что даёт сертификат в OPC UA?
  options:
    - "Аутентификацию сторон"
    - "Сжатие"
    - "Резервирование"
    - "Логирование"
  answer: 0
  explanation: Сертификаты удостоверяют клиента/сервер.
```

## Где пригодится

- Аудит АСУ ТП.
- Пентест ICS.
- CTF ICS.
