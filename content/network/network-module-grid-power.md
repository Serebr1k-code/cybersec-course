---
id: network-module-grid-power
title: "Модуль: Энергетика и подстанции"
category: network
parent: network-module-ics-grid
difficulty: medium
order: 1
tags: [network, module, roadmap]
prerequisites: [network-module-ics-grid]
useful_for:
- Аудит АСУ ТП.
- Пентест энергетики.
- CTF ICS.
estimated_minutes: 10
summary: "Iec 61850 (mms/goose/sv), iec 60870-5-104 и hart-ip"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Энергетика и подстанции»: IEC 61850 (MMS/GOOSE/SV), IEC 60870-5-104 и HART-IP.

- **network-iec61850** — IEC 61850: MMS, GOOSE и SV в подстанциях.
- **network-iec104** — IEC 60870-5-104: телемеханика и ASDU.
- **network-hart-ip** — HART-IP: процессные приборы и диагностика.

## Почему такой порядок

Энергетика — критичная инфраструктура; её протоколы разбираются первыми в ветке АСУ ТП.

## Что вы сможете после этапа

- Разбирать GOOSE/SV и ASDU.
- Оценивать риски подстанций и приборов.

## Квиз

Проверь себя.

```quiz
- question: Что передаёт GOOSE в IEC 61850?
  options:
    - "Быстрые сообщения о событиях"
    - "Файлы прошивки"
    - "Пароли"
    - "DNS-запросы"
  answer: 0
  explanation: GOOSE публикует события реального времени.
- question: Чем характерен IEC 60870-5-104?
  options:
    - "Телемеханика поверх TCP (ASDU)"
    - "Протокол зданий"
    - "Формат файла"
    - "Протокол зарядки"
  answer: 0
  explanation: 104 переносит телеметрию через ASDU.
- question: Где применяют HART-IP?
  options:
    - "В процессных приборах"
    - "В браузерах"
    - "В СУБД"
    - "В DNS"
  answer: 0
  explanation: HART-IP — протокол процессной автоматизации.
```

## Где пригодится

- Аудит АСУ ТП.
- Пентест энергетики.
- CTF ICS.
