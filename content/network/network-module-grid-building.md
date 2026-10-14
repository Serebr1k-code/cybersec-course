---
id: network-module-grid-building
title: "Модуль: Здания, дороги и модель АСУ ТП"
category: network
parent: network-module-ics-grid
difficulty: medium
order: 2
tags: [network, module, roadmap]
prerequisites: [network-module-ics-grid]
useful_for:
- Аудит АСУ ТП.
- Пентест зданий/транспорта.
- CTF ICS.
estimated_minutes: 10
summary: "Ntcip, bacnet, purdue-модель и системы противоаварийной защиты (sis)"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Здания, дороги и модель АСУ ТП»: NTCIP, BACnet, Purdue-модель и системы противоаварийной защиты (SIS).

- **network-ntcip** — NTCIP: дорожные контроллеры, SNMP-объекты и опасность set.
- **network-bacnet** — BACnet: автоматизация зданий, BBMD и риски.
- **network-ics-purdue** — Purdue-модель: сегментация и зоны/кондуиты.
- **network-ics-safety** — SIS: системы противоаварийной защиты.

## Почему такой порядок

Модель сегментации и безопасность процессов — рамка, в которую укладываются протоколы.

## Что вы сможете после этапа

- Применять Purdue-модель к сегментации.
- Оценивать риски BACnet/NTCIP.

## Квиз

Проверь себя.

```quiz
- question: Что описывает Purdue-модель?
  options:
    - "Уровни сегментации промышленной сети"
    - "Формат кадра"
    - "Тип подписи"
    - "Схему БД"
  answer: 0
  explanation: Purdue делит сеть на уровни и зоны.
- question: Где применяют BACnet?
  options:
    - "В автоматизации зданий"
    - "В энергетике"
    - "В автомобилях"
    - "В DNS"
  answer: 0
  explanation: BACnet — протокол зданий (HVAC, доступ).
- question: Что такое SIS?
  options:
    - "Система противоаварийной защиты"
    - "Формат файла"
    - "Тип шины"
    - "Протокол зарядки"
  answer: 0
  explanation: SIS отключает процесс при опасности.
```

## Где пригодится

- Аудит АСУ ТП.
- Пентест зданий/транспорта.
- CTF ICS.
