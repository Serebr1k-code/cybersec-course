---
id: cloud-net-connectivity
title: "Модуль: Связность и гибридные мосты"
category: cloud
parent: cloud-network-egress
difficulty: medium
order: 1
tags: [cloud, module, roadmap]
prerequisites: [cloud-network-egress]
useful_for:
- Аудит облачной сети.
- Red team.
- Пентест гибрида.
estimated_minutes: 10
summary: "Site-to-site vpn/direct connect/expressroute, privatelink и vpc peering"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Связность и гибридные мосты»: Site-to-Site VPN/Direct Connect/ExpressRoute, PrivateLink и VPC peering.

- **cloud-vpn-hybrid** — Site-to-Site VPN / Direct Connect / ExpressRoute: гибридные мосты.
- **cloud-privatelink** — PrivateLink / Private Service Connect / Private Endpoint.
- **cloud-vpc-peering** — VPC peering / Transit Gateway / hub-spoke: изоляция и её обход.

## Почему такой порядок

Гибридные соединения соединяют облако с офисом — их изоляция важна для lateral movement.

## Что вы сможете после этапа

- Оценивать маршруты гибридных соединений.
- Искать обход изоляции через peering.

## Квиз

Проверь себя.

```quiz
- question: Что делает VPC peering?
  options:
    - "Соединяет две VPC приватно"
    - "Публикует сайт"
    - "Шифрует диск"
    - "Создаёт ключи"
  answer: 0
  explanation: Peering даёт приватную связность между VPC.
- question: Чем интересен PrivateLink атакующему?
  options:
    - "Публикует сервис без интернета — меняет модель доступа"
    - "Ускоряет DNS"
    - "Отключает логи"
    - "Шифрует трафик"
  answer: 0
  explanation: PrivateLink меняет путь к сервису и модель доверия.
- question: Что такое Direct Connect/ExpressRoute?
  options:
    - "Выделенное приватное соединение с облаком"
    - "Формат файла"
    - "Тип балансировщика"
    - "Схема БД"
  answer: 0
  explanation: Это выделенные каналы в облако.
```

## Где пригодится

- Аудит облачной сети.
- Red team.
- Пентест гибрида.
