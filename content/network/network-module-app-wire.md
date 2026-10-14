---
id: network-module-app-wire
title: "Модуль: прикладные протоколы на проводе — SSH, LDAP, Kerberos, RDP"
category: network
parent: network-quic
difficulty: hard
order: 2
tags: [network, app-protocols, module]
prerequisites: [network-quic]
useful_for:
  - "CTF Network (разбор протоколов)"
  - "Пентест: прикладные сервисы"
  - "Работа: анализ трафика"
estimated_minutes: 50
summary: "Навигационный модуль про «сервисные» протоколы на уровне сообщений: SSH, LDAP, Kerberos и RDP."
---

## Вопрос, с которого всё начинается

SSH, LDAP, Kerberos и RDP — повседневные сервисы. Понимание их «на проводе» нужно и для анализа, и для поиска слабостей.

## Что покрывает

- [`network-ssh-wire`](network-ssh-wire) — KEX, auth, каналы.
- [`network-ldap-wire`](network-ldap-wire) — ASN.1, фильтры.
- [`network-kerberos-asn1`](network-kerberos-asn1) — структура сообщений.
- [`network-rdp-protocol`](network-rdp-protocol) — NLA/CredSSP.

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
