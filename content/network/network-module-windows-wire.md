---
id: network-module-windows-wire
title: "Модуль: Windows-протоколы — SMB2/3, signing, MSRPC, EPM"
category: network
parent: network-ntlm-relay
difficulty: hard
order: 2
tags: [network, app-protocols, module]
prerequisites: [network-ntlm-relay]
useful_for:
  - "CTF Network (разбор протоколов)"
  - "Пентест: прикладные сервисы"
  - "Работа: анализ трафика"
estimated_minutes: 50
summary: "Навигационный модуль про «провод» Windows-протоколов: SMB2/3, подпись/шифрование, MS-RPC и endpoint mapper."
---

## Вопрос, с которого всё начинается

Windows-сети говорят на SMB, MS-RPC и DCERPC. Понимание их сообщений — основа анализа и атак (relay, opnum).

## Что покрывает

- [`network-smb2-deep`](network-smb2-deep) — диалекты, сжатие.
- [`network-smb-signing`](network-smb-signing) — подпись/шифрование, downgrade.
- [`network-msrpc`](network-msrpc) — DCERPC/opnum.
- [`network-dcerpc-epm`](network-dcerpc-epm) — endpoint mapper (135).

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
