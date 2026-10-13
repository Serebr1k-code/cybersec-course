---
id: crypto-real-world
title: "Криптография в реальных протоколах: TLS, Wi-Fi, диски и Kerberos"
category: crypto
parent: crypto-applied-protocols
difficulty: medium
order: 2
tags: [crypto, roadmap, tls, wifi, wpa, luks, bitlocker, kerberos, protocols, real-world]
prerequisites: [crypto-applied-protocols]
useful_for:
  - "Планировать изучение криптографии реальных протоколов"
  - "Понимать, где искать уязвимости в TLS, WPA, дисковом шифровании и Kerberos"
estimated_minutes: 10
summary: "Модуль прикладной криптографии реальных протоколов: атаки на TLS (downgrade, Heartbleed, POODLE, отпечатки), Wi-Fi (WPA2/WPA3, PMKID, KRACK), дисковое шифрование (LUKS/BitLocker/VeraCrypt) и криптография Kerberos."
lab:
  kind: shell
  title: 'Практика: PMKID-взлом WPA2 (hashcat)'
  toolset: [core, hashcat, python]
  workdir: /home/student/task
  files: [task.md, notes.txt, pmkid.hc22000, wordlist.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`cat pmkid.hc22000` — формат hashcat `WPA*01*…`.'
    - 'Это режим `-m 22000` (PMKID), подбирается офлайн.'
    - 'Запусти: `hashcat -m 22000 pmkid.hc22000 wordlist.txt`.'
    - 'Запиши флаг: `hashcat -m 22000 pmkid.hc22000 wordlist.txt | grep nto > found.txt`.'
---

`crypto-applied-protocols` описывает протоколы «на бумаге»: commitment, ZK-доказательства, Shamir. Этот модуль спускается на землю: как те же примитивы собраны в реальных системах, которые мы видим в пентесте каждый день — TLS, WPA2/WPA3, дисковое шифрование и Kerberos. Здесь важны не столько формулы, сколько знание, **какие параметры и режимы выбирают реальные стеки** и где исторически ломались.

## Что покрывает этап

- **crypto-tls-attacks** — TLS: downgrade-атаки, Heartbleed, POODLE/BEAST/CRIME, renegotiation, отпечатки JA3/JA4, pinning, атаки на версии и наборы шифров.
- **crypto-wifi-wpa** — Wi-Fi: WPA2 4-way handshake, PMKID, KRACK, WPA3 SAE/Dragonfly, evil-twin и перехват, инструменты hcxdumptool/hcxtools/hashcat.
- **crypto-disk-encryption** — LUKS, BitLocker, VeraCrypt: структура заголовков, режимы (XTS/CBC), извлечение и подбор пароля, аппаратные ключи.
- **crypto-kerberos-crypto** — Kerberos: типы шифрования, Kerberoasting и AS-REP roasting, PAC, слабые тикеты и их офлайн-взлом.

## Почему такой порядок

Сначала TLS — самый массовый протокол и источник исторических атак, на которых выросли целые классы уязвимостей. Затем Wi-Fi — протокол с уникальной моделью (радио, handshake, PSK) и своими инструментами. Затем дисковое шифрование — сценарий, где ключ защищает данные «at rest». Kerberos замыкает модуль как протокол аутентификации в корпоративной среде, тесно связанный с AD.

## Что вы сможете после этапа

- Оценивать конфигурацию TLS и использовать известные атаки/отпечатки.
- Захватывать и ломать WPA2/WPA3-рукопожатия и PMKID.
- Разбирать заголовки LUKS/BitLocker/VeraCrypt и подбирать пароли.
- Проводить Kerberoasting/AS-REP roasting и взламывать тикеты.

## Квиз

```quiz
- question: "Что такое PMKID в контексте атак на WPA2?"
  options:
    - "Значение, из которого можно вывести PSK без полного 4-way handshake"
    - "Тип шифрования"
    - "Пароль точки доступа"
    - "MAC-адрес клиента"
  answer: 0
  explanation: "PMKID вычисляется из PMK и позволяет атаковать без перехвата полного handshake — достаточно запросить его у AP."
- question: "Какой режим чаще всего используется для шифрования дисков в LUKS?"
  options:
    - "ECB"
    - "XTS"
    - "OFB"
    - "нет режима"
  answer: 1
  explanation: "XTS — стандартный tweakable-режим для секторного шифрования дисков; номер сектора служит tweak."
- question: "Что запрашивает атака Kerberoasting?"
  options:
    - "TGS-тикет для сервисной учётной записи с известным SPN"
    - "AS-REP для любого пользователя"
    - "Приватный ключ KDC"
    - "PAC-подпись"
  answer: 0
  explanation: "Kerberoasting запрашивает TGS для SPN и ломает его офлайн по паролю сервисной учётки."
```

## Где пригодится

- **CTF:** задачи на TLS-атаки, WPA-рукопожатия, LUKS-заголовки и Kerberos.
- **Bug bounty:** оценка TLS-конфигураций и отпечатков, тестирование аутентификации.
- **Пентест:** взлом Wi-Fi, дисковых образов, Kerberos-тикетов в AD-среде.
- **Работа:** аудит TLS-терминаторов, VPN, дискового шифрования и AD.
