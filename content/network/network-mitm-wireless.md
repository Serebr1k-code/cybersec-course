---
id: network-mitm-wireless
title: "MITM и беспроводные сети"
category: network
parent: network-mitm
difficulty: easy
order: 1
tags: [network, mitm, wifi, dhcp, ntlm]
prerequisites: [network-mitm]
useful_for:
  - "CTF: Network"
  - "Red team: внутренний периметр"
  - "Работа: защита беспроводных и AD-сетей"
estimated_minutes: 12
summary: "Этап MITM: Wi-Fi (WPA2/WPA3, evil twin), rogue DHCP и NTLM relay."
---

Этот урок — **этап-навигатор** в ветке. Он короткий: его задача — объяснить, что вы будете изучать на этом этапе, почему темы идут именно в таком порядке и что вы сможете делать после прохождения.

## О чём этот этап

Заключительный этап MITM-ветки про перехват в реальных условиях: беспроводные сети (WPA2/WPA3, PMKID, evil twin), подставной DHCP-сервер и релей аутентификации NTLM с коэрсией.

## Что вы освоите

- 802.11 Wi-Fi: WPA2/WPA3, handshake, PMKID и evil twin
- DHCP: rogue-сервер и атаки на конфигурацию
- NTLM relay и коэрсия

## Как проходить

Начните с беспроводной части (нужен Wi-Fi-адаптер с monitor mode), затем rogue DHCP и NTLM relay. Для relay потребуется среда Active Directory в лаборатории.

## Квиз

```quiz
- question: "Что перехватывают для офлайн-подбора пароля WPA2?"
  options:
    - "4-way handshake или PMKID"
    - "ARP-таблицу"
    - "DHCP-lease"
    - "TLS-сертификат"
  answer: 0
  explanation: "Handshake/PMKID содержат материал для офлайн-подбора PSK."
- question: "Чем опасен rogue DHCP-сервер?"
  options:
    - "Выдаёт жертве свой шлюз/DNS для MITM"
    - "Ускоряет сеть"
    - "Шифрует трафик"
    - "Меняет SSID"
  answer: 0
  explanation: "Подставной DHCP подменяет шлюз и DNS, направляя трафик через атакующего."
- question: "Что нужно для NTLM relay?"
  options:
    - "Перехваченная аутентификация и цель, принимающая её"
    - "Пароль в открытом виде"
    - "Сертификат домена"
    - "MAC-адрес жертвы"
  answer: 0
  explanation: "Relay переиспользует перехваченную NTLM-аутентификацию против другой службы."
```

## Где пригодится

- **CTF:** Network
- **Red team:** внутренний периметр
- **Работа:** защита беспроводных и AD-сетей
