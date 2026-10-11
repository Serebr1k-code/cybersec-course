---
id: network-vpn
title: "VPN: WireGuard, IPsec и OpenVPN"
category: network
parent: network-intro
difficulty: easy
order: 3
tags: [network, vpn, wireguard, ipsec, openvpn]
prerequisites: [network-intro]
useful_for:
  - "CTF: Network"
  - "Пентест: аудит VPN-инфраструктур"
  - "Работа: администрирование защищённых каналов"
estimated_minutes: 12
summary: "Этап про VPN: анализ WireGuard/IPsec и OpenVPN, их handshake и типовые ошибки."
---

Этот урок — **этап-навигатор** в ветке. Он короткий: его задача — объяснить, что вы будете изучать на этом этапе, почему темы идут именно в таком порядке и что вы сможете делать после прохождения.

## О чём этот этап

Этот этап про современные защищённые каналы. Вы разберёте, как устроены WireGuard и IPsec, чем отличается их модель безопасности, и детально изучите OpenVPN — TLS-handshake, режимы и типичные ошибки конфигурации, которые превращают VPN в точку входа.

## Что вы освоите

- WireGuard и IPsec: анализ современных VPN на уровне протокола
- OpenVPN: TLS-handshake, режимы и типовые ошибки
- Понимать, какие параметры VPN критичны для безопасности

## Как проходить

Сначала WireGuard/IPsec как более простой для понимания протокол, затем OpenVPN с его TLS-инфраструктурой. Поднимайте VPN в лаборатории и снимайте handshake в Wireshark.

## Квиз

```quiz
- question: "Чем WireGuard отличается от IPsec по объёму кода?"
  options:
    - "WireGuard значительно компактнее"
    - "IPsec компактнее"
    - "Они одинаковы"
    - "WireGuard не шифрует трафик"
  answer: 0
  explanation: "WireGuard спроектирован минималистичным, что уменьшает поверхность атаки."
- question: "Что критично проверить в конфигурации OpenVPN?"
  options:
    - "Стойкость TLS-параметров и отзыв сертификатов"
    - "Цвет интерфейса клиента"
    - "Число процессоров сервера"
    - "Размер логотипа"
  answer: 0
  explanation: "Слабый TLS (старые шифры, отсутствие CRL) — типичная уязвимость OpenVPN."
- question: "Какой инструмент снимет VPN-handshake для анализа?"
  options:
    - "Wireshark"
    - "nmap"
    - "gobuster"
    - "hashcat"
  answer: 0
  explanation: "Wireshark позволяет захватить и разобрать пакеты handshake."
```

## Где пригодится

- **CTF:** Network
- **Пентест:** аудит VPN-инфраструктур
- **Работа:** администрирование защищённых каналов
