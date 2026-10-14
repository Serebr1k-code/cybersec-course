---
id: net-vpn
title: 'VPN в форензике: туннели и что в них видно'
category: forensics
parent: forensics-net-lan
difficulty: hard
order: 4
tags: [network, vpn, ipsec, wireguard, openvpn, forensics]
prerequisites: [forensics-network-deep]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как распознать VPN-трафик, какие протоколы бывают и что можно (и нельзя) извлечь из туннеля.'
lab:
  kind: shell
  title: 'Практика: VPN в форензике'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

В дампе — непонятный UDP-трафик на нестандартный порт. Это VPN? И если да, можно ли
заглянуть внутрь? Ответ зависит от протокола. Разберём, как распознать и что извлечь.

## Наш пример: подозрительный туннель

## Шаг 1: распознаём протокол

```
$ tshark -r capture.pcap -T fields -e ip.proto -e udp.port -e frame.len | head
17	51820	142
17	51820	98
```

Порт `51820` — стандартный для **WireGuard**. Другие маркеры: `1194` (OpenVPN),
`500/4500` (IPsec/IKE), `443` (VPN поверх TLS).

## Шаг 2: WireGuard

WireGuard — минималистичный UDP-протокол. Он не имеет «рукопожатия в открытом виде»:
всё зашифровано с первой секунды.

```
$ tshark -r capture.pcap -Y 'udp.port==51820' -c 4
```

Внутреннее содержимое недоступно без приватного ключа пира. В расследовании факт
туннеля сам по себе — улика: трафик шёл в обход корпоративного контроля.

## Шаг 3: OpenVPN

OpenVPN узнаваем по первым байтам:

```
$ tshark -r capture.pcap -Y 'tcp.port==1194 || udp.port==1194' -c 2
```

При наличии ключа/статического ключа можно расшифровать. Часто в конфиге используется
TLS — тогда нужны ключи сессии.

## Шаг 4: IPsec

IPsec — это IKE (UDP 500/4500) для установки ключей и ESP для данных:

```
$ tshark -r capture.pcap -Y 'isakmp' -T fields -e isakmp.msg.type | head
```

IKE-фаза видна в открытом виде (идентификаторы, алгоритмы). Данные (ESP) зашифрованы.

## Шаг 5: следы на хосте

На самом устройстве остаётся конфигурация VPN:

```
$ ls /etc/wireguard/
wg0.conf
$ grep -i 'Endpoint\|AllowedIPs' /etc/wireguard/wg0.conf
Endpoint = 203.0.113.5:51820
AllowedIPs = 0.0.0.0/0
```

`AllowedIPs = 0.0.0.0/0` означает, что весь трафик уходил в туннель — признак
перенаправления всей сети.

## Что мы теперь знаем

- VPN распознаётся по порту и сигнатуре.
- WireGuard (51820) не отдаёт содержимое без ключа.
- OpenVPN (1194) можно расшифровать при наличии ключей.
- IPsec: IKE виден, ESP зашифрован.
- Конфиги на хосте показывают endpoint и маршруты.

## Если не сработало

- Трафик на 443? Возможно, VPN замаскирован под HTTPS.
- Нужны данные? Ищи ключи на хосте или в памяти.
- Нет дампа? Смотри конфиги VPN и логи демонов.

## Квиз

Проверь себя.

```quiz
- question: Какой порт типичен для WireGuard?
  options:
    - '22'
    - '51820/udp'
    - '443'
    - '53'
  answer: 1
  explanation: 'WireGuard по умолчанию использует UDP 51820.'
- question: Что видно в трафике WireGuard без ключа?
  options:
    - 'весь трафик'
    - 'только факт туннеля (содержимое зашифровано)'
    - 'пароли'
    - 'DNS'
  answer: 1
  explanation: 'WireGuard шифрует всё с первого пакета; виден лишь сам туннель.'
- question: Что видно в IPsec-трафике?
  options:
    - 'ничего'
    - 'IKE-фаза (открыто), ESP-данные (зашифрованы)'
    - 'только пароли'
    - 'только DNS'
  answer: 1
  explanation: 'IKE устанавливает ключи открыто, данные в ESP защищены.'
- question: Что означает AllowedIPs = 0.0.0.0/0 в WireGuard?
  options:
    - 'ничего'
    - 'весь трафик идёт через туннель'
    - 'только локальная сеть'
    - 'туннель выключен'
  answer: 1
  explanation: 'Это full-tunnel: все маршруты через VPN.'
```
