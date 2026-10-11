---
id: network-module-vpn
title: "VPN глубоко: IPsec, TLS-VPN и туннели удалённого доступа"
category: network
parent: network-vpn
difficulty: easy
order: 1
tags: [network, vpn, ipsec, ike, ssl-vpn, wireguard, openvpn]
prerequisites: [network-vpn, network-openvpn]
useful_for:
  - "CTF Network (VPN-протоколы)"
  - "Пентест: анализ VPN-трафика и мисконфигураций"
  - "Работа (SOC): детект VPN-аномалий"
estimated_minutes: 60
summary: "Модуль по VPN: чем отличаются IPsec, WireGuard, OpenVPN, SSTP и L2TP, что видно на проводе, какие мисконфигурации опасны и какие атаки возможны на VPN-инфраструктуру."
---

VPN соединяет сети или пользователей через недоверенную среду, шифруя трафик. Но «VPN» — это целое семейство технологий: от классического IPsec до современного WireGuard. Каждая имеет свою модель аутентификации, свой формат на проводе и свой набор слабостей. Этот модуль — база для [`network-ipsec-ike`](network-ipsec-ike) и [`network-sstp-l2tp`](network-sstp-l2tp), опирается на [`network-vpn`](network-vpn), [`network-openvpn`](network-openvpn) и [`network-wireguard`](network-wireguard).

## Зачем отдельный модуль по VPN

VPN — точка входа в корпоративную сеть. Поэтому её так часто атакуют:

- **слабые credentials** — VPN-логин часто равен доменному;
- **устаревшие протоколы** — PPTP/L2TP/IKEv1 с известными слабостями;
- **мисконфигурации** — split-tunnel, отсутствие MFA, широкий доступ;
- **анализ трафика** — даже без расшифровки видно версии, режимы, идентификаторы;
- **экспозиция** — открытый IKE/OpenVPN-порт раскрывает вендора и политику.

Без понимания формата VPN-протоколов невозможно ни корректно атаковать, ни защищать.

## Виды VPN и их отличия

| Тип | Пример | Уровень | Транспорт |
|---|---|---|---|
| IPsec | IKEv2, strongSwan | L3 | ESP/AH (proto 50/51) |
| TLS-VPN | OpenVPN, SSTP | L3/L4 | TCP/UDP+TLS |
| Современный | WireGuard | L3 | UDP |
| PPP-based | PPTP, L2TP | L2 | GRE/UDP |
| Web-VPN | clientless SSL | L7 | HTTPS |

IPsec и TLS-VPN — два больших семейства; PPP-based считаются устаревшими.

## IPsec: архитектура

IPsec состоит из:

- **IKE** — согласование ключей и параметров (UDP 500, NAT-T 4500);
- **ESP** — шифрование и аутентификация полезной нагрузки (proto 50);
- **AH** — только аутентификация заголовка (proto 51, редко);
- **SA** (Security Association) — однонаправленный «канал» с параметрами.

Два режима: **transport** (защищает только payload) и **tunnel** (защищает весь IP-пакет, для site-to-site).

## TLS-based VPN

OpenVPN инкапсулирует свои пакеты в TLS поверх TCP/UDP; SSTP — в HTTPS поверх TCP/443. Оба используют сертификаты, часто с паролем. WireGuard не использует TLS: у него свой протокол с фиксированными примитивами (Curve25519, ChaCha20-Poly1305) и статическими публичными ключами.

## PPP-based (устаревшие)

PPTP использует MS-CHAPv2 — ломается перебором (инструмент `chapcrack`/`asleap`). L2TP сам по себе не шифрует; его часто комбинируют с IPsec (L2TP/IPsec). Чистый L2TP/PPTP — красный флаг.

## Что видно на проводе

Даже без расшифровки видно:

- **IPsec** — proto 50/51, UDP 500/4500, IKE-идентификаторы (vendor ID, version);
- **OpenVPN** — свой opcode, TLS-хендшейк, сертификаты (если не tls-auth);
- **WireGuard** — UDP, фиксированный формат, но невидимые handshake-типы;
- **SSTP** — HTTPS на 443, похож на обычный TLS.

```bash
# Захватить VPN-трафик
sudo tcpdump -i eth0 -nn 'udp port 500 or udp port 4500 or ip proto 50 or udp port 1194 or udp port 51820'
# Определить версию IKE
sudo nmap -sU -p 500 --script ike-version 10.0.0.1
```

## Атаки на VPN

- **Перебор credentials** (VPN-логины, MS-CHAPv2);
- **IKE-агрессивный режим** — утечка идентификатора/хэша (IKEv1);
- **Downgrade** — заставить выбрать слабые параметры;
- **Split-tunnel abuse** — трафик жертвы частично не шифруется;
- **Ошибки в конфиге** — разрешён весь трафик, нет MFA;
- **Анализ метаданных** — кто, когда, сколько.

```bash
# Перебор OpenVPN (лаборатория)
# openvpn --config client.ovpn --auth-user-pass creds.txt
# IKE-скан
sudo ike-scan -M 10.0.0.1
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `ike-scan` | обнаружение и fingerprint IKE |
| `nmap ike-version` | версия IKE/IPsec |
| `strongswan` | реализация IPsec/IKE |
| `openvpn`/`wg` | клиенты VPN |
| `tcpdump`/`tshark` | захват и разбор |
| `asleap`/`chapcrack` | атаки на MS-CHAPv2 |

```bash
# tshark: разбор IKE
tshark -r cap.pcap -Y 'isakmp' -T fields -e isakmp.version -e isakmp.exchangetype | head
```

## Типовые ошибки

- **Использовать PPTP/L2TP без IPsec** — слабая аутентификация.
- **Отключать MFA** — перебор логина/пароля.
- **Оставлять IKEv1 aggressive mode** — утечка хэшей.
- **Split-tunnel по умолчанию** — часть трафика идёт мимо VPN.
- **Не обновлять сертификаты** — истёкшие/отозванные принимаются.
- **Открывать управление VPN наружу** — панель/API.
- **Не логировать подключения** — аномалии невидимы.

## Что дальше / решение

Пройдите [`network-ipsec-ike`](network-ipsec-ike) и [`network-sstp-l2tp`](network-sstp-l2tp). Для конкретных реализаций — [`network-openvpn`](network-openvpn) и [`network-wireguard`](network-wireguard).

## IKE и IPsec на практике

```bash
# 1. Обнаружить IPsec-шлюз
sudo ike-scan -M 10.0.0.1
# 2. Определить версию и вендор
sudo nmap -sU -p 500,4500 --script ike-version 10.0.0.1
# 3. Захватить согласование
sudo tcpdump -i eth0 -nn -w vpn.pcap 'udp port 500 or udp port 4500 or ip proto 50'
# 4. Разобрать обмен в tshark
tshark -r vpn.pcap -Y 'isakmp' -T fields -e isakmp.version -e isakmp.exchangetype | head
# 5. Найти инкапсулированный ESP (NAT-T)
tshark -r vpn.pcap -Y 'udp.port==4500' -T fields -e ip.src | head
```

Даже без ключей видно: версию IKE, тип обмена, идентификаторы (в aggressive), выбранные алгоритмы. Это метаданные, достаточные для выбора вектора.

## Сравнение VPN-протоколов

| Протокол | Транспорт | Шифрование | Порт/прото |
|---|---|---|---|
| IPsec/IKEv2 | UDP | да (ESP) | 500/4500, 50 |
| WireGuard | UDP | да | 51820 |
| OpenVPN | TCP/UDP | да (TLS) | 1194 |
| SSTP | TCP | да (TLS) | 443 |
| L2TP/IPsec | UDP | да (IPsec) | 1701 + 500 |
| PPTP | GRE | слабое | 1723, 47 |

## Чек-лист аудита VPN

1. Какие VPN-протоколы и порты открыты наружу?
2. Версия IKE — не осталось ли IKEv1 aggressive?
3. Какие алгоритмы разрешены (нет ли DES/3DES/MD5)?
4. Обязательна ли **MFA**?
5. Настроен ли **split-tunnel** (и не утекает ли трафик)?
6. Логируются ли подключения и ошибки?
7. Обновляются ли сертификаты и ключи?

```bash
# Снимок: открытые VPN-порты
sudo nmap -sU -p 500,4500,1194,51820,1701 10.0.0.1
sudo nmap -sS -p 443,1723 10.0.0.1
```

Практический вывод: VPN защищает только при правильной конфигурации. Устаревшие протоколы (PPTP, IKEv1 aggressive, L2TP без IPsec) и отключённая MFA сводят пользу на нет.

## Практический итог по VPN

Правильная стратегия аудита VPN:

1. **Инвентаризация** — какие VPN-порты/протоколы открыты.
2. **Fingerprint** — версия IKE, вендор, режимы.
3. **Проверка legacy** — PPTP, IKEv1 aggressive, DES/3DES.
4. **Аутентификация** — PSK/сертификаты, MFA, перебор.
5. **Конфигурация** — split-tunnel, маршруты, политики.
6. **Мониторинг** — логи подключений, аномалии.

```bash
# Быстрый обзор VPN-поверхности
sudo nmap -sU -p 500,4500,1194,51820,1701 10.0.0.1
sudo nmap -sS -p 443,1723 10.0.0.1
```

Каждый шаг даёт конкретный вывод: что открыто, насколько современно, что можно перебрать, куда утекает трафик. Из этих шести шагов складывается полная картина VPN-безопасности периметра.

## Квиз

```quiz
- question: "Какой протокол IPsec обеспечивает шифрование полезной нагрузки?"
  options:
    - "ESP (proto 50)"
    - "AH (proto 51)"
    - "IKE (UDP 500)"
    - "GRE"
  answer: 0
  explanation: "ESP шифрует и аутентифицирует payload; AH только аутентифицирует."
- question: "Какой порт использует IKE для согласования?"
  options:
    - "UDP 500 (и 4500 для NAT-T)"
    - "TCP 443"
    - "UDP 1194"
    - "UDP 51820"
  answer: 0
  explanation: "IKE — UDP 500; NAT-T — 4500."
- question: "Чем опасен PPTP?"
  options:
    - "MS-CHAPv2 ломается перебором"
    - "Он шифрует слишком сильно"
    - "Он требует сертификат"
    - "Он использует IPv6"
  answer: 0
  explanation: "MS-CHAPv2 уязвим к захвату и офлайн-перебору."
- question: "Что такое split-tunnel?"
  options:
    - "Часть трафика идёт мимо VPN"
    - "Двойное шифрование"
    - "Два сервера VPN"
    - "Разделение ключей"
  answer: 0
  explanation: "Только часть трафика уходит в туннель — риск утечки."
- question: "Что видно на проводе у IPsec без расшифровки?"
  options:
    - "proto 50/51 и UDP 500/4500, версии IKE"
    - "Пароли в открытом виде"
    - "Полный HTTP-трафик"
    - "MAC-адреса клиентов"
  answer: 0
  explanation: "Метаданные и параметры IKE видны, содержимое — нет."
```

## Где пригодится

- **CTF:** задачи с VPN-протоколами и дампами.
- **Пентест:** анализ VPN-инфраструктуры, перебор, мисконфиги.
- **SOC:** детект аномальных VPN-подключений.
- **Инженерия:** выбор и настройка VPN, отказ от устаревших.
