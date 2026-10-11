---
id: network-sstp-l2tp
title: "SSTP, L2TP и PPTP: PPP-based VPN и их слабости"
category: network
parent: network-module-vpn
difficulty: medium
order: 2
tags: [network, sstp, l2tp, pptp, ppp, vpn, ms-chap]
prerequisites: [network-module-vpn, network-pppoe]
useful_for:
  - "CTF Network (PPP/VPN)"
  - "Пентест: анализ устаревших VPN, MS-CHAPv2"
  - "Работа (SOC): детект слабых VPN"
estimated_minutes: 55
summary: "L2TP, SSTP и PPTP: как PPP инкапсулируется в разные транспорты, чем опасен MS-CHAPv2, что видно на проводе и почему PPTP/L2TP без IPsec считаются устаревшими."
---

PPP-based VPN выросли из дозвона: они используют **PPP** (Point-to-Point Protocol) для аутентификации и передают его через разные транспорты — GRE (PPTP), UDP (L2TP), HTTPS (SSTP). Общая слабость — аутентификация (MS-CHAPv2) и отсутствие шифрования у части протоколов. Урок продолжает [`network-module-vpn`](network-module-vpn) и опирается на [`network-pppoe`](network-pppoe).

## PPP: общая основа

**PPP** обеспечивает установление канала, аутентификацию (PAP/CHAP/MS-CHAPv2) и назначение адресов (через IPCP). Он не шифрует. Все PPP-based VPN инкапсулируют PPP-кадры в свой транспорт.

## PPTP: GRE и MS-CHAPv2

**PPTP** (устаревший) передаёт PPP в **GRE** (proto 47) и управляет соединением по TCP/1723. Аутентификация — MS-CHAPv2, которая **ломается**: перехваченное рукопожатие позволяет офлайн-перебор (asleap, chapcrack).

```bash
# Захватить PPTP (GRE)
sudo tcpdump -i eth0 -nn 'tcp port 1723 or ip proto 47'
# Перебор MS-CHAPv2 (лаборатория)
# asleap -r capture.pcap -W words.txt
# chapcrack -i capture.pcap
```

## L2TP: PPP в UDP

**L2TP** инкапсулирует PPP в **UDP/1701**. Сам по себе не шифрует — поэтому на практике используют **L2TP/IPsec** (IPsec защищает L2TP). Чистый L2TP = аутентификация без шифрования.

```bash
# Захватить L2TP
sudo tcpdump -i eth0 -nn 'udp port 1701'
tshark -r cap.pcap -Y 'l2tp' -T fields -e l2tp.type | sort | uniq -c
```

## SSTP: PPP в HTTPS

**SSTP** (Secure Socket Tunneling Protocol, Microsoft) инкапсулирует PPP в **HTTPS (TCP/443)**. Это делает его NAT-friendly и «невидимым»: снаружи это обычный TLS. Шифрование обеспечивает TLS, аутентификация — внутри.

```bash
# SSTP выглядит как HTTPS на 443
sudo tcpdump -i eth0 -nn 'tcp port 443'
# Отличить SSTP от обычного TLS сложно без DPI по SNI/поведению
```

## Сравнение

| Протокол | Транспорт | Шифрование | Аутентификация | Статус |
|---|---|---|---|---|
| PPTP | GRE + TCP/1723 | слабое (MPPE) | MS-CHAPv2 | устарел |
| L2TP | UDP/1701 | нет (нужен IPsec) | PPP (CHAP) | только с IPsec |
| L2TP/IPsec | UDP/1701 + IPsec | да | PPP + PSK/серт | приемлемо |
| SSTP | TCP/443 | TLS | PPP | ок, но проприетарный |
| IKEv2 | UDP 500/4500 | IPsec | серт/EAP | рекомендуется |

## Что видно на проводе

- **PPTP** — TCP 1723 и GRE; рукопожатие MS-CHAPv2 в открытом виде;
- **L2TP** — UDP 1701, PPP-кадры; без IPsec — содержимое видно;
- **SSTP** — HTTPS/443, нужен DPI для различения;
- **PPP** — имена пользователей, хэши, IPCP-параметры.

```bash
# Ищем признаки PPP/CHAP
tshark -r cap.pcap -Y 'ppp' -V | grep -iE "chap|user|protocol" | head
```

## Атаки

- **Перебор MS-CHAPv2** — из захваченного рукопожатия (PPTP);
- **Отсутствие шифрования L2TP** — перехват содержимого;
- **Credentials по PPP** — утечка логина;
- **Downgrade** — заставить выбрать слабую аутентификацию;
- **MITM на GRE** — при отсутствии IPsec.

```bash
# MS-CHAPv2: извлечь challenge/response и перебрать
# asleap -r pptp.pcap -W rockyou.txt
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `tcpdump`/`tshark` | захват PPTP/L2TP/SSTP |
| `asleap` | атака на MS-CHAPv2 |
| `chapcrack` | разбор MS-CHAPv2 |
| `pppd` | PPP-демон (Linux) |
| `strongswan` | IPsec для L2TP/IPsec |
| `xl2tpd` | L2TP-сервер |

```bash
# Поднять L2TP/IPsec (lab)
sudo ipsec up L2TP-PSK
sudo xl2tpd -D
```

## Защита

| Мера | Против чего |
|---|---|
| Отказаться от PPTP | MS-CHAPv2-перебор |
| L2TP только с IPsec | перехват содержимого |
| Сильная аутентификация (EAP/серт) | перебор credentials |
| MFA | компрометация пароля |
| Предпочитать IKEv2/WireGuard | слабости PPP-based |
| Мониторинг GRE/1701/1723 | аномалии |

## Частые ошибки

- **Использовать PPTP** — небезопасно по определению.
- **L2TP без IPsec** — нет шифрования.
- **Считать SSTP «просто HTTPS»** — нужен DPI.
- **Забывать про PPP-логи** — утечка имён.
- **Разрешать PAP/CHAP** — слабая аутентификация.
- **Игнорировать GRE** — proto 47 часто не фильтруется.
- **Не логировать подключения** — атаки невидимы.

## Что дальше / решение

После PPP-based VPN вернитесь к [`network-module-vpn`](network-module-vpn) и сравните с [`network-wireguard`](network-wireguard). Для IPsec — [`network-ipsec-ike`](network-ipsec-ike).

## Практика: разбор PPTP и L2TP

```bash
# PPTP: управление по TCP/1723, данные в GRE (proto 47)
sudo tcpdump -i eth0 -nn -w pptp.pcap 'tcp port 1723 or ip proto 47'
# L2TP: UDP/1701
sudo tcpdump -i eth0 -nn -w l2tp.pcap 'udp port 1701'
# Разобрать PPP-аутентификацию
tshark -r pptp.pcap -Y 'ppp' -V | grep -iE "chap|user|protocol" | head -20
# Извлечь MS-CHAPv2 challenge/response для перебора
# chapcrack -i pptp.pcap
# asleap -r pptp.pcap -W words.txt
```

MS-CHAPv2 использует DES-шифрование challenge, что делает офлайн-перебор тривиальным при слабом пароле.

## Сравнение с современными VPN

| Свойство | PPTP | L2TP | SSTP | IKEv2 | WireGuard |
|---|---|---|---|---|---|
| Шифрование | слабое | нет | TLS | IPsec | ChaCha20 |
| Аутентификация | MS-CHAPv2 | PPP | PPP+TLS | серт/EAP | ключи |
| NAT-friendly | частично | да | да | да (NAT-T) | да |
| Статус | устарел | с IPsec | ок | рекомендуется | рекомендуется |
| Сложность | низкая | средняя | средняя | высокая | низкая |

## Чек-лист PPP-based VPN

1. Остался ли где-то **PPTP** (1723 + GRE)?
2. Используется ли **L2TP без IPsec** (нет шифрования)?
3. Как аутентифицируются пользователи (**PAP/CHAP/MS-CHAPv2**)?
4. Есть ли **MFA**?
5. Логируются ли PPP-подключения и ошибки?
6. Фильтруется ли **GRE (proto 47)** на периметре?
7. Планируется ли миграция на **IKEv2/WireGuard**?

```bash
# Быстрый скан устаревших VPN-портов
sudo nmap -sS -p 1723 10.0.0.1
sudo nmap -sU -p 1701 10.0.0.1
```

Вывод: PPTP нужно выключать безусловно; L2TP — только в связке с IPsec; SSTP допустим, но уступает IKEv2/WireGuard по современности. MS-CHAPv2 — красный флаг в любой конфигурации.

## Итог по PPP-based VPN

PPP-based VPN — наследие дозвона. Их общая проблема: **PPP-аутентификация** и частое отсутствие шифрования.

- **PPTP** — выключать: MS-CHAPv2 ломается.
- **L2TP** — только с IPsec.
- **SSTP** — допустим, но проприетарный.
- **Современный выбор** — IKEv2 или WireGuard.

```bash
# Проверить legacy-порты
sudo nmap -sS -p 1723 10.0.0.1
sudo nmap -sU -p 1701 10.0.0.1
# Убедиться, что L2TP защищён IPsec
sudo ike-scan -M 10.0.0.1
```

Практический вывод: если видите PPTP — это гарантированный вектор; L2TP без IPsec — открытый текст; SSTP — приемлемо. Миграция на IKEv2/WireGuard устраняет класс проблем целиком.

## Квиз

```quiz
- question: "Чем опасен PPTP?"
  options:
    - "MS-CHAPv2 ломается офлайн-перебором"
    - "Он слишком медленный"
    - "Он требует сертификат"
    - "Он использует IPv6"
  answer: 0
  explanation: "Захваченное рукопожатие позволяет перебрать пароль."
- question: "Какой порт использует L2TP?"
  options:
    - "UDP 1701"
    - "TCP 1723"
    - "UDP 500"
    - "TCP 443"
  answer: 0
  explanation: "L2TP — UDP 1701."
- question: "Что обеспечивает шифрование в L2TP/IPsec?"
  options:
    - "IPsec"
    - "Сам L2TP"
    - "PPP"
    - "GRE"
  answer: 0
  explanation: "L2TP не шифрует; защиту даёт IPsec."
- question: "Во что инкапсулирует PPP протокол SSTP?"
  options:
    - "В HTTPS (TCP/443)"
    - "В GRE"
    - "В UDP/1701"
    - "В ESP"
  answer: 0
  explanation: "SSTP несёт PPP внутри HTTPS."
- question: "Какая защита против атак на PPP-аутентификацию?"
  options:
    - "Отказ от PPTP, EAP/сертификаты, MFA"
    - "Включение GRE"
    - "Использование PAP"
    - "Отключение TLS"
  answer: 0
  explanation: "Сильная аутентификация и отказ от MS-CHAPv2 закрывают вектор."
```

## Где пригодится

- **CTF:** задачи с PPTP/L2TP и MS-CHAPv2.
- **Пентест:** анализ устаревших VPN, перебор credentials.
- **SOC:** детект GRE/1701/1723 и слабых VPN.
- **Инженерия:** миграция с PPTP/L2TP на IKEv2/WireGuard.
