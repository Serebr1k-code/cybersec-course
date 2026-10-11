---
id: network-socks-http-connect
title: "SOCKS и HTTP CONNECT: прокси-туннели для pivoting"
category: network
parent: network-module-tunnel
difficulty: medium
order: 1
tags: [network, socks, http-connect, proxy, pivoting, proxychains]
prerequisites: [network-module-tunnel, network-ssh-tunnel]
useful_for:
  - "CTF Network (прокси-задачи)"
  - "Пентест: pivoting через прокси"
  - "Работа (SOC): детект прокси-злоупотребления"
estimated_minutes: 55
summary: "Как работают SOCKS4/5 и HTTP CONNECT, как настроить pivoting через SSH-динамический порт и proxychains, чем отличается прокси от туннеля и как детектировать прокси-трафик."
---

Прокси — самый доступный способ pivoting: он не требует прав на инкапсуляцию и часто разрешён наружу. Понимание SOCKS и HTTP CONNECT объясняет, как протащить сканер в закрытый сегмент и как это заметить. Урок продолжает [`network-module-tunnel`](network-module-tunnel).

## Что такое прокси

Прокси — посредник: клиент адресует запрос прокси, а тот устанавливает соединение с целью и релеит данные. Различают:

- **Forward proxy** — для клиентов (обход ограничений, pivoting);
- **Reverse proxy** — для серверов (балансировка, WAF);
- **Transparent** — без настройки клиента;
- **Open proxy** — доступен всем (abuse).

## SOCKS4 и SOCKS5

**SOCKS4** — только TCP и IPv4, без аутентификации. **SOCKS4a** — с разрешением имён на прокси. **SOCKS5** — TCP и UDP, IPv6, методы аутентификации (none, user/pass, GSSAPI).

```text
SOCKS5 greeting:  VER=5, NMETHODS, METHODS...
SOCKS5 request:   VER=5, CMD(connect), ATYP, DST.ADDR, DST.PORT
```

```bash
# Динамический SOCKS через SSH (самый частый способ)
ssh -D 1080 -N -f user@foothold
# Проверить
curl --socks5 127.0.0.1:1080 http://internal.local
# Или через curl с прокси
curl --proxy socks5h://127.0.0.1:1080 http://internal.local
```

`socks5h` означает, что DNS-резолвинг тоже идёт через прокси (важно, чтобы не утечь имена).

## HTTP CONNECT

Метод **CONNECT** превращает HTTP-прокси в TCP-релей. Клиент шлёт:

```text
CONNECT internal.local:443 HTTP/1.1
Host: internal.local:443
```

Прокси отвечает `200 Connection established` и далее пропускает байты. Это стандартный путь для HTTPS через прокси — и удобный канал для туннелирования произвольного TCP.

```bash
# Туннель через прокси
curl -x http://proxy:3128 -p https://internal.local
# Ручной CONNECT
printf 'CONNECT internal.local:22 HTTP/1.1\r\nHost: internal.local:22\r\n\r\n' | nc proxy 3128
```

## Практика: pivoting через proxychains

```bash
# 1. Поднять SOCKS через скомпрометированный хост
ssh -D 1080 -N -f user@foothold
# 2. Настроить proxychains
cat > /etc/proxychains4.conf <<'EOF'
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
EOF
# 3. Сканировать внутренний сегмент
proxychains4 nmap -sT -Pn -p 22,80,445 10.10.10.0/24
# 4. Обращаться к сервисам
proxychains4 curl http://10.10.10.5/
```

Важно: `nmap` без `-sT` (SYN-скан) через прокси не работает — прокси даёт только TCP-соединения. Поэтому используйте connect-скан.

## Детект прокси-трафика

- **CONNECT-запросы** в логах прокси — к необычным портам;
- **долгие TCP-сессии** с однородным трафиком;
- **обращение к одному прокси** множества внутренних адресов;
- **SOCKS-рукопожатия** (`0x05` в начале).

```bash
# Найти CONNECT-запросы
tshark -r cap.pcap -Y 'http.request.method=="CONNECT"' -T fields -e http.host | sort | uniq -c
# Найти SOCKS5 (первый байт 0x05)
tshark -r cap.pcap -Y 'tcp.len>0' -T fields -e tcp.payload | grep -i '^05' | head
```

## Защита

| Мера | Против чего |
|---|---|
| Запрет CONNECT к внутренним адресам | pivoting |
| Аутентификация прокси | open proxy |
| Egress-фильтрация | туннели наружу |
| Мониторинг CONNECT/SOCKS | детект |
| Не использовать открытые прокси | abuse |

## Частые ошибки

- **SYN-скан через прокси** — не работает, нужен `-sT`.
- **Утечка DNS** — без `socks5h`/`proxy_dns` имена уходят напрямую.
- **Забывать про аутентификацию** — открытый прокси.
- **Игнорировать CONNECT-порты** — нестандартные порты выдают туннель.
- **Считать прокси шифром** — он не шифрует.
- **Не проверять UDP** — SOCKS5 умеет UDP, многие это забывают.
- **Забывать про MTU/таймауты** — долгие сессии рвутся.

## Что дальше / решение

После прокси переходите к [`network-gre-vxlan`](network-gre-vxlan) (сетевые туннели). Для полного pivoting — [`network-ssh-tunnel`](network-ssh-tunnel) и [`network-firewall-piercing`](network-firewall-piercing).

## Продвинутая настройка proxychains

```bash
# Динамическая цепочка (dynamic_chain) — пропускает мёртвые прокси
cat > /etc/proxychains4.conf <<'EOF'
dynamic_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
EOF
# Random chain — рандомизирует порядок (для обхода корреляции)
# strict_chain — строгий порядок
```

```bash
# Инструменты через прокси
proxychains4 curl http://10.10.10.5/
proxychains4 smbclient -L 10.10.10.5
proxychains4 hydra -L users -P pass ssh://10.10.10.5
# Запуск приложения целиком
proxychains4 -q firefox
```

Помните: proxychains перехватывает `connect()` через LD_PRELOAD — статические бинарники и сырые сокеты (SYN-скан) обходят его.

## Сравнение прокси-протоколов

| Протокол | Уровень | TCP | UDP | Аутентификация |
|---|---|---|---|---|
| SOCKS4 | прикл. | да | нет | нет |
| SOCKS4a | прикл. | да | нет | нет (имена на прокси) |
| SOCKS5 | прикл. | да | да | none/user-pass |
| HTTP CONNECT | прикл. | да | нет | basic |
| SSH -D | прикл. | да | нет | SSH-ключ/пароль |

## Чек-лист прокси-pivoting

1. Какой прокси **разрешён** наружу (SOCKS/CONNECT)?
2. Есть ли **аутентификация** (или прокси открыт)?
3. Настроен ли **DNS через прокси** (`socks5h`/`proxy_dns`)?
4. Работает ли **connect-скан** (`-sT`)?
5. Нужен ли **UDP** (тогда SOCKS5)?
6. Сколько **звеньев** цепочки нужно?
7. Как прокси **детектируется** (CONNECT к внутренним адресам)?

```bash
# Диагностика прокси
curl -v --socks5 127.0.0.1:1080 http://example.com 2>&1 | head
proxychains4 -q curl -s ifconfig.me
```

Вывод: SOCKS5 через SSH — универсальный выбор; HTTP CONNECT — когда наружу открыт только прокси; для UDP — SOCKS5. Ключевые подводные камни — утечка DNS, невозможность SYN-скана и выбор звеньев.

## Детект и защита прокси-pivoting

```bash
# CONNECT-запросы к внутренним адресам — признак pivoting
tshark -r cap.pcap -Y 'http.request.method=="CONNECT"' \
  -T fields -e http.host -e ip.dst | sort | uniq -c | sort -rn | head
# SOCKS5-рукопожатие: первый байт 0x05 в payload
tshark -r cap.pcap -Y 'tcp.len>0 && tcp.port==1080' -T fields -e tcp.payload | head
# Аномально долгие однородные TCP-сессии
tshark -r cap.pcap -Y 'tcp' -T fields -e tcp.stream | sort | uniq -c | sort -rn | head
```

Признаки pivoting: один источник обращается к множеству внутренних адресов; CONNECT к нестандартным портам (22, 445, 3389); SOCKS-рукопожатия внутри сети; долгие сессии без «прикладного» обмена.

## Защита на стороне сети

| Мера | Эффект |
|---|---|
| Запретить CONNECT к внутренним подсетям | ломает pivoting |
| Аутентификация прокси | закрывает open proxy |
| Egress-allowlist | ограничивает туннели наружу |
| Мониторинг CONNECT/SOCKS | детект |
| Сегментация + межсегментный firewall | ограничивает охват |

```bash
# Пример правила squid: запрет CONNECT к RFC1918
# acl internal dst 10.0.0.0/8
# acl internal dst 192.168.0.0/16
# http_access deny CONNECT internal
```

Вывод: прокси-pivoting трудно устранить полностью (наружу часто разрешён HTTPS), но можно резко ограничить: запретить CONNECT к внутренним адресам, требовать аутентификацию и мониторить необычные цели. В сочетании с сегментацией это делает pivoting дорогим.

## Квиз

```quiz
- question: "Чем SOCKS5 отличается от SOCKS4?"
  options:
    - "Поддержкой UDP, IPv6 и аутентификации"
    - "Только скоростью"
    - "Отсутствием TCP"
    - "Шифрованием"
  answer: 0
  explanation: "SOCKS5 добавил UDP, IPv6 и методы аутентификации."
- question: "Что делает метод HTTP CONNECT?"
  options:
    - "Устанавливает TCP-туннель через прокси"
    - "Шифрует запрос"
    - "Сжимает ответ"
    - "Назначает IP"
  answer: 0
  explanation: "CONNECT превращает прокси в TCP-релей."
- question: "Почему SYN-скан не работает через SOCKS-прокси?"
  options:
    - "Прокси даёт только TCP-соединения, не сырые пакеты"
    - "Прокси блокирует порты"
    - "Прокси шифрует"
    - "Прокси медленный"
  answer: 0
  explanation: "Нужен connect-скан (-sT), а не сырой SYN."
- question: "Что означает socks5h в curl?"
  options:
    - "DNS-резолвинг тоже идёт через прокси"
    - "Шифрование трафика"
    - "Использование IPv6"
    - "UDP-режим"
  answer: 0
  explanation: "h = hostname resolved by proxy — нет утечки DNS."
- question: "Какой признак CONNECT в дампе?"
  options:
    - "HTTP-метод CONNECT к внутреннему адресу"
    - "Ровный HTTPS-поток"
    - "ARP-запрос"
    - "ICMP echo"
  answer: 0
  explanation: "CONNECT-запросы к внутренним целям выдают pivoting."
```

## Где пригодится

- **CTF:** задачи с прокси и внутренними сегментами.
- **Пентест:** pivoting через SOCKS/CONNECT.
- **SOC:** детект CONNECT и SOCKS-рукопожатий.
- **Инженерия:** настройка и ограничение прокси.
