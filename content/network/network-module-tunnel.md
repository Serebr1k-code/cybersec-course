---
id: network-module-tunnel
title: "Туннели и оверлеи глубоко: SOCKS, HTTP CONNECT, GRE и VXLAN"
category: network
parent: network-tunneling
difficulty: easy
order: 3
tags: [network, tunnel, proxy, socks, http-connect, gre, vxlan, overlay]
prerequisites: [network-tunneling, network-ssh-tunnel]
useful_for:
  - "CTF Network (туннели и прокси)"
  - "Пентест: pivoting, обход сегментации"
  - "Работа (SOC): детект инкапсуляции"
estimated_minutes: 60
summary: "Модуль по туннелям и оверлеям: чем прокси отличается от туннеля, как работают SOCKS и HTTP CONNECT, что инкапсулируют GRE и VXLAN и как это использовать для pivoting и обхода сегментации."
---

Туннель переносит один протокол внутри другого, а оверлей строит виртуальную сеть поверх физической. Для пентестера это инструмент pivoting и обхода сегментации, для защитника — источник «невидимой» инкапсуляции. Этот модуль — база для [`network-socks-http-connect`](network-socks-http-connect) и [`network-gre-vxlan`](network-gre-vxlan), опирается на [`network-tunneling`](network-tunneling) и [`network-ssh-tunnel`](network-ssh-tunnel).

## Зачем туннели и оверлеи

Они решают три задачи:

- **доступ** — дотянуться до сегмента, куда нет прямого маршрута (pivoting);
- **обход** — протащить трафик через разрешённый канал;
- **изоляция** — построить виртуальную сеть поверх физической (VXLAN).

В пентесте туннели — основной способ двигаться вглубь сети после первого футхолда.

## Прокси vs туннель

- **Прокси** работает на прикладном уровне: клиент явно шлёт запрос прокси, тот пересылает. Примеры: SOCKS, HTTP CONNECT.
- **Туннель** инкапсулирует на сетевом уровне: пакеты «заворачиваются» целиком, приложение не знает о туннеле. Примеры: GRE, IPsec, VXLAN.

Прокси проще настраивается, туннель прозрачнее для приложений.

## SOCKS

**SOCKS** — прокси-протокол, работающий с любым TCP (SOCKS5 — ещё и UDP). Версии 4/4a (IPv4) и 5 (IPv6, аутентификация, UDP). Клиент говорит прокси «соедини меня с X:Y», прокси устанавливает соединение и релеит байты.

```bash
# SOCKS5 через SSH
ssh -D 1080 user@host
# Использовать через proxychains
proxychains4 curl http://internal.local
# Или напрямую
curl --socks5 127.0.0.1:1080 http://internal.local
```

## HTTP CONNECT

**HTTP CONNECT** — метод HTTP, превращающий прокси в TCP-релей: клиент шлёт `CONNECT host:port`, прокси устанавливает соединение и дальше пропускает байты. Часто разрешён на периметре (для HTTPS), поэтому это удобный канал для туннелирования.

```bash
# Туннель через корпоративный прокси
curl -x http://proxy:3128 -p https://internal.local
# Создать CONNECT-туннель вручную
printf 'CONNECT internal.local:443 HTTP/1.1\r\nHost: internal.local:443\r\n\r\n' | nc proxy 3128
```

## GRE

**GRE** (Generic Routing Encapsulation, IP proto 47) инкапсулирует произвольный протокол в IP. Не шифрует и не аутентифицирует — только инкапсулирует. Используется для туннелей и как транспорт для других протоколов.

```bash
# Создать GRE-туннель
sudo ip tunnel add gre1 mode gre remote 192.0.2.1 local 10.0.0.2 ttl 64
sudo ip link set gre1 up
sudo ip addr add 172.16.0.1/30 dev gre1
```

## VXLAN

**VXLAN** (Virtual Extensible LAN) строит L2-оверлей поверх L3: кадры Ethernet инкапсулируются в UDP (обычно порт 4789). Идентификатор сети — **VNI** (24 бита, до 16 млн сегментов). Точки инкапсуляции — **VTEP**.

```text
+--------+--------+------+--------+------------------+
| IP hdr | UDP    |VXLAN | VNI    | Original Ethernet|
+--------+--------+------+--------+------------------+
                     dst 4789
```

```bash
# Создать VXLAN-интерфейс
sudo ip link add vx0 type vxlan id 100 remote 192.0.2.1 dstport 4789 dev eth0
sudo ip link set vx0 up
sudo bridge fdb append 00:00:00:00:00:00 dev vx0 dst 192.0.2.1
```

## Инкапсуляция: что видно на проводе

| Технология | Инкапсуляция | Признак в дампе |
|---|---|---|
| SOCKS | TCP-релей | прикладной протокол внутри |
| HTTP CONNECT | TCP-релей | `CONNECT ...` в начале |
| GRE | proto 47 | внешний IP + GRE-заголовок |
| VXLAN | UDP/4789 | VNI + Ethernet внутри |
| IP-in-IP | proto 4 | двойной IP-заголовок |

```bash
# Захватить GRE и VXLAN
sudo tcpdump -i eth0 -nn 'ip proto 47'
sudo tcpdump -i eth0 -nn 'udp port 4789'
tshark -r cap.pcap -Y 'vxlan' -T fields -e vxlan.vni | sort -u
```

## Атаки и злоупотребления

- **Pivoting** — туннель в недоступный сегмент;
- **Обход сегментации** — трафик в инкапсуляции не фильтруется ACL по IP;
- **Covert-канал** — данные в туннеле;
- **VXLAN-инъекция** — подделка VNI/VTEP;
- **Прокси-abuse** — использование открытого прокси.

```bash
# Pivot через SSH SOCKS и проверка
ssh -D 1080 -N user@foothold &
proxychains4 nmap -sT -Pn -p 22,445 10.10.10.0/24
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `ssh -D/-L/-R` | SOCKS и port-forward |
| `proxychains` | маршрутизация через SOCKS |
| `chisel` | TCP/UDP-туннель через HTTP |
| `socat`/`nc` | реле и CONNECT |
| `ip tunnel` | GRE/IP-in-IP |
| `ip link vxlan` | VXLAN |

```bash
# chisel: сервер и клиент (pivot)
./chisel server -p 8080 --reverse
./chisel client attacker:8080 R:socks
```

## Типовые ошибки

- **Путать прокси и туннель** — разный уровень.
- **Забывать про MTU** — инкапсуляция уменьшает полезный размер.
- **Считать GRE «защищённым»** — он не шифрует.
- **Игнорировать UDP/4789** — VXLAN не фильтруется.
- **Не проверять DNS через прокси** — утечка резолвинга.
- **Забывать про прокси-аутентификацию** — открытый прокси.
- **Не тестировать маршруты** — pivot «есть», а трафик не идёт.

## Что дальше / решение

Пройдите [`network-socks-http-connect`](network-socks-http-connect) и [`network-gre-vxlan`](network-gre-vxlan). Для практики pivoting — [`network-ssh-tunnel`](network-ssh-tunnel) и [`network-firewall-piercing`](network-firewall-piercing).

## Практика: полная цепочка pivoting

```bash
# 1. Футхолд даёт SSH
ssh user@10.10.10.5
# 2. Поднять SOCKS на локальной машине через футхолд
ssh -D 1080 -N -f user@10.10.10.5
# 3. Настроить proxychains
cat > /etc/proxychains4.conf <<'EOF'
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
EOF
# 4. Просканировать следующий сегмент
proxychains4 nmap -sT -Pn -n -p 22,80,445,3389 10.10.20.0/24
# 5. Второй хост -> вторая цепочка (chain)
ssh -D 1081 -N -f user@10.10.20.7
```

Двухзвенные цепочки настраиваются в proxychains через `strict_chain` с двумя socks-записями.

## Сравнение способов туннелирования

| Способ | Уровень | Шифрование | Обход фильтров | Сложность |
|---|---|---|---|---|
| SSH -D (SOCKS) | прикл. | да (SSH) | средняя | низкая |
| SSH -L/-R | прикл. | да | средняя | низкая |
| HTTP CONNECT | прикл. | зависит | высокая (443) | низкая |
| chisel | прикл. | нет/опц. | высокая (HTTP) | низкая |
| GRE | сетевой | нет | высокая | средняя |
| VXLAN | канальный | нет | высокая | средняя |
| IPsec | сетевой | да | средняя | высокая |

## Чек-лист туннелирования

1. Есть ли **разрешённый** исходящий канал (443, DNS, ICMP)?
2. Какой уровень доступа нужен — TCP-порт или вся сеть?
3. Нужно ли **шифрование** (или достаточно инкапсуляции)?
4. Не утекает ли **DNS**?
5. Корректен ли **MTU** (инкапсуляция уменьшает payload)?
6. Работает ли **UDP** (если нужен)?
7. Как туннель **детектируется** (для защиты)?

```bash
# Проверить доступные исходящие каналы
nc -zv target 443; nc -zv target 53
# Проверить MTU внутри туннеля
ping -M do -s 1400 <inner-host>
```

Практический вывод: для pivoting почти всегда достаточно SOCKS через SSH; когда его нет — CONNECT/chisel; когда нужен «прозрачный» L3 — GRE/VXLAN. Выбор диктуется тем, что разрешено наружу и какой уровень доступа нужен.

## Квиз

```quiz
- question: "На каком уровне работает SOCKS-прокси?"
  options:
    - "Прикладном (релеит TCP/UDP)"
    - "Канальном"
    - "Сетевом (инкапсуляция)"
    - "Физическом"
  answer: 0
  explanation: "SOCKS — прокси-протокол для TCP (и UDP в v5)."
- question: "Что делает метод HTTP CONNECT?"
  options:
    - "Превращает прокси в TCP-релей"
    - "Шифрует запрос"
    - "Сжимает данные"
    - "Назначает IP"
  answer: 0
  explanation: "CONNECT устанавливает туннель через прокси."
- question: "Какой IP-протокол использует GRE?"
  options:
    - "47"
    - "50"
    - "51"
    - "41"
  answer: 0
  explanation: "GRE — protocol 47."
- question: "По какому порту обычно работает VXLAN?"
  options:
    - "UDP 4789"
    - "TCP 443"
    - "UDP 500"
    - "TCP 4789"
  answer: 0
  explanation: "VXLAN инкапсулирует Ethernet в UDP/4789."
- question: "Почему туннель помогает обойти сегментацию?"
  options:
    - "ACL по IP не видит инкапсулированный трафик"
    - "Он ускоряет сеть"
    - "Он меняет MAC"
    - "Он отключает STP"
  answer: 0
  explanation: "Фильтры уровня IP не разбирают внутреннюю инкапсуляцию."
```

## Где пригодится

- **CTF:** задачи с туннелями и оверлеями.
- **Пентест:** pivoting, обход сегментации.
- **SOC:** детект GRE/VXLAN и необычных прокси.
- **Инженерия:** диагностика MTU, VXLAN-фабрик.
