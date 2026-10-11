---
id: network-gre-vxlan
title: "GRE и VXLAN: инкапсуляция, оверлеи и их атаки"
category: network
parent: network-module-tunnel
difficulty: hard
order: 2
tags: [network, gre, vxlan, overlay, encapsulation, vtep, vni]
prerequisites: [network-module-tunnel, network-vlan-qinq]
useful_for:
  - "CTF Network (инкапсуляция)"
  - "Пентест: обход сегментации, инъекции в оверлей"
  - "Работа (SOC): детект оверлеев"
estimated_minutes: 60
summary: "GRE и VXLAN: как инкапсулируется трафик, как читать GRE-заголовок и VXLAN VNI, зачем нужны VTEP, какие атаки возможны и как детектировать оверлеи в трафике."
---

Инкапсуляция — основа оверлеев: GRE прячет произвольный протокол в IP, VXLAN строит L2-сеть поверх L3. Для пентестера это способ обойти сегментацию и инъецировать трафик в чужой оверлей; для SOC — источник «невидимых» потоков. Урок продолжает [`network-module-tunnel`](network-module-tunnel).

## GRE: базовая инкапсуляция

**GRE** (Generic Routing Encapsulation) — IP-протокол **47**. Он инкапсулирует любой протокол в IP и **не шифрует**. GRE-заголовок содержит флаги, protocol type (что внутри) и опциональные поля.

```text
+--------+--------+--------+------------------+
| IP hdr | GRE hdr| inner  | FCS/транспорт    |
| proto47| type   | packet |                  |
+--------+--------+--------+------------------+
```

```bash
# Создать GRE-туннель
sudo ip tunnel add gre1 mode gre remote 192.0.2.1 local 10.0.0.2 ttl 64
sudo ip link set gre1 up
sudo ip addr add 172.16.0.1/30 dev gre1
# Захватить
sudo tcpdump -i eth0 -nn 'ip proto 47'
```

GRE часто несёт multicast/unicast-трафик между сайтами и служит транспортом для других протоколов (например, PPTP).

## VXLAN: L2 поверх L3

**VXLAN** инкапсулирует Ethernet-кадры в **UDP/4789**. Идентификатор сети — **VNI** (24 бита). Устройства, выполняющие инкапсуляцию, называются **VTEP** (VXLAN Tunnel Endpoint). VXLAN позволяет «растянуть» L2 между датацентрами.

```text
+---------+------+-------+-----+-------------------+
| outer IP| UDP  | VXLAN | VNI | inner Ethernet    |
|         | 4789 | hdr   |     | frame             |
+---------+------+-------+-----+-------------------+
```

```bash
# Создать VXLAN-интерфейс
sudo ip link add vx0 type vxlan id 100 remote 192.0.2.1 dstport 4789 dev eth0
sudo ip link set vx0 up
# FDB-запись для удалённого VTEP
sudo bridge fdb append 00:00:00:00:00:00 dev vx0 dst 192.0.2.1
# Захватить и увидеть VNI
sudo tcpdump -i eth0 -nn 'udp port 4789'
tshark -r cap.pcap -Y 'vxlan' -T fields -e vxlan.vni | sort -u
```

## Формат и VTEP

VXLAN-заголовок — 8 байт: flags, reserved, **VNI** (24 бита), reserved. VTEP — источник/приёмник инкапсуляции; бывает аппаратным (коммутатор) или программным (Linux vxlan).

| Поле | Размер | Смысл |
|---|---|---|
| Flags | 1 | I-бит = valid VNI |
| Reserved | 3 | зарезервировано |
| VNI | 3 | идентификатор сети |
| Reserved | 1 | зарезервировано |

## Практика: разбор оверлея

```bash
# 1. Захватить VXLAN
sudo tcpdump -i eth0 -nn -w vx.pcap 'udp port 4789'
# 2. Показать VNI и внутренние MAC
tshark -r vx.pcap -Y 'vxlan' -T fields -e vxlan.vni -e eth.src | head
# 3. Внутренние IP (внутри инкапсуляции)
tshark -r vx.pcap -Y 'vxlan' -V | grep -A1 "Internet Protocol" | head
# 4. GRE
sudo tcpdump -i eth0 -nn -w gre.pcap 'ip proto 47'
tshark -r gre.pcap -Y 'gre' -T fields -e gre.proto | head
```

Внутренние адреса видны только после разбора инкапсуляции — именно поэтому простые ACL по IP их не фильтруют.

## Атаки

- **Обход сегментации** — трафик в оверлее не матчится ACL по внешнему IP;
- **VNI-инъекция** — подделка VNI/VTEP для доступа в чужой сегмент;
- **Covert-канал** — данные внутри GRE/VXLAN;
- **MITM на VTEP** — при отсутствии аутентификации;
- **Amplification** — редко, но VXLAN/VTEP-флуд возможен.

```bash
# Инъекция в оверлей через scapy (лаборатория)
python3 - <<'PY'
from scapy.all import *
pkt = IP(dst="192.0.2.1")/UDP(dport=4789)/VXLAN(vni=100)/Ether()/IP(dst="10.10.10.5")/ICMP()
send(pkt)
PY
```

## Детект в SOC

- **UDP/4789** и **proto 47** на неожиданных сегментах;
- **аномальные VNI** (не из разрешённого диапазона);
- **VTEP с неизвестного адреса**;
- **всплеск инкапсулированного трафика**.

```bash
# Сводка VNI и VTEP
tshark -r vx.pcap -Y 'vxlan' -T fields -e ip.src -e vxlan.vni | sort | uniq -c | sort -rn
# GRE внутри
tshark -r gre.pcap -Y 'gre' -T fields -e ip.src -e gre.proto | sort | uniq -c
```

## Защита

| Мера | Против чего |
|---|---|
| Фильтрация UDP/4789 и proto 47 на границе | инъекции извне |
| Аутентификация VTEP (IPsec/MACsec) | MITM/спуфинг |
| Разрешённый список VNI/VTEP | инъекция в чужой оверлей |
| Сегментация под VTEP | lateral movement |
| Мониторинг оверлеев | детект аномалий |

## Частые ошибки

- **Считать GRE шифрованием** — он не шифрует.
- **Не фильтровать UDP/4789** — VXLAN-инъекции проходят.
- **Игнорировать MTU** — инкапсуляция уменьшает полезный размер.
- **Путать VNI и VLAN** — разные пространства идентификаторов.
- **Смотреть только внешний IP** — внутренние адреса не видны.
- **Не аутентифицировать VTEP** — спуфинг/ MITM.
- **Забывать про FDB** — оверлей «не поднимается».

## Что дальше / решение

После GRE/VXLAN вернитесь к [`network-module-tunnel`](network-module-tunnel). Для pivoting — [`network-socks-http-connect`](network-socks-http-connect) и [`network-ssh-tunnel`](network-ssh-tunnel).

## Практика: GRE и VXLAN на Linux

```bash
# GRE-туннель точка-точка
sudo ip tunnel add gre1 mode gre remote 192.0.2.1 local 10.0.0.2 ttl 64
sudo ip link set gre1 up
sudo ip addr add 172.16.0.1/30 dev gre1
ip -d link show gre1
# Наблюдать инкапсуляцию
sudo tcpdump -i eth0 -nn 'ip proto 47' -c 5

# VXLAN-оверлей
sudo ip link add vx0 type vxlan id 100 remote 192.0.2.1 dstport 4789 dev eth0
sudo ip link set vx0 up
sudo ip addr add 10.100.0.1/24 dev vx0
sudo bridge fdb append 00:00:00:00:00:00 dev vx0 dst 192.0.2.1
ip -d link show vx0 | grep vxlan
sudo tcpdump -i eth0 -nn 'udp port 4789' -c 5
```

На стенде удобно наблюдать: внешний IP, GRE-заголовок или UDP/4789 с VNI, и внутренний кадр.

## Сравнение оверлеев

| Оверлей | Инкапсуляция | Единица | Порт/прото | Шифрование |
|---|---|---|---|---|
| GRE | IP в IP | туннель | 47 | нет |
| VXLAN | Ethernet в UDP | VNI | 4789 | нет |
| Geneve | Ethernet в UDP | VNI | 6081 | нет |
| IP-in-IP | IP в IP | туннель | 4 | нет |
| WireGuard | IP в UDP | peer | 51820 | да |
| IPsec | IP в ESP | SA | 50 | да |

## Чек-лист оверлеев

1. Какие оверлеи работают (**proto 47, UDP 4789/6081**)?
2. Какие **VNI** разрешены и есть ли аномальные?
3. Кто такие **VTEP** и не появляются ли новые?
4. Аутентифицирован ли оверлей (**IPsec/MACsec**)?
5. Фильтруется ли инкапсуляция на **границе**?
6. Корректен ли **MTU** (инкапсуляция уменьшает payload)?
7. Мониторятся ли оверлеи?

```bash
# Сводка по оверлеям в дампе
tshark -r cap.pcap -T fields -e ip.proto | sort | uniq -c | sort -rn | head
tshark -r cap.pcap -Y 'vxlan' -T fields -e vxlan.vni | sort | uniq -c
```

Вывод: GRE и VXLAN — мощные оверлеи без встроенной безопасности. Их защита целиком ложится на фильтрацию на границе, аутентификацию VTEP и мониторинг VNI/VTEP.

## Квиз

```quiz
- question: "Какой IP-протокол использует GRE?"
  options:
    - "47"
    - "50"
    - "4"
    - "41"
  answer: 0
  explanation: "GRE инкапсулирует произвольный протокол под IP protocol 47."
- question: "Шифрует ли GRE трафик?"
  options:
    - "Нет, только инкапсулирует"
    - "Да, AES"
    - "Да, но слабо"
    - "Только заголовок"
  answer: 0
  explanation: "GRE не обеспечивает шифрование и аутентификацию."
- question: "Какой порт использует VXLAN по умолчанию?"
  options:
    - "UDP 4789"
    - "TCP 443"
    - "UDP 500"
    - "UDP 1701"
  answer: 0
  explanation: "VXLAN инкапсулирует Ethernet в UDP/4789."
- question: "Что такое VNI в VXLAN?"
  options:
    - "Идентификатор сети (24 бита)"
    - "IP-адрес VTEP"
    - "MAC-адрес"
    - "Порт"
  answer: 0
  explanation: "VNI (VXLAN Network Identifier) различает сегменты оверлея."
- question: "Почему оверлей обходит сегментацию?"
  options:
    - "ACL по внешнему IP не разбирают инкапсуляцию"
    - "Он шифрует"
    - "Он ускоряет сеть"
    - "Он меняет MAC"
  answer: 0
  explanation: "Внутренний трафик скрыт внутри UDP/proto47."
```

## Где пригодится

- **CTF:** задачи с инкапсуляцией и оверлеями.
- **Пентест:** обход сегментации, инъекции в оверлей.
- **SOC:** детект VXLAN/GRE и аномальных VNI.
- **Инженерия:** диагностика VXLAN-фабрик и MTU.
