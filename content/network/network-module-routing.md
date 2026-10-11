---
id: network-module-routing
title: "Маршрутизация глубоко: RIP, OSPF, EIGRP, MPLS и VRF"
category: network
parent: network-routing
difficulty: easy
order: 1
tags: [network, routing, rip, ospf, eigrp, mpls, vrf, bgp]
prerequisites: [network-routing-wan, network-routing]
useful_for:
  - "CTF Network (маршрутизация)"
  - "Пентест: инъекции маршрутов, hijack"
  - "Работа (SOC/инженер): анализ и защита маршрутизации"
estimated_minutes: 60
summary: "Модуль по маршрутизации: как выбирается путь, чем отличаются RIP/OSPF/EIGRP/BGP, зачем нужны MPLS и VRF и какие атаки возможны на динамическую маршрутизацию."
---

Маршрутизация — «мозг» сети: она решает, куда уйдёт каждый пакет. Динамические протоколы (RIP, OSPF, EIGRP, BGP) обмениваются маршрутами без аутентификации во многих конфигурациях, поэтому атакующий в сегменте может подсунуть ложный маршрут и увести трафик. Этот модуль — база для [`network-rip-eigrp`](network-rip-eigrp) и [`network-mpls-vrf`](network-mpls-vrf), опирается на [`network-routing`](network-routing) и [`network-bgp-hijack`](network-bgp-hijack).

## Зачем отдельный модуль

Маршрутизация кажется «скучной», но именно она определяет:

- куда реально идёт трафик (и куда его можно увести);
- какие пути резервные (и как их отравить);
- как сегментированы сети (VRF, MPLS);
- где границы доверия (BGP-сессии, OSPF-соседство).

Ошибка в маршрутизации или поддельное объявление могут «выключить» сеть или сделать MITM на масштабе региона.

## Как маршрутизатор выбирает путь

Маршрутизатор хранит **RIB** (Routing Information Base) — таблицу маршрутов. При нескольких путях к одной сети выбирается по:

1. **Longest prefix match** — самый специфичный префикс.
2. **Administrative Distance (AD)** — доверие к источнику маршрута.
3. **Метрика** — «стоимость» пути внутри протокола.

```bash
# Таблица маршрутов и выбор для адреса
ip route show
ip route get 10.20.30.40
```

## Administrative Distance: кому верить

| Источник | AD (Cisco) |
|---|---|
| Connected | 0 |
| Static | 1 |
| eBGP | 20 |
| EIGRP | 90 |
| OSPF | 110 |
| RIP | 120 |
| iBGP | 200 |

Меньше AD — выше доверие. Это ключ к атакам: если подсунуть маршрут от источника с меньшим AD (или более специфичный префикс), он победит легитимный.

## Протоколы маршрутизации: кратко

- **RIP** — дистанционно-векторный, метрика = число хопов, максимум 15. Прост, медленный, уязвим.
- **OSPF** — link-state, метрика = стоимость (bandwidth), сходимость быстрая. Атакуется через поддельные LSA.
- **EIGRP** — гибридный (Cisco), метрика по bandwidth/delay. Атакуется через поддельные update.
- **BGP** — внешняя маршрутизация между AS. Атаки — hijack, route leak (см. `network-bgp-hijack`).

## MPLS и VRF: сегментация на L3

**MPLS** коммутирует по меткам (label), а не по IP: маршрут определяется заранее (LSP). **VRF** (Virtual Routing and Forwarding) создаёт несколько независимых таблиц маршрутов на одном устройстве — так провайдер изолирует клиентов. Утечка между VRF (route leak) — серьёзная атака. Подробно — в `network-mpls-vrf`.

## Атаки на маршрутизацию

- **RIP/OSPF/EIGRP-инъекция** — поддельные объявления уводят трафик;
- **Route leak** — анонс чужих префиксов;
- **BGP hijack** — перехват префикса;
- **Blackhole/loop** — маршрут в никуда;
- **MITM через маршрут** — «я ближе к этой сети».

```bash
# RIP-объявление (лаборатория, scapy)
python3 - <<'PY'
from scapy.all import *
pkt = IP(dst="224.0.0.9")/UDP(sport=520,dport=520)/b"\x02\x02\x00\x00\x00\x02" + b"\x00\x02" + b"\x0a\x00\x00\x00\xff\xff\xff\x00" + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x00"*6
send(pkt)
PY
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `ip route` | таблица маршрутов |
| `quagga`/`frr` | запуск OSPF/RIP/BGP на Linux |
| `scapy` | генерация протокольных пакетов |
| `tcpdump`/`tshark` | захват OSPF/RIP/BGP |
| `bgpstream`/`RIPE RIS` | наблюдение BGP |

```bash
# Захватить OSPF hello и BGP
sudo tcpdump -i eth0 -nn 'ip proto 89 or tcp port 179'
```

## Типовые ошибки

- **Забывать про AD** — «непонятно, почему выбран этот маршрут».
- **Путать метрику и AD** — это разные вещи.
- **Игнорировать аутентификацию протоколов** — RIP/OSPF без пароля.
- **Считать VRF «полной изоляцией»** — route leak возможен.
- **Не мониторить изменения RIB** — hijack невидим.
- **Тестировать только default route** — специфичные префиксы важнее.
- **Забывать про IPv6-маршрутизацию** — отдельная плоскость.

## Что дальше / решение

Пройдите [`network-rip-eigrp`](network-rip-eigrp) и [`network-mpls-vrf`](network-mpls-vrf). Для BGP — [`network-bgp-hijack`](network-bgp-hijack) и [`network-routing`](network-routing).

## Метрики OSPF и стоимость пути

OSPF считает стоимость как `reference bandwidth / interface bandwidth`. По умолчанию reference = 100 Мбит/с, поэтому 100 Мбит/с и выше дают одинаковую стоимость 1 — частая ошибка проектирования. Метрику можно задать вручную.

| Скорость | Cost (ref 100 Мбит) | Cost (ref 10 Гбит) |
|---|---|---|
| 10 Мбит/с | 10 | 1000 |
| 100 Мбит/с | 1 | 100 |
| 1 Гбит/с | 1 | 10 |
| 10 Гбит/с | 1 | 1 |

```text
# Cisco: изменить reference bandwidth и стоимость
auto-cost reference-bandwidth 10000
interface Gi0/1
 ip ospf cost 5
```

## Лаборатория: FRR и OSPF

```bash
# Установить FRR и поднять OSPF на Linux
sudo apt install frr
sudo vtysh -c 'configure terminal' -c 'router ospf' -c 'network 10.0.0.0/24 area 0'
# Захватить OSPF-пакеты (protocol 89)
sudo tcpdump -i eth0 -nn 'ip proto 89'
# Показать соседей и маршруты
sudo vtysh -c 'show ip ospf neighbor' -c 'show ip route ospf'
```

OSPF-соседство устанавливается через Hello-пакеты на multicast `224.0.0.5` (AllSPFRouters). Поддельный Hello с большим Router Priority может стать DR (Designated Router) — а поддельные LSA уводят трафик.

## Практический чек-лист маршрутизации

1. Какие протоколы маршрутизации работают в сегменте (OSPF/RIP/EIGRP)?
2. Включена ли **аутентификация**?
3. Настроены ли **passive-interface** на «крайних» портах?
4. Каковы **AD** и **метрики** — можно ли подсунуть лучший маршрут?
5. Есть ли **фильтрация** маршрутных протоколов на периметре?
6. Мониторятся ли **изменения RIB** и новые соседи?
7. Как настроены **VRF/MPLS** — нет ли утечек?

```bash
# Снимок маршрутов для baseline
ip route show; ip -6 route show
# Трассировка реального пути
traceroute -n 10.20.0.1
```

## Пример конфигураций протоколов

```text
# OSPF (Cisco)
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
 passive-interface Gi0/24
# RIP (Cisco)
router rip
 version 2
 network 10.0.0.0
 no auto-summary
# EIGRP (Cisco)
router eigrp 100
 network 10.0.0.0
 passive-interface default
 no passive-interface Gi0/1
# BGP (Cisco)
router bgp 65001
 neighbor 10.0.0.2 remote-as 65002
```

```bash
# FRR: запустить и посмотреть состояние
sudo vtysh -c 'show ip ospf neighbor'
sudo vtysh -c 'show ip bgp summary'
sudo vtysh -c 'show ip route'
```

## Диагностика: симптомы и причины

| Симптом | Вероятная причина |
|---|---|
| Трафик идёт «не туда» | поддельный маршрут / неверный AD |
| Сеть периодически «моргает» | flapping-линк, нестабильные update |
| Появился новый next hop | инъекция маршрута |
| Маршрут исчез после перезагрузки | нет статики/аутентификации |
| Асимметрия путей | разная метрика на концах |
| Петля маршрутизации | ошибка summary/redistribute |

```bash
# Сравнить путь до цели
ip route get 10.20.0.1
traceroute -n 10.20.0.1
# Проверить стабильность (несколько раз)
for i in 1 2 3; do ip route get 10.20.0.1; sleep 1; done
```

Стабильность пути между запросами — простой тест на flapping и инъекцию.

## Квиз

```quiz
- question: "По какому принципу выбирается маршрут при нескольких совпадениях?"
  options:
    - "Longest prefix match, затем AD и метрика"
    - "Случайно"
    - "По номеру интерфейса"
    - "По размеру пакета"
  answer: 0
  explanation: "Сначала самый специфичный префикс, затем доверие (AD), затем метрика."
- question: "Что такое Administrative Distance?"
  options:
    - "Мера доверия к источнику маршрута"
    - "Скорость интерфейса"
    - "Число хопов"
    - "Размер MTU"
  answer: 0
  explanation: "Меньше AD — выше приоритет источника маршрута."
- question: "Какая метрика у RIP?"
  options:
    - "Число хопов (максимум 15)"
    - "Стоимость канала"
    - "Задержка"
    - "Загрузка"
  answer: 0
  explanation: "RIP считает хопы; 16 = недостижимо."
- question: "Что делает VRF?"
  options:
    - "Создаёт независимые таблицы маршрутов на одном устройстве"
    - "Шифрует трафик"
    - "Ускоряет BGP"
    - "Назначает MAC"
  answer: 0
  explanation: "VRF изолирует маршруты (например, клиентов провайдера)."
- question: "Какая атака уводит трафик через поддельное объявление?"
  options:
    - "Инъекция маршрута (RIP/OSPF/EIGRP)"
    - "ARP-спуфинг"
    - "DNS-туннель"
    - "SYN-флуд"
  answer: 0
  explanation: "Поддельный update/LSA меняет RIB и путь трафика."
```

## Где пригодится

- **CTF:** задачи с маршрутизацией и дампами OSPF/RIP/BGP.
- **Пентест:** инъекции маршрутов, MITM, hijack.
- **SOC:** детект аномальных объявлений и route leak.
- **Инженерия:** диагностика выбора пути, AD, VRF.
