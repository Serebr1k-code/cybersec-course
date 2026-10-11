---
id: network-mpls-vrf
title: "MPLS и VRF: метки, LSP и изоляция маршрутов"
category: network
parent: network-module-routing
difficulty: hard
order: 2
tags: [network, mpls, vrf, label, lsp, l3vpn, isolation]
prerequisites: [network-module-routing, network-routing]
useful_for:
  - "CTF Network (MPLS/VRF)"
  - "Пентест: утечки между VRF, перехват провайдерского трафика"
  - "Работа (инженер): диагностика MPLS и изоляции"
estimated_minutes: 60
summary: "Как MPLS коммутирует по меткам, что такое LSP, как VRF изолирует маршруты клиентов и какие атаки возможны (route leak, label spoofing) — с командами и разбором."
---

Провайдеры не маршрутизируют клиентский трафик «в лоб»: они коммутируют его по **меткам** (MPLS) и держат маршруты клиентов в отдельных таблицах (**VRF**). Эта архитектура быстра и изолирует клиентов — но изоляция не абсолютна. Урок продолжает [`network-module-routing`](network-module-routing).

## Что такое MPLS

**MPLS** (Multiprotocol Label Switching) — коммутация по **метке** фиксированной длины (20 бит) вместо анализа IP на каждом хопе. Метка вставляется между L2- и L3-заголовками (или в shim-заголовок). Пакет идёт по заранее построенному **LSP** (Label Switched Path).

```text
+--------+--------+---------+--------+----------+------+
| Dst MAC| Src MAC| 0x8847 | Label  | IP-пакет | FCS  |
+--------+--------+---------+--------+----------+------+
```

EtherType `0x8847` (unicast MPLS), `0x8848` (multicast).

```bash
# Захватить MPLS-пакеты
sudo tcpdump -i eth0 -nn 'ether proto 0x8847' -c 5
tshark -r cap.pcap -Y 'mpls' -T fields -e mpls.label | head
```

## Метки и LSP

Маршрутизатор на входе в MPLS-домен (**ingress LER**) навешивает метку, промежуточные (**LSR**) меняют её (**swap**), на выходе (**egress LER**) снимают. Метка определяет следующий хоп, а не IP. Стек меток позволяет строить VPN (внешняя метка — транспорт, внутренняя — VPN).

```bash
# На Cisco: посмотреть таблицу меток
# show mpls forwarding-table
# show mpls ldp bindings
```

## VRF: изоляция маршрутов

**VRF** — это отдельная таблица маршрутов + отдельная таблица forwarding. Провайдер создаёт по VRF на клиента, поэтому два клиента с одинаковыми `10.0.0.0/24` не конфликтуют. Идентификация клиента — **RD** (Route Distinguisher), а экспорт/импорт маршрутов между VRF — через **RT** (Route Target).

```bash
# На Linux: список VRF
ip vrf show 2>/dev/null || ip link show type vrf
# Маршруты внутри VRF
ip route show vrf blue
```

## Утечки и атаки

- **Route leak между VRF** — маршруты одного клиента попадают в таблицу другого. Причина — неверные RT.
- **Label spoofing** — подделка метки для инъекции в чужой LSP.
- **LDP/RSVP-инъекция** — поддельные привязки меток.
- **Mpls-инкапсуляция как обход** — трафик в MPLS не фильтруется обычными ACL по IP.

```bash
# Найти утечку: маршрут клиента A виден в VRF клиента B
ip route show vrf red | grep '10.99.0.0'
# Захват MPLS и разбор стека меток
tshark -r cap.pcap -Y 'mpls' -T fields -e mpls.label -e ip.dst | head
```

## Практика: разбор стека меток

```bash
# 1. Захватить MPLS-трафик
sudo tcpdump -i eth0 -nn -w mpls.pcap 'ether proto 0x8847'
# 2. Показать стек меток
tshark -r mpls.pcap -Y 'mpls' -V | grep -E "Label|Bottom of Stack|TTL" | head -20
# 3. Сопоставить внешнюю/внутреннюю метку
tshark -r mpls.pcap -T fields -e mpls.label | sort | uniq -c | sort -rn | head
```

Внешняя метка — транспорт до egress, внутренняя — VPN-идентификатор. Аномальная метка (не из диапазона провайдера) — признак инъекции.

## Защита

| Мера | Против чего |
|---|---|
| Корректные RT (import/export) | route leak |
| Аутентификация LDP/RSVP | поддельные привязки меток |
| Фильтрация MPLS на границе домена | инъекции извне |
| Раздельные VRF + ACL внутри | lateral movement |
| Мониторинг изменения таблиц меток | детект атак |
| Не тянуть MPLS до access-порта | поверхность атаки |

```text
# Cisco: ограничить распространение меток
mpls ldp router-id Loopback0
interface Gi0/1
 mpls ip
```

## Частые ошибки

- **Считать VRF полной изоляцией** — ошибки RT дают утечку.
- **Путать RD и RT** — первое уникализирует префикс, второе управляет импортом.
- **Игнорировать MPLS как «прозрачный»** — он меняет модель фильтрации.
- **Не аутентифицировать LDP** — привязки меток подделываются.
- **Смотреть только IP-заголовок** — метка вне IP.
- **Забывать про TTL в MPLS** — отдельное поле, может утекать.
- **Не мониторить стек меток** — инъекция невидима.

## Что дальше / решение

После MPLS/VRF вернитесь к [`network-module-routing`](network-module-routing) и [`network-bgp-hijack`](network-bgp-hijack) для внешней маршрутизации. Для сегментации — [`network-vlan-qinq`](network-vlan-qinq).

## Стек меток и TTL

В MPLS-метке есть поле **TTL**, которое работает независимо от IP-TTL. При инкапсуляции TTL копируется, при разинкапсуляции — возвращается. Аномалии TTL в метке — признак инъекции или петли.

| Поле метки | Биты | Смысл |
|---|---|---|
| Label | 20 | значение метки |
| EXP/TC | 3 | QoS (traffic class) |
| S | 1 | bottom of stack |
| TTL | 8 | время жизни |

```bash
# Показать метку и TTL
tshark -r mpls.pcap -Y 'mpls' -T fields -e mpls.label -e mpls.ttl | head
# Стек меток (несколько значений в одном кадре)
tshark -r mpls.pcap -T fields -e mpls.label | sort | uniq -c | sort -rn | head
```

## Лаборатория: MPLS на Linux

```bash
# Включить MPLS на интерфейсе
sudo modprobe mpls_router mpls_iptunnel
sudo sysctl -w net.mpls.platform_labels=100000
sudo ip link set dev eth0 up
sudo sysctl -w net.mpls.conf.eth0.input=1
# Добавить правило входа для метки
sudo ip -f mpls route add 100 via inet 10.0.0.2 dev eth0
# Посмотреть MPLS-маршруты
sudo ip -f mpls route show
```

На этом стенде удобно наблюдать swap меток и поведение TTL, а также воспроизводить инъекцию в чужой LSP.

## Чек-лист MPLS/VRF

1. Работает ли MPLS в сегменте (ethertype 0x8847/0x8848)?
2. Какие **метки** используются и есть ли аномальные?
3. Настроены ли **VRF** и корректны ли **RT** (import/export)?
4. Нет ли **утечек** маршрутов между VRF?
5. Аутентифицированы ли **LDP/RSVP**?
6. Фильтруется ли MPLS на **границе** домена?
7. Мониторятся ли **таблицы меток**?

```bash
# Быстрый снимок
tshark -r mpls.pcap -Y 'mpls' -T fields -e mpls.label | sort -u | head
ip route show vrf blue 2>/dev/null | head
```

Ключевая мысль: MPLS и VRF дают производительность и изоляцию, но изоляция держится на корректной конфигурации. Ошибка в RT или отсутствие фильтрации на границе превращают «непрозрачную» сеть в проходимую.

## Диагностика MPLS

```bash
# Linux: состояние MPLS-маршрутов и интерфейсов
ip -f mpls route show
ip -d link show | grep -i mpls
# На Cisco
# show mpls ldp neighbor
# show mpls forwarding-table detail
# show mpls interfaces
```

Типовые проблемы: **label mismatch** (метка не привязана), **LDP-сессия не поднялась** (нет связности по протоколу), **TTL propagation** выключен, **PHP** (penultimate hop popping) ломает ожидания.

## Сравнение сегментации L2 и L3

| Уровень | Технология | Единица изоляции |
|---|---|---|
| L2 | VLAN / PVLAN | broadcast-домен |
| L3 | VRF | таблица маршрутов |
| MPLS | L3VPN (VRF+метки) | VPN-инстанс |
| Оверлей | VXLAN/GRE | тенант |

Каждая технология изолирует по-своему, и каждая имеет свой класс ошибок/атак: VLAN hopping, route leak, label spoofing, оверлей-инъекции.

## Чек-лист: проверить изоляцию

```bash
# 1. Видны ли чужие префиксы изнутри своего VRF?
ip route show vrf blue | grep -v '10.0.0'
# 2. Есть ли утечка через статику/redistribute?
sudo vtysh -c 'show ip route vrf blue' 2>/dev/null | head
# 3. Мониторить аномальные метки
tshark -r mpls.pcap -T fields -e mpls.label | sort | uniq -c | sort -rn | head
```

Практический вывод: MPLS/VRF — мощная, но «тонкая» изоляция. Её надёжность определяется корректностью RT, аутентификацией LDP/RSVP и фильтрацией на границе домена. Без этого провайдерская сеть становится проходимой.

## Квиз

```quiz
- question: "По какому признаку коммутируется пакет в MPLS?"
  options:
    - "По метке фиксированной длины"
    - "По MAC"
    - "По IP"
    - "По порту TCP"
  answer: 0
  explanation: "MPLS использует 20-битную метку вместо анализа IP на каждом хопе."
- question: "Какой EtherType используется для unicast MPLS?"
  options:
    - "0x8847"
    - "0x8100"
    - "0x0800"
    - "0x8848"
  answer: 0
  explanation: "0x8847 — unicast MPLS, 0x8848 — multicast."
- question: "Что делает VRF?"
  options:
    - "Создаёт отдельную таблицу маршрутов/forwarding"
    - "Шифрует трафик"
    - "Сжимает пакеты"
    - "Назначает MAC"
  answer: 0
  explanation: "VRF изолирует маршруты (например, по клиентам)."
- question: "Что управляет импортом/экспортом маршрутов между VRF?"
  options:
    - "Route Target (RT)"
    - "Route Distinguisher (RD)"
    - "MTU"
    - "TTL"
  answer: 0
  explanation: "RT определяет, какие VRF обмениваются маршрутами; RD уникализирует префикс."
- question: "Какая атака даёт доступ к чужому VRF?"
  options:
    - "Route leak из-за неверных RT"
    - "SYN-флуд"
    - "DNS-туннель"
    - "ARP-спуфинг"
  answer: 0
  explanation: "Некорректные RT приводят к утечке маршрутов между клиентами."
```

## Где пригодится

- **CTF:** задачи с MPLS-метками и VRF.
- **Пентест:** поиск утечек между VRF, инъекции в LSP.
- **SOC:** детект аномальных меток и изменений таблиц.
- **Инженерия:** диагностика MPLS/LDP, корректные RT.
