---
id: network-vlan-qinq
title: "VLAN глубоко: 802.1Q, QinQ, double tagging и hopping"
category: network
parent: network-module-l2
difficulty: medium
order: 3
tags: [network, vlan, 802.1q, qinq, double-tagging, trunk, hopping]
prerequisites: [network-ethernet, network-module-l2]
useful_for:
  - "CTF Network (разбор VLAN-тегов)"
  - "Пентест: VLAN hopping, доступ к чужому сегменту"
  - "Работа (инженер): корректная настройка trunk/native VLAN"
estimated_minutes: 60
summary: "Как устроен 802.1Q, чем отличается access от trunk, как работает native VLAN, что такое QinQ и double tagging, как выполняется VLAN hopping и как от него защищаться."
---

VLAN — способ разделить один физический коммутатор на несколько логических сетей. Проблема в том, что разделение основано на теге в кадре, а тег можно подделать. Классический **VLAN hopping** позволяет прыгнуть в чужой сегмент, а **double tagging** — обойти изоляцию через native VLAN. Этот урок — часть модуля [`network-module-l2`](network-module-l2) и продолжает [`network-vlan-hopping`](network-vlan-hopping).

## Что такое VLAN и зачем она

VLAN (Virtual LAN) — логическая группа портов, образующая отдельный broadcast-домен. Зачем:

- **изоляция** — бухгалтерия и гости не видят друг друга;
- **сегментация** — меньше broadcast-шума, проще политика;
- **гибкость** — порт можно перекинуть в другую VLAN без перекоммутации;
- **безопасность** — VLAN не заменяет firewall, но уменьшает поверхность.

## Формат тега 802.1Q

Между `Src MAC` и `EtherType` вставляется 4-байтовый тег:

```text
+--------+--------+--------+-----------------+----------+------+
| Dst MAC| Src MAC| 0x8100 | TCI             | EtherType| Data |
+--------+--------+--------+-----------------+----------+------+
                           | PCP(3) | DEI(1) | VID(12)
```

- **PCP** (3 бита) — приоритет QoS (CoS).
- **DEI** (1 бит) — drop eligible.
- **VID** (12 бит) — идентификатор VLAN (0–4095; 0 и 4095 зарезервированы).

```bash
# Показать теги в дампе
sudo tcpdump -i eth0 -e -nn vlan
# Wireshark: фильтр vlan.id==100
```

## Access, trunk и native VLAN

- **Access-порт** — принимает/отдаёт кадры **без тега**; VLAN назначается портом. Конечное устройство обычно не знает о VLAN.
- **Trunk-порт** — несёт много VLAN, каждый кадр **с тегом**.
- **Native VLAN** — на trunk трафик **без тега** относится к native VLAN (по умолчанию VLAN 1). Это дыра: если native-тег можно подделать, кадр «перепрыгнет».

```text
Access:  [PC] --- untagged --- [switch port VLAN 10]
Trunk:   [switch] --- tagged(10,20,30) --- [switch]
Native:  untagged on trunk = VLAN 1 (по умолчанию)
```

## QinQ (802.1ad): два тега

**QinQ** («802.1ad», provider bridging) добавляет **второй** тег поверх первого. Используется у провайдеров: внутренний (customer) тег + внешний (service) тег. Кадр выглядит так:

```text
Dst | Src | 0x88A8 | S-TAG | 0x8100 | C-TAG | EtherType | Data
```

Двойное тегирование — основа **double tagging атаки**: первый (внешний) тег соответствует native VLAN, а внутренний — целевой VLAN. Промежуточный коммутатор снимает внешний тег и forward-ит кадр во внутреннюю VLAN.

## VLAN hopping: техника double tagging

Сценарий: атакующий в access-порту VLAN 10, хочет попасть в VLAN 20.

1. Формируется кадр с двумя тегами: внешний = **native VLAN** (например, 10), внутренний = **целевой** (20).
2. Первый коммутатор снимает внешний тег (native) и пересылает кадр по trunk.
3. Второй коммутатор видит внутренний тег 20 и доставляет в VLAN 20.

```bash
# Инструмент: yersinia (802.1Q double tagging) или scapy
python3 - <<'PY'
from scapy.all import *
pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/Dot1Q(vlan=10)/Dot1Q(vlan=20)/IP(dst="10.20.0.1")/ICMP()
sendp(pkt, iface="eth0")
PY
```

Ограничение: ответы обычно не возвращаются (односторонний канал) — но для инъекции этого хватает.

## Switch spoofing: стать trunk-портом

Второй вариант hopping — заставить порт перейти в **trunk** (DTP — Dynamic Trunking Protocol). Если порт настроен как `dynamic auto`/`dynamic desirable`, атакующий шлёт DTP-кадры и становится trunk, получая доступ ко всем VLAN.

```bash
# yersinia DTP-атака
sudo yersinia -I   # выбрать DTP -> enabling trunking
# Вручную смотреть DTP-кадры
sudo tcpdump -i eth0 -nn -e 'ether[20:2] == 0x2004'
```

## Разведка VLAN в сегменте

```bash
# 1. Захватить tagged-кадры
sudo tcpdump -i eth0 -nn -e vlan -c 20
# 2. Найти VLAN ID в дампе
tshark -r cap.pcap -Y vlan -T fields -e vlan.id | sort -u
# 3. Проверить native VLAN (untagged на trunk)
sudo tcpdump -i eth0 -nn -e 'not vlan and not arp' -c 10
```

## Защита

| Мера | Против чего |
|---|---|
| Явно задать native VLAN ≠ 1 и совпадающий на обоих концах | double tagging |
| Не использовать VLAN 1 для данных | hopping |
| Выключить DTP (`switchport nonegotiate`) | switch spoofing |
| Все неиспользуемые порты — в «мёртвую» VLAN и shutdown | доступ к порту |
| Port security + BPDU guard на access-портах | spoofing/BPDU |
| Не делать access-порт частью trunk | hopping |

```text
interface Gi0/1
 switchport mode access
 switchport access vlan 999
 switchport nonegotiate
 spanning-tree bpduguard enable
```

## Практика: разбор QinQ в Wireshark

```bash
# Фильтр по внешнему (S-TAG) и внутреннему (C-TAG) тегам
tshark -r qinq.pcap -Y 'vlan' -T fields -e vlan.id
# -> 10,20 (два тега в одном кадре)
```

Два `vlan.id` в одном кадре — прямой признак двойного тегирования, то есть либо QinQ, либо атака.

## Частые ошибки

- **Оставлять native VLAN = 1** — самый частый путь для hopping.
- **Путать QinQ и double tagging** — первое легитимно, второе атака.
- **Считать access-порт безопасным** — DTP может сделать его trunk.
- **Забывать про mismatch native VLAN** на концах trunk — утечка кадров.
- **Игнорировать PCP** — приоритет QoS можно использовать для манипуляций.
- **Не выключать DTP** — «dynamic auto» готов стать trunk.
- **Доверять 4095/0 как VLAN** — они зарезервированы и ведут себя особо.

## Что дальше / решение

Разобравшись с VLAN, переходите к [`network-lldp-cdp`](network-lldp-cdp) (разведка) и [`network-stp-deep`](network-stp-deep) (дерево). Для практических атак — [`network-vlan-hopping`](network-vlan-hopping) и [`network-layer2-attacks`](network-layer2-attacks).

## VTP и распространение VLAN

**VTP** (VLAN Trunking Protocol) синхронизирует список VLAN между коммутаторами. Режимы: Server (меняет и рассылает), Client (принимает), Transparent (локально). Опасность: сервер VTP может **удалить** VLAN во всём домене. Атакующий, ставший VTP-сервером с высоким revision number, способен обнулить конфигурацию VLAN всей сети.

```bash
# Посмотреть VTP-объявления
sudo tcpdump -i eth0 -nn -e 'ether[20:2] == 0x2003'
# Cisco: статус VTP
# show vtp status
```

## Приватные VLAN (PVLAN)

**PVLAN** делят VLAN на изолированные и community-порты внутри одного сегмента: хосты в isolated VLAN не видят друг друга даже при общей подсети. Это защита от lateral movement. Нарушение PVLAN (например, через promiscuous-порт) — отдельный класс атак.

```text
vlan 100
 private-vlan primary
 private-vlan association 101,102
vlan 101
 private-vlan isolated
vlan 102
 private-vlan community
```

## Голосовой VLAN и QoS

IP-телефония использует отдельный **voice VLAN** и тег с высоким **PCP** (CoS 5). Телефон сам тегирует трафик, а к нему подключается ПК (через встроенный коммутатор телефона). Классический вектор: занять порт телефона и получить доступ к voice VLAN, где часто слабее контроль.

```bash
# Захватить голосовой трафик (RTP/VoIP) и теги
sudo tcpdump -i eth0 -nn -e vlan and udp portrange 16384-32767 -c 20
```

## Проверка конфигурации VLAN с хоста

```bash
# Список VLAN-интерфейсов и их состояние
ip -d link show type vlan
# Проверить, приходит ли untagged (native) трафик
sudo tcpdump -i eth0 -nn -e 'not vlan and icmp' -c 5
# Определить, есть ли доступ к чужой подсети через hopping
ping -c 1 -W 1 10.20.0.1
```

## Модель угроз: что реально работает

| Атака | Требует | Эффект |
|---|---|---|
| Double tagging | native VLAN = целевой | односторонняя инъекция |
| DTP switch spoofing | порт dynamic auto/desirable | стать trunk, видеть все VLAN |
| VTP server hijack | отсутствие пароля/domain | перестройка VLAN |
| PVLAN bypass | promiscuous-порт | lateral внутри сегмента |
| VLAN 1 abuse | данные в VLAN 1 | доступ к управлению |

Понимание этих условий помогает и атаковать, и защищаться: почти все векторы закрываются конфигурацией (nonegotiate, нестандартная native VLAN, VTP-пароль, отключение VLAN 1 для данных).

## Квиз

```quiz
- question: "Какой EtherType используется для 802.1Q-тега?"
  options:
    - "0x8100"
    - "0x0800"
    - "0x0806"
    - "0x86DD"
  answer: 0
  explanation: "0x8100 указывает на VLAN-тег 802.1Q."
- question: "Что такое native VLAN на trunk-порту?"
  options:
    - "VLAN для трафика без тега"
    - "VLAN для голоса"
    - "VLAN управления"
    - "Резервная VLAN"
  answer: 0
  explanation: "Untagged-трафик на trunk относится к native VLAN."
- question: "На чём основана атака double tagging?"
  options:
    - "Внешний тег = native VLAN, внутренний = целевой VLAN"
    - "Отправка двух ARP-ответов"
    - "Подмена DNS"
    - "Отключение STP"
  answer: 0
  explanation: "Промежуточный коммутатор снимает внешний (native) тег и доставляет внутренний."
- question: "Каким протоколом порт можно заставить стать trunk?"
  options:
    - "DTP"
    - "STP"
    - "LLDP"
    - "DHCP"
  answer: 0
  explanation: "Dynamic Trunking Protocol договаривается о режиме trunk."
- question: "Какая защита против VLAN hopping?"
  options:
    - "Выключить DTP и сменить native VLAN"
    - "Включить IPv6"
    - "Использовать VLAN 1"
    - "Отключить ARP"
  answer: 0
  explanation: "nonegotiate + нестандартная native VLAN закрывают классические векторы."
```

## Где пригодится

- **CTF:** дампы с VLAN-тегами, поиск ID и QinQ.
- **Пентест:** VLAN hopping для доступа к изолированному сегменту.
- **SOC:** детект DTP-кадров и двойного тегирования.
- **Инженерия:** корректная настройка trunk, native VLAN, port security.
