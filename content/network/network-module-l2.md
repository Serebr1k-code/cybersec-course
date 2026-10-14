---
id: network-module-l2
title: "Канальный уровень глубоко: кадры, VLAN, STP и discovery"
category: network
parent: network-vlan-hopping
difficulty: easy
order: 1
tags: [network, l2, ethernet, vlan, stp, lldp, cdp, switching]
prerequisites: [network-layer2-attacks, network-vlan-hopping]
useful_for:
  - "CTF Network (анализ L2-трафика)"
  - "Пентест внутренней сети: доступ к порту коммутатора"
  - "Работа (SOC/инженер): чтение коммутационной топологии"
estimated_minutes: 60
summary: "Модуль про канальный уровень: кадр Ethernet, VLAN (802.1Q/QinQ), STP/RSTP/MSTP и протоколы обнаружения LLDP/CDP — как читать L2 и где искать слабости."
lab:
  kind: shell
  title: "Практика: разбираем L2-кадры из порта"
  toolset: [core, tshark]
  workdir: /home/student/task
  files: [task.md, l2.pcap]
  check: "grep -q 'nto{l2_0ld_sw1tch_1s_0wn3d}' answer.txt"
  hints:
    - "Начни со сводки дампа: `tshark -r l2.pcap -nn`."
    - "Один из кадров — служебный LLDP от коммутатора `core-sw-1` (ethertype 0x88cc)."
    - "Разбери поля LLDP: `tshark -r l2.pcap -Y lldp -T fields -e lldp.tlv.system.name -e lldp.tlv.system.desc`."
    - "Метка лежит в System Description: `nto{l2_0ld_sw1tch_1s_0wn3d}`."
---

## Вопрос, с которого всё начинается

Ты подключился к свободному порту в офисе и хочешь понять, **куда попал**: какой это сегмент, какие VLAN, какие коммутаторы рядом. Весь этот мир живёт **до IP** — на канальном уровне (L2). Большинство «сетевых» атак на внутреннем периметре начинается именно здесь: ARP-спуфинг, переполнение CAM-таблицы, захват корневого моста STP, двойное тегирование VLAN.

Этот модуль — про то, как читать L2-трафик. Он опирается на [`network-layer2-attacks`](network-layer2-attacks) и [`network-vlan-hopping`](network-vlan-hopping) и ведёт к [`network-ethernet`](network-ethernet), [`network-stp-deep`](network-stp-deep), [`network-vlan-qinq`](network-vlan-qinq) и [`network-lldp-cdp`](network-lldp-cdp).

## Наш пример: что видно из порта

Втыкаем кабель и смотрим первые кадры с MAC-адресами и типами:

```
$ sudo tcpdump -i eth0 -e -nn -c 4
16:20:01 12:34:56:aa:bb:cc > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42
16:20:01 12:34:56:dd:ee:ff > 01:80:c2:00:00:00, ethertype LLDP (0x88cc), length 86
16:20:02 12:34:56:aa:bb:cc > 12:34:56:dd:ee:ff, ethertype IPv4 (0x0800), length 74
16:20:02 12:34:56:dd:ee:ff > 12:34:56:aa:bb:cc, ethertype 802.1Q (0x8100), length 78
```

Здесь сразу видно три вещи: широковещательный **ARP** (`ff:ff:ff:ff:ff:ff`), кадр **LLDP** — сеть сама о себе рассказывает, и кадр с тегом **802.1Q** (`0x8100`), то есть VLAN. Разберём каждую.

## Шаг 1: кадр Ethernet

Классический кадр Ethernet II выглядит так:

```
+----------------+----------------+--------+-------------------------+-------+
| Dst MAC (6)    | Src MAC (6)    | Type   | Payload (46-1500)       | FCS 4 |
+----------------+----------------+--------+-------------------------+-------+
```

- **Dst MAC** — кому; `ff:ff:ff:ff:ff:ff` — broadcast;
- **Src MAC** — от кого; по нему коммутатор **учится**;
- **Type** — `0x0800` (IPv4), `0x0806` (ARP), `0x86DD` (IPv6), `0x8100` (VLAN), `0x8847` (MPLS);
- **FCS** — контрольная сумма; битые кадры коммутатор молча дропает.

Минимальный кадр — 64 байта, максимальный полезный размер — 1500 байт (**MTU**).

## Шаг 2: как коммутатор принимает решения

Коммутатор хранит **CAM-таблицу** (Content-Addressable Memory): MAC → порт → возраст. Алгоритм:

1. Пришёл кадр — запомнить `Src MAC` и порт входа (**learning**).
2. Посмотреть `Dst MAC`: есть в таблице → отправить в один порт (**forward**); нет → разослать во все порты кроме входного (**flood**, unknown unicast); broadcast/multicast → flood всегда.
3. Если Dst MAC = порт входа → **drop**.

Эта модель — корень L2-атак: если переполнить CAM-таблицу, коммутатор «поплывёт» и начнёт flood-ить всё, превращаясь в hub — тогда снифер видит чужой трафик.

```
$ bridge fdb show br0 | head
12:34:56:aa:bb:cc dev eth0 master br0
12:34:56:dd:ee:ff dev eth1 master br0
```

CAM-запись живёт ограниченное время (ageing, обычно 300 секунд). Тихий хост из таблицы выпадает, и трафик к нему временно флудится — шанс для снифера.

## Шаг 3: VLAN — логическая сегментация

**VLAN** делит один физический коммутатор на несколько логических L2-доменов. Кадры между VLAN не ходят без L3-устройства. Тегирование — стандарт **802.1Q**: в кадр добавляется тег `0x8100` с 12-битным идентификатором VLAN.

- **Access-порт** — трафик без тега (VLAN назначается портом);
- **Trunk-порт** — несёт несколько VLAN с тегами;
- **Native VLAN** — на trunk-порту трафик без тега; классический вектор атаки, если native не совпадает.

```
$ sudo ip link add link eth0 name eth0.100 type vlan id 100
$ sudo ip link set eth0.100 up
$ tcpdump -i eth0 -e -nn vlan
16:21:10 12:34:56:dd:ee:ff > 12:34:56:aa:bb:cc, ethertype 802.1Q (0x8100), vlan 100, length 78
```

Двойное тегирование (**QinQ**, 802.1ad) добавляет второй тег — подробности в [`network-vlan-qinq`](network-vlan-qinq).

## Шаг 4: STP — защита от петель

У коммутаторов нет TTL: кадр в петле зацикливается навсегда и убивает сеть (**broadcast storm**). **Spanning Tree Protocol** строит дерево без петель: выбирается **Root Bridge** (по минимальному Bridge ID), каждый коммутатор выбирает **Root Port** и блокирует избыточные порты. Служебные кадры **BPDU** ходят каждые 2 секунды.

| Протокол | Сходимость | Особенности |
|---|---|---|
| STP (802.1D) | 30–50 с | один инстанс, медленно |
| RSTP (802.1w) | < 1 с | быстрые роли, edge-порты |
| MSTP (802.1s) | < 1 с | несколько инстансов |
| PVST+ | < 1 с | по инстансу на VLAN (Cisco) |

Атака: вбросить BPDU с минимальным priority и стать корнем — трафик пойдёт через атакующего. Подробно — в [`network-stp-deep`](network-stp-deep).

## Шаг 5: LLDP и CDP — сеть рассказывает о себе

- **LLDP** (802.1AB) — вендоронезависимый: отправляет имя устройства, порт, VLAN, capabilities.
- **CDP** (Cisco) — проприетарный аналог, болтливый: модель, версия IOS, management IP, native VLAN.

Оба — «золото» для разведки и одновременно утечка. В нашем первом дампе был именно LLDP-кадр (`0x88cc`):

```
$ sudo tcpdump -i eth0 -nn -v -c 5 'ether proto 0x88cc or ether proto 0x2000'
16:20:01 LLDP, length 86
    System Name TLV: SW-CORE-01
    Port Description TLV: GigabitEthernet1/0/12
    Management Address TLV: 10.0.0.254
```

За один кадр мы узнали имя коммутатора, номер порта и management-адрес. Подробности — в [`network-lldp-cdp`](network-lldp-cdp).

## Инструмент: tshark — Wireshark в консоли

`tshark` — это Wireshark без графики: он читает дамп (`-r файл.pcap`) и печатает ровно то, что ты попросишь. Главный инструмент, когда графической оболочки нет или разбор надо автоматизировать.

Ключи, которые пригодятся:
* `-r <файл.pcap>` — читать дамп (без него tshark слушает живой интерфейс);
* `-nn` — не резолвить имена/порты: видно «как есть» и быстрее;
* `-Y '<фильтр>'` — display-фильтр, оставить только нужные пакеты (`http.request`, `dns`, `eapol`, `ospf`);
* `-T fields -e <поле>` — вместо сводки печатать значения полей (`-e ip.src -e tcp.dstport -e http.host`);
* `-q -z follow,tcp,ascii,N` — собрать TCP-поток номер N и показать его как текст.

### Рабочий пример (как в лаборатории)

```
$ tshark -r l2.pcap -Y vlan -T fields -e vlan.id -e ip.src -e tcp.dstport
100	10.0.0.5	445
```

Подсказка из лаборатории: `tshark -r <pcap> [-nn] [-Y фильтр] [-T fields -e поле…] — разбор дампа (реальный вывод tshark)`.

## Что мы теперь знаем

- Кадр Ethernet адресуется по MAC; коммутатор учится по адресу источника и пересылает по назначению.
- CAM-таблица стареет; переполнение превращает коммутатор в hub.
- VLAN (802.1Q, тег `0x8100`) делит коммутатор на сегменты; native VLAN — вектор атаки.
- STP строит дерево без петель; поддельный BPDU делает тебя корнем.
- LLDP/CDP раскрывают топологию, порты и адреса.

## Если защита мешает

- **Port security.** Привязка MAC↔порт режет подмену MAC и переполнение.
- **BPDU guard / root guard.** Не дают вбросить BPDU и стать корнем.
- **DHCP snooping / dynamic ARP inspection.** Ловят rogue DHCP и ARP-спуфинг.
- **Отключён LLDP/CDP на абонентских портах.** Топология не утекает — разведка труднее.
- **Storm control.** Всплеск broadcast гасится на порту (иногда с err-disable).

<!-- lab -->

## Практика: чтение L2-сегмента

```
$ sudo arp-scan --interface=eth0 --localnet
$ bridge fdb show br0 | head
$ tcpdump -i eth0 -e -nn vlan | head
$ sudo tcpdump -i eth0 -nn -v -c 20 'ether proto 0x88cc or ether proto 0x2000'
$ tcpdump -i eth0 -nn 'broadcast' -c 100 | wc -l
```

Первая команда находит хосты в сегменте, вторая показывает MAC-таблицу, третья — VLAN-теги, четвёртая — топологию через LLDP/CDP, последняя — оценивает уровень broadcast (признак петли или шторма). Читать L2-дамп удобнее в Wireshark: он раскрывает VLAN-теги, LLDP-TLV и STP-поля человекочитаемо.

## Квиз

Проверь себя.

```quiz
- question: 'По какому полю кадра коммутатор обучает CAM-таблицу?'
  options:
    - 'Src MAC'
    - 'Dst MAC'
    - 'Type'
    - 'FCS'
  answer: 0
  explanation: 'Коммутатор запоминает, с какого порта пришёл кадр, по адресу источника.'
- question: 'Что означает тег 0x8100 в поле Type?'
  options:
    - 'Кадр инкапсулирован по 802.1Q (VLAN)'
    - 'Это IPv6'
    - 'Это ARP'
    - 'Это MPLS'
  answer: 0
  explanation: '0x8100 — ethertype VLAN-тега 802.1Q.'
- question: 'Почему переполнение CAM-таблицы опасно?'
  options:
    - 'Коммутатор начинает flood-ить неизвестный трафик во все порты'
    - 'Сеть становится быстрее'
    - 'Отключается IPv6'
    - 'Пропадает DNS'
  answer: 0
  explanation: 'Без записей коммутатор ведёт себя как hub и рассылает трафик всем.'
- question: 'Какой протокол строит дерево без петель?'
  options:
    - 'STP'
    - 'LLDP'
    - 'CDP'
    - 'DHCP'
  answer: 0
  explanation: 'Spanning Tree Protocol блокирует избыточные порты.'
- question: 'Чем LLDP полезен при разведке?'
  options:
    - 'Раскрывает топологию, порты и VLAN соседних устройств'
    - 'Шифрует трафик'
    - 'Назначает IP-адреса'
    - 'Строит дерево STP'
  answer: 0
  explanation: 'LLDP/CDP сообщают соседям идентификацию и возможности порта.'
```

## Куда дальше

Мы научились читать L2-сегмент. Дальше — четыре практических урока: [`network-ethernet`](network-ethernet) разберёт кадр и MAC-адресацию, [`network-stp-deep`](network-stp-deep) — захват корневого моста, [`network-vlan-qinq`](network-vlan-qinq) — 802.1Q и QinQ, [`network-lldp-cdp`](network-lldp-cdp) — разведку топологии. А пока запомни: **коммутатор учится по источнику и пересылает по назначению — и вся L2-атака начинается с этой модели.**

## Где пригодится

- **CTF:** задачи с дампами L2-трафика, VLAN-тегами и STP.
- **Пентест:** вход во внутреннюю сеть, разведка коммутационной топологии.
- **SOC/IR:** детект ARP-спуфинга, MAC-flooding, поддельных BPDU.
- **Инженерия:** диагностика петель, native VLAN и port-security.
