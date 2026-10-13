---
id: network-dhcpv6
title: "DHCPv6 и SLAAC: назначение адресов, RA-атаки и rogue-сервер"
category: network
parent: network-ipv6
difficulty: medium
order: 1
tags: [network, dhcpv6, slaac, ipv6, ra, ndp, rogue]
prerequisites: [network-ipv6, network-module-ip]
useful_for:
  - "CTF Network (IPv6-конфигурация)"
  - "Пентест: rogue DHCPv6/RA, перехват IPv6"
  - "Работа (SOC): детект RA-спуфинга"
estimated_minutes: 55
summary: "Как IPv6 назначает адреса (SLAAC, DHCPv6, RA), чем опасны rogue DHCPv6 и RA-спуфинг, как подсунуть жертве свой DNS/шлюз и как защититься (RA Guard, DHCPv6 Guard)."
lab:
  kind: shell
  title: "Практика: DUID клиента в DHCPv6"
  toolset: [core, tshark]
  workdir: /home/student/task
  files: [task.md, dhcp6.pcap]
  check: "grep -q '0001000100000000001122334455' answer.txt"
  hints:
    - "DHCPv6 использует UDP/546 (клиент) и UDP/547 (сервер) поверх IPv6."
    - "Клиент идентифицируется через Client Identifier (DUID)."
    - "Искомый DUID — 14 байт: `0001000100000000001122334455`."
---

## Вопрос, с которого всё начинается

Ты на хосте в IPv6-сегменте, где админа никто не настраивал — адрес появился «сам». Откуда хост взял адрес, шлюз и DNS? И, что важнее для пентеста: кто ещё может ему эти параметры навязать?

В IPv6 адреса чаще всего назначаются **автоматически** — через SLAAC или DHCPv6. Оба механизма не аутентифицированы, поэтому атакующий в сегменте может объявить себя роутером и перенаправить весь трафик через себя.

## Наш пример: откуда у хоста адрес

Смотрим, что настроено:

```
$ ip -6 addr show dev eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet6 fe80::a00:27ff:fe4e:66a1/64 scope link
    inet6 2001:db8:1:1::a00:27ff:fe4e:66a1/64 scope global dynamic
       valid_lft 2591978sec preferred_lft 604778sec
$ ip -6 route show default
default via fe80::1 dev eth0 proto ra metric 100 expires 1790sec
```

Адрес помечен `dynamic`, а маршрут — `proto ra`. «ra» означает **Router Advertisement**: хост взял и адрес, и шлюз из объявления роутера, а не из конфига.

## Шаг 1: три способа получить IPv6-адрес

- **SLAAC** (Stateless Address Autoconfiguration) — хост сам формирует адрес из префикса RA + идентификатора интерфейса. Сервер не нужен.
- **DHCPv6 stateful** — сервер выдаёт адрес и параметры (DNS, домен).
- **DHCPv6 stateless** — адрес из SLAAC, а параметры (DNS) — по DHCPv6.

Выбор задаётся флагами в RA: **M** (managed — взять адрес по DHCPv6) и **O** (other — взять по DHCPv6 только параметры). Понять конфигурацию можно так:

```
$ ip -6 route show default
$ cat /etc/resolv.conf
```

## Шаг 2: Router Advertisement и Neighbor Discovery

RA-сообщения (ICMPv6 type 134) рассылаются на multicast `ff02::1` каждые ~200 секунд. Хост принимает RA и настраивает адрес и шлюз. **NDP** (Neighbor Discovery, ICMPv6 135/136) заменяет ARP: запрос «кто владеет этим IPv6» → ответ с MAC. Захватим RA:

```
$ sudo tcpdump -i eth0 -nn 'icmp6 and ip6[40]==134'
12:00:01.100 IP6 fe80::1 > ff02::1: ICMP6, router advertisement, length 64
```

## Шаг 3: rogue RA — становимся шлюзом

Раз RA от любого узла принимается без аутентификации, объявляем себя роутером:

```
$ sudo sysctl -w net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.forwarding = 1
$ sudo fake_router6 eth0 2001:db8:dead:beef::/64
```

Хосты перенастраивают маршрут по умолчанию через нас — полный MITM. Смотрим, что теперь идёт через нас:

```
$ sudo tcpdump -i eth0 -nn ip6 -c 3
12:01:10 2001:db8:1:1::cafe:1.44321 > 2001:db8:1:1::10.443: Flags [P.], length 220
```

## Шаг 4: rogue DHCPv6 и главный приз — DNS

Часто атакуют не ради адреса, а ради **DNS**. RDNSS-опция в RA или DHCPv6-опция 23 позволяют указать свой резолвер. Жертва начнёт резолвить имена через атакующего:

```
$ sudo dhcp6s -c /etc/dhcp6s.conf eth0
$ sudo tcpdump -i eth0 -nn 'udp port 546 or udp port 547'
12:02:00 IP6 fe80::a00:27ff:fe4e:66a1.546 > ff02::1:2.547: dhcp6 solicit
```

Дальше — DNS-спуфинг, перехват, туннелирование (см. [`network-dns-attacks`](network-dns-attacks)).

## Шаг 5: детект и защита

На стороне защиты аномалии видны по RA от незнакомых источников и rogue-серверам DHCPv6:

```
$ tshark -r cap.pcap -Y 'icmpv6.type==134' -T fields -e ipv6.src -e eth.src | sort | uniq -c | sort -rn
```

| Мера | Против чего |
|---|---|
| RA Guard на access-портах | rogue RA |
| DHCPv6 Guard | rogue DHCPv6 |
| ND Inspection / SAVI | NDP-спуфинг |
| Фильтрация ICMPv6 на хостах | поддельные RA/NDP |
| `accept_ra=0` на серверах | подмена маршрута |

```
$ sudo sysctl -w net.ipv6.conf.eth0.accept_ra=0
```

## SLAAC vs DHCPv6: когда что

| Свойство | SLAAC | DHCPv6 |
|---|---|---|
| Кто выдаёт адрес | хост сам (из RA) | сервер |
| Нужен сервер | нет | да |
| Аутентификация | нет | нет |
| DNS | RDNSS в RA | опция 23 |
| Учёт/аудит | нет | есть (lease) |
| Применение | клиентские сети | управляемые сети |

Часто используется гибрид: адрес по SLAAC, а DNS и домен — по DHCPv6 (stateless). Поэтому блокировка только DHCPv6 не спасает: RDNSS в RA всё равно прилетит.

## Ловушка гибридной конфигурации

Многие администраторы блокируют DHCPv6, считая, что «закрыли выдачу адресов». Но при гибриде адрес приходит по SLAAC, а DNS — опцией RDNSS прямо в RA. Блокировка DHCPv6 не мешает rogue RA подсунуть свой резолвер. Поэтому защищать нужно оба механизма одновременно: RA Guard на портах доступа и DHCPv6 Guard рядом. На серверах автонастройку по RA обычно отключают полностью, задавая маршрут и DNS статически.

## Практический чек-лист

1. Есть ли у хостов IPv6-адреса (`ip -6 addr`)?
2. Откуда приходят RA и какие в них RDNSS?
3. Кто отвечает на DHCPv6 — легитимный сервер или rogue?
4. Настроены ли RA Guard и DHCPv6 Guard на портах доступа?
5. Принимают ли серверы RA (`accept_ra`)?
6. Логируется ли смена маршрута/DNS по IPv6?

```
$ ip -6 addr show; ip -6 route show; ip -6 neigh show
$ sudo tcpdump -i eth0 -nn -c 20 'icmp6[icmp6type]==134 or udp port 547'
```

## Защита: что закрывать

- **RA Guard** на портах доступа — отбрасывает RA от недоверенных портов.
- **DHCPv6 Guard** — не пускает ответы rogue-серверов.
- **ND Inspection / SAVI** — против NDP-спуфинга.
- **Фильтрация ICMPv6** на хостах — против поддельных RA/NDP.
- `accept_ra=0` на серверах — не принимать подмену маршрута.

```
$ sysctl net.ipv6.conf.all.accept_ra
```

## Шаг 6: полный MITM по IPv6

Соберём атаку целиком. Цель — не просто стать шлюзом, а видеть и, при желании, менять трафик.

1. **Включаем forwarding** — иначе трафик через нас не пойдёт:
```
$ sudo sysctl -w net.ipv6.conf.all.forwarding=1
```
2. **Объявляем себя роутером** и заодно подсовываем свой DNS через RDNSS:
```
$ sudo fake_router6 eth0 2001:db8:dead:beef::/64
```
3. **Поднимаем свой DNS** и отвечаем на запросы жертвы — например, поддельным адресом для нужного домена:
```
$ sudo dnsspoof -i eth0 -f hosts.txt
```
4. **Смотрим перехваченный трафик** — незашифрованный HTTP или учётные данные:
```
$ sudo tcpdump -i eth0 -nn -A 'tcp port 80' -c 5
```

Ключевой момент: жертва не замечает подмены — маршрут и DNS «появились сами» из RA. Именно поэтому IPv6-MITM в неподготовленной сети проходит почти незаметно.

## Как детектить в PCAP

Защитнику важно ловить аномалии RA. Два практичных фильтра.

Считаем источники RA — их должно быть ровно столько, сколько легитимных роутеров:
```
$ tshark -r cap.pcap -Y 'icmpv6.type==134' -T fields -e ipv6.src | sort | uniq -c | sort -rn
     48 fe80::1
      3 fe80::dead:beef
```
Источник `fe80::dead:beef` с малым числом объявлений — rogue RA.

Смотрим, не приходит ли DNS (RDNSS) из неожиданного источника:
```
$ tshark -r cap.pcap -Y 'icmpv6.type==134 && icmpv6.opt.rdnss' -T fields -e ipv6.src -e icmpv6.opt.rdnss
```
Если RDNSS указывает на адрес, которого нет в инвентаре, — это попытка увести резолвинг.

## Если не сработало

- **Хосты не меняют маршрут.** Проверь, включён ли IPv6 на интерфейсе и принимают ли хосты RA (`accept_ra`). На серверах RA часто отключён — там вектор не сработает.
- **RA не доходит.** Multicast `ff02::1` может резаться на коммутаторе (RA Guard уже настроен). Тогда пробуй unicast-RA конкретному хосту.
- **Жертва не резолвит через тебя.** Проверь, что RDNSS реально попал в её конфиг (`resolvectl status`), а не перебит DHCPv4.
- **Трафик идёт мимо.** Убедись, что forwarding включён и IPv6-адрес шлюза совпадает с твоим `fe80::` на интерфейсе.

## Что мы теперь знаем

- IPv6 назначает адреса через SLAAC (из RA) или DHCPv6, без аутентификации.
- Флаги M и O в RA выбирают режим DHCPv6.
- Rogue RA делает атакующего шлюзом по умолчанию — MITM.
- Rogue DHCPv6 и RDNSS подсовывают свой DNS — часто это и есть цель.
- Защита: RA Guard, DHCPv6 Guard, ND Inspection, отключение `accept_ra` на серверах.
- Гибрид SLAAC+DHCPv6 (stateless) означает, что блокировка одного DHCPv6 не спасает: RDNSS придёт в RA.
- Детект rogue RA — подсчёт источников `icmpv6.type==134` и проверка RDNSS против инвентаря.
- Полный IPv6-MITM = forwarding + rogue RA + свой DNS.
- RA Guard/DHCPv6 Guard ставят на портах доступа, а не на транзитных.
- SLAAC не требует сервера: адрес формируется из префикса RA и идентификатора интерфейса.
- Флаг O в RA = взять только параметры (DNS) по DHCPv6, адрес — по SLAAC.
- NDP (135/136) заменяет ARP и тоже не аутентифицирован — его спуфинг ведёт к подмене соседа.

## Квиз

Проверь себя.

```quiz
- question: 'Что означает флаг M в Router Advertisement?'
  options:
    - 'Использовать DHCPv6 для получения адреса (managed)'
    - 'Только SLAAC'
    - 'Отключить IPv6'
    - 'Использовать DNS'
  answer: 0
  explanation: 'M (managed) указывает хосту взять адрес по DHCPv6.'
- question: 'Какой тип ICMPv6 используется для Router Advertisement?'
  options:
    - '134'
    - '135'
    - '136'
    - '133'
  answer: 0
  explanation: 'RA — ICMPv6 type 134; 133 — Router Solicitation.'
- question: 'Чем опасен rogue RA?'
  options:
    - 'Хосты перенастраивают маршрут через атакующего (MITM)'
    - 'Ускоряется сеть'
    - 'Отключается IPv4'
    - 'Меняется MAC'
  answer: 0
  explanation: 'Поддельный RA делает атакующего шлюзом по умолчанию.'
- question: 'Что чаще всего является целью rogue DHCPv6?'
  options:
    - 'Указать свой DNS (RDNSS/опция 23)'
    - 'Изменить MAC'
    - 'Отключить STP'
    - 'Сменить VLAN'
  answer: 0
  explanation: 'Контроль DNS даёт спуфинг и перехват имён.'
- question: 'Какая защита блокирует rogue RA на порту?'
  options:
    - 'RA Guard'
    - 'STP'
    - 'VTP'
    - 'DTP'
  answer: 0
  explanation: 'IPv6 RA Guard отбрасывает RA от недоверенных портов.'
```

## Куда дальше

Мы научились перенаправлять IPv6-трафик через rogue RA и DHCPv6. Дальше — как пронести IPv6 через IPv4-периметр с помощью переходных туннелей. А пока запомни: **в IPv6 конфигурация «по умолчанию» почти всегда доверяющая — значит, явная политика обязательна.**

## Где пригодится

- **CTF:** задачи с IPv6-конфигурацией и RA/NDP.
- **Пентест:** rogue RA/DHCPv6 для перехвата IPv6-трафика.
- **SOC:** детект поддельных RA и DHCPv6-серверов.
- **Инженерия:** RA Guard, DHCPv6 Guard, SAVI.
