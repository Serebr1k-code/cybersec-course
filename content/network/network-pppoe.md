---
id: network-pppoe
title: "PPPoE, PPTP и VPN-протоколы: инкапсуляция, аутентификация и слабости"
category: network
parent: network-routing-wan
difficulty: easy
order: 1
tags: [network, pppoe, pptp, vpn, ppp, authentication]
prerequisites: [network-tcpip]
useful_for:
  - "CTF Network (разбор инкапсуляции)"
  - "Пентест: анализ доступа провайдеров и удалённых сотрудников"
  - "Работа: разбор проблем VPN-доступа"
estimated_minutes: 35
summary: "Как устроены PPPoE, PPTP и родственные VPN-протоколы, чем опасна слабая аутентификация и как анализировать их трафик."
---

До повсеместного Ethernet поверх «последней мили» интернет-провайдеры выдавали доступ через PPPoE — PPP поверх Ethernet. Даже сегодня PPPoE живёт у многих провайдеров, а PPTP/L2TP/PPTP-наследие — в корпоративных VPN. Этот урок разбирает инкапсуляцию, фазы аутентификации и конкретные слабости, которые эксплуатируют пентестеры.

## Инкапсуляция: от Ethernet до PPP

PPPoE встраивает PPP-кадр внутрь Ethernet:

```
Ethernet | PPPoE header | PPP | PPP payload (IP)
```

- **PPPoE Discovery (PADI/PADO/PADR/PADS):** клиент ищет сервер доступа (AC), договариваются о Session ID.
- **PPPoE Session:** кадры несут PPP-инкапсуляцию с `Session ID`.
- **PPP:** содержит LCP (согласование параметров канала) и протоколы аутентификации (PAP/CHAP).

Стек: Ethernet → PPPoE → PPP → IP → TCP/UDP. Ошибка новичка — считать, что PPPoE это «просто Ethernet»: внутри есть фаза согласования и отдельная адресация.

## Аутентификация PPP: PAP и CHAP

| Метод | Как работает | Слабость |
|---|---|---|
| PAP | логин/пароль в открытом виде | перехват пароля из PCAP |
| CHAP | сервер шлёт challenge, клиент отвечает MD5(challenge+secret) | оффлайн-перебор ответа, MITM-релей |
| MS-CHAPv2 | вариант CHAP от Microsoft | известен разбор: по ответу восстанавливается NTLM-хэш пароля |

MS-CHAPv2 — классическая цель: из перехваченного handshake восстанавливается NT-хэш (атака «chapcrack»/«asleap»).

## PPTP, L2TP и точка зрения атакующего

- **PPTP:** PPP поверх GRE (IP-протокол 47) + управляющий канал TCP/1723. Исторически слаб: MS-CHAPv2 + слабое шифрование MPPE. Считается сломанным, но всё ещё встречается.
- **L2TP:** сам по себе не шифрует — обычно работает с IPsec (L2TP/IPsec). Слабость — в конфигурации PSK и аутентификации.
- **SSTP:** PPP поверх HTTPS (TCP/443) — обходит фильтрацию по портам, маскируется под обычный TLS.

Для атакующего важно: PPTP-туннель часто выглядит как GRE (не всегда фильтруется), а аутентификация даёт материал для оффлайн-атаки.

## Инструменты и команды

Захват и анализ:

```bash
# фильтр только PPPoE-сессий
tcpdump -i eth0 -nn 'pppoes'
tshark -r pppoe.pcap -Y 'ppp' -V | less
```

Подъём PPPoE-клиента (для лаборатории, с явным указанием интерфейса):

```bash
sudo pppoeconf            # интерактивно, для Debian-подобных
# либо через pppd с конфигом /etc/ppp/peers/dsl-provider
```

Перебор MS-CHAPv2-ответа:

```bash
# asleap по перехваченному challenge/response
asleap -C <challenge> -R <response> -W wordlist.txt
# chapcrack + hashcat для восстановления NT-хэша
chapcrack -f capture.pcap -o handshake.txt
hashcat -m 5500 handshake.txt wordlist.txt
```

## Разобранный пример: перехват PAP в открытой сети

Сценарий: в лабораторном сегменте клиент подключается к PPPoE-серверу с PAP.

1. Захватываем трафик на мосту: `tcpdump -i br0 -w pppoe.pcap 'pppoes'`.
2. Открываем в Wireshark, фильтр `ppp.protocol == 0xc023` (PAP) → видим кадр `Authenticate-Request`.
3. В поле `Peer-ID` и `Password` — логин и пароль **в открытом виде**.
4. Вывод: PAP непригоден в недоверенной сети; это прямой путь к компрометации учётной записи доступа.

С CHAP будет иначе: в кадре только challenge и хэш-ответ. Тогда путь — оффлайн-перебор или релей (поднять фальшивый AC и переслать challenge жертве).

## Защита

- **Отказ от PAP/MS-CHAPv2:** использовать только современные методы (EAP-TLS, PEAP с сертификатами).
- **IPsec для L2TP:** сильный PSK или сертификаты, отключение агрессивного режима.
- **Изоляция:** PPPoE только на портах доступа, фильтрация discovery на транзитных интерфейсах.
- **Мониторинг:** детект аномальных PPPoE discovery и GRE-туннелей на нестандартных портах.

## Частые ошибки

- **Считать PPTP безопасным.** Протокол сломан на уровне MS-CHAPv2 и MPPE — не используйте его.
- **Путать инкапсуляцию с шифрованием.** PPPoE/L2TP сами по себе не шифруют трафик.
- **Забывать про GRE.** PPTP легко блокируется фильтрацией IP-протокола 47 — учитывайте это при планировании.
- **Анализировать только TCP/1723.** Данные идут в GRE; без фильтра `pppoes`/`gre` вы их не увидите.

## Фазы PPPoE и PPP: что происходит до передачи данных

PPPoE — это не только инкапсуляция, а последовательность состояний. Понимание фаз объясняет, где перехватывать учётки и как ломается доступ.

1. **Discovery (PPPoE)**: клиент рассылает `PADI` (Active Discovery Initiation) broadcast'ом; серверы отвечают `PADO` (Offer); клиент выбирает и шлёт `PADR` (Request); сервер завершает `PADS` (Session-confirmation), выдавая `Session ID`. После этого кадры PPP идут уже в unicast с этим Session ID.
2. **LCP (PPP)**: согласование параметров канала — MRU, magic number, аутентификация, сжатие.
3. **Аутентификация**: PAP или CHAP (MS-CHAPv2) — именно здесь утекают креды.
4. **IPCP**: согласование IP-адресов и DNS (аналог DHCP внутри PPP).
5. **Data**: собственно IP-трафик.

```bash
# Разбор фаз в дампе (Wireshark-фильтры)
#   pppoed            -> только discovery (PADI/PADO/PADR/PADS)
#   pppoes            -> только сессия
#   ppp               -> PPP (LCP, PAP, CHAP, IPCP)
tshark -r pppoe.pcap -Y 'pppoed' -T fields -e pppoe.code -e pppoe.session_id | head
# pppoe.code: 0x09 PADI, 0x07 PADO, 0x19 PADR, 0x65 PADS
```

Ошибка новичка — смотреть только «есть ли PPPoE» и не различать discovery и сессию. Учётные данные находятся **не** в discovery, а в PPP-фазе аутентификации.

## PPPoE-сессия: MTU, MSS clamping и типичные сбои

PPPoE добавляет 8 байт заголовка (6 PPPoE + 2 PPP), поэтому полезный MTU уменьшается с 1500 до **1492**. Если этого не учесть, крупные пакеты с `DF`-флагом теряются — классическая проблема «сайты грузятся частично».

```bash
# Узнать MTU интерфейса PPPoE
ip link show ppp0
# Классический фикс на роутере/шлюзе: MSS clamping
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu
# Проверить PMTU (не пройдёт, если MTU завышен)
ping -M do -s 1472 8.8.8.8     # 1472 + 28 = 1500, для PPPoE нужно 1464
```

Сбои PPPoE обычно сводятся к: неверный MTU/MSS, обрыв сессии из-за отсутствия `lcp-echo` keepalive, несовпадение сервис-неймов (Service-Name) в PADI/PADO, дублирующиеся Session ID при проблемах на стороне AC.

## Атаки на PPPoE и PPP: hijack, sniff, relay, DoS

| Атака | Механика | Что нужно |
|---|---|---|
| PAP-сниффинг | пароль идёт открытым текстом | пассивный доступ к каналу |
| CHAP/MS-CHAPv2-перехват | challenge/response | MITM или зеркалирование |
| Session hijack | подмена Session ID/релей сессии | активная позиция на L2 |
| Rogue AC | фальшивый Access Concentrator | отвечает PADO быстрее легитимного |
| DoS | флуд PADI, истощение сессий | доступ к сегменту доступа |

**PAP** отдаёт пароль целиком. **MS-CHAPv2** — challenge/response, который можно перебрать оффлайн (hashcat `-m 5500`) или отрелеить, не зная пароля. **Rogue AC** (фальшивый сервер доступа) заставляет жертву подключиться к нему — тогда вы получаете и креды, и весь её трафик.

```bash
# Перехват PPPoE-трафика на мосту/порту доступа
tcpdump -i br0 -nn -w pppoe.pcap 'pppoes or pppoed'
# Извлечь PAP-учётки из дампа
tshark -r pppoe.pcap -Y 'ppp.protocol==0xc023' -T fields -e ppp.peer_id -e ppp.password
# MS-CHAPv2 -> hashcat (после chapcrack)
chapcrack -f pppoe.pcap -o hs.txt && hashcat -m 5500 hs.txt rockyou.txt
```

## Инструменты: rp-pppoe, pppd, Scapy, chapcrack

```bash
# Клиент PPPoE (Debian-подобные)
sudo pppoeconf                       # интерактивная настройка
sudo pon dsl-provider                # поднять соединение
sudo poff dsl-provider               # опустить
# Ручной pppd с конфигом /etc/ppp/peers/dsl-provider:
#   plugin rp-pppoe.so eth0
#   user "login@isp"  noauth  mtu 1492 mru 1492
#   persist  maxfail 0
# Разбор и кастомные пакеты (Scapy)
python3 -c "from scapy.all import PPPoE, PPP; print(PPPoE().show())"
# Перебор MS-CHAPv2
asleap -C <challenge> -R <response> -W wordlist.txt
```

| Инструмент | Роль | Ключевые флаги |
|---|---|---|
| pppoeconf / pon | поднять клиента | `-i` интерфейс, `persist` |
| pppd | демон PPP | `mtu/mru 1492`, `lcp-echo-interval` |
| tcpdump/tshark | анализ | `pppoes`, `pppoed`, `ppp` |
| chapcrack | извлечь handshake | `-f pcap -o out` |
| asleap | перебор CHAP | `-C`, `-R`, `-W` |
| Scapy | PoC/rogue | `PPPoE()`, `PPP()` |

## Сравнение PPPoE, PPTP, L2TP, SSTP и OpenVPN

| Протокол | Транспорт | Шифрование | Аутентификация | Статус |
|---|---|---|---|---|
| PPPoE | Ethernet (0x8863/0x8864) | нет (только PPP) | PAP/CHAP | доступ провайдера |
| PPTP | GRE(47)+TCP/1723 | MPPE (слабое) | MS-CHAPv2 | сломан |
| L2TP | UDP/1701 (+IPsec) | только с IPsec | PSK/cert | нужен IPsec |
| SSTP | TCP/443 (TLS) | TLS | cert | маскируется под HTTPS |
| OpenVPN | UDP/1194 или TCP/443 | TLS | cert/PSK | зрелый, гибкий |
| WireGuard | UDP | Noise (ChaCha20) | ключи | современный |

Вывод для практики: **PPTP не использовать**, **L2TP только с IPsec**, а для доступа — современные варианты (OpenVPN/WireGuard/SSTP) с сильной аутентификацией.

## OPSEC и защита доступа

- **Отказ от PAP и MS-CHAPv2** — только EAP-TLS/PEAP с сертификатами.
- **IPsec для L2TP** — сильный PSK или сертификаты, отключён aggressive mode.
- **Изоляция**: PPPoE только на портах доступа; discovery не пропускать на транзит.
- **Port security / 802.1X**: не давать постороннему хосту встать в сегмент доступа.
- **Мониторинг**: аномальные PADI-флуды, смена Session ID, появление второго AC.
- **MTU/MSS**: корректная настройка, чтобы не ломать крупные сессии.

```bash
# Проверить, что на порту доступа нет лишних PPPoE-серверов (в лаборатории)
sudo pppoe-discovery -I eth0     # слушает PADO от доступных AC
```

## Квиз

```quiz
- question: "Какой метод аутентификации PPP передаёт пароль в открытом виде?"
  options:
    - "CHAP"
    - "PAP"
    - "EAP-TLS"
    - "MS-CHAPv2"
  answer: 1
  explanation: "PAP передаёт логин и пароль открытым текстом; CHAP использует challenge/response."
- question: "Какой протокол используется для инкапсуляции данных PPTP?"
  options:
    - "GRE (IP-протокол 47)"
    - "TCP/443"
    - "UDP/500"
    - "IP-протокол 89"
  answer: 0
  explanation: "PPTP несёт PPP поверх GRE; управляющий канал — TCP/1723."
- question: "В чём слабость MS-CHAPv2, позволяющая атаку оффлайн?"
  options:
    - "Пароль передаётся в открытом виде"
    - "Из перехваченного challenge/response можно восстановить NT-хэш пароля"
    - "Используется слабый RC4 без ключа"
    - "Нет слабостей"
  answer: 1
  explanation: "По ответу на известный challenge восстанавливается NT-хэш, который затем перебирается оффлайн."
- question: "Что означает фаза PPPoE Discovery (PADI/PADO/PADR/PADS)?"
  options:
    - "Шифрование сессии"
    - "Поиск сервера доступа и согласование Session ID"
    - "Аутентификацию пользователя"
    - "Распределение IP через DHCP"
  answer: 1
  explanation: "Discovery — это поиск Access Concentrator и установка параметров сессии до передачи данных."
- question: "Какой VPN-протокол маскируется под обычный HTTPS на TCP/443?"
  options:
    - "PPTP"
    - "L2TP"
    - "SSTP"
    - "PPPoE"
  answer: 2
  explanation: "SSTP несёт PPP поверх TLS/HTTPS и потому проходит фильтрацию по портам."
```

## Где пригодится

- **CTF:** задачи на разбор инкапсуляции и восстановление учёток из PPPoE/PPP-трафика.
- **Пентест:** оценка доступа провайдера, анализ удалённого VPN-периметра.
- **Bug bounty:** чаще косвенно — при анализе сетевой инфраструктуры клиента.
- **Работа:** диагностика VPN-подключений и выбор безопасных методов аутентификации.
