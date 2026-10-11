---
id: network-tor
title: "Tor и анонимизирующие сети: как работает и как анализировать"
category: network
parent: network-anonymity
difficulty: medium
order: 1
tags: [network, tor, anonymity, onion, covert]
prerequisites: [network-covert, network-tls-inspection]
useful_for:
  - "CTF Network (анонимность, onion)"
  - "Пентест: обход и анализ анонимизации"
  - "Работа (SOC): детект и политика Tor"
estimated_minutes: 50
summary: "Как Tor обеспечивает анонимность (цепи, onion-сервисы), что видно в трафике и как с ним работать в пентесте и защите."
---

Tor — сеть для анонимизации трафика, маршрутизирующая его через несколько узлов с многослойным шифрованием («луковица»). В пентесте он нужен для обхода блокировок и скрытого доступа к внутренним сервисам (onion), в защите — как источник трафика, который надо детектировать и контролировать. Урок опирается на [`network-covert`](network-covert) и [`network-tls-inspection`](network-tls-inspection).

## Как работает Tor

- **Цепь (circuit)** из трёх узлов: **Guard** (входной), **Middle** (средний), **Exit** (выходной).
- Каждый узел снимает свой слой шифрования — отсюда «луковица».
- **Guard** знает ваш IP, но не назначение. **Exit** знает назначение, но не ваш IP.
- **Onion-сервисы** (`.onion`) не используют exit: обе стороны встречаются внутри сети Tor (rendezvous point), анонимны и клиент, и сервис.

```text
Вы --TLS--> Guard --TLS--> Middle --TLS--> Exit --plain--> Сайт
   (каждый знает только соседей)
```

## Что видно в трафике

- **На проводе** — только TLS-соединение к Guard-узлу (порт 9001/443). Содержимое и назначение скрыты.
- **Трафик к relay-узлам** — характерные размеры (512-байтовые ячейки) и постоянный поток.
- **Публичный список** relay-узлов — в **consensus** (можно скачать и сопоставить IP).

```bash
# Скачать консенсус (список узлов)
curl -s https://onionoo.torproject.org/summary | head -c 300
# Сопоставить IP из трафика с relay
curl -s "https://onionoo.torproject.org/details?search=203.0.113.5" | head
```

## Инструменты и команды

```bash
# Проверить, тор ли это (простой чек-лист через exit-адреса)
curl -s https://check.torproject.org/api/ip
# Использовать Tor как прокси (SOCKS5 на 9050)
tor &
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/
proxychains4 -q nmap -sT -Pn example.com
# Мосты (обход блокировки)
# /etc/tor/torrc:
#   UseBridges 1
#   Bridge obfs4 <ip:port> <fingerprint>
```

**Onion-сервисы**:

```bash
# /etc/tor/torrc:  HiddenServiceDir /var/lib/tor/myservice/
#                   HiddenServicePort 80 127.0.0.1:8080
# после запуска адрес в HiddenServiceDir/hostname
curl --socks5-hostname 127.0.0.1:9050 http://<addr>.onion/
```

## Разобранный пример: доступ к внутреннему сервису через Tor

```bash
# 1. Поднять Tor
tor &
# 2. Проверить цепь
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# 3. Доступ к onion-сервису
curl --socks5-hostname 127.0.0.1:9050 -sI http://exampleonionaddress.onion/
# 4. Сквозь Tor — к обычному сайту (для обхода геоблокировки)
curl --socks5-hostname 127.0.0.1:9050 https://target.example/
# 5. В CTF: часто нужно найти .onion-адрес в артефактах, затем зайти
```

## Детект и политика (для SOC)

- **Блокировка** известных relay-узлов по IP/consensus (список обновляется).
- **Traffic analysis**: характерный TLS-паттерн к 9001/443, 512-байтовые ячейки.
- **DNS**: запросы `.onion` (если приложение резолвит их) — прямой индикатор.
- **DLP/прокси** с блокировкой Tor + мониторинг **bridges** (obfs4/meek — сложнее).
- **Утечки**: приложение, резолвящее DNS напрямую (не через Tor), деанонимизирует активность.

## Частые ошибки

- **Думать, что Tor = полная анонимность** — DNS-утечки, fingerprinting, вход в те же аккаунты деанонимизируют.
- **Использовать Tor без мостов в цензурируемой сети** — соединение к Guard блокируется.
- **Путать relay и exit** — exit-узлы видны как источник трафика.
- **Игнорировать consensus** — без него не сопоставить IP и узел.
- **Ожидать высокой скорости** — Tor медленный, это цена анонимности.
- **Забывать про `.onion` в DNS-логах** — частый индикатор.

## Onion-сервисы: детали

- Адрес `.onion` — производная от публичного ключа (base32), версия 3 — 56 символов.
- **Rendezvous point** соединяет клиента и сервис; ни один из них не знает IP другого.
- Сервис публикует **descriptor** в распределённой hash-таблице (HSDir).
- **Onion v2** (16 символов) устарел/отключён; v3 — стандарт.

```bash
# Поднять свой onion-сервис
# /etc/tor/torrc:
#   HiddenServiceDir /var/lib/tor/hs/
#   HiddenServicePort 80 127.0.0.1:8080
sudo systemctl restart tor
sudo cat /var/lib/tor/hs/hostname     # ваш .onion-адрес
```

## Мосты и обход цензуры

Когда соединения к Guard-узлам блокируются, используют **bridges**:

```bash
# /etc/tor/torrc
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
Bridge obfs4 <ip:port> <fingerprint> cert=<...> iat-mode=0
# Или meek (маскируется под Azure/CDN)
ClientTransportPlugin meek_lite exec /usr/bin/obfs4proxy
Bridge meek_lite 192.0.2.2:443 url=https://meek.azureedge.net/
```

**obfs4** делает трафик неотличимым от случайного; **meek** — от HTTPS к CDN.

## Атаки на анонимность

- **Correlation attacks**: контроль входа и выхода позволяет сопоставить поток.
- **Fingerprinting**: анализ размеров/таймингов выдаёт посещённый сайт.
- **Application leaks**: приложение, обращающееся к сети напрямую (не через SOCKS), деанонимизирует.
- **DNS leaks**: резолв вне Tor.
- **Bad apple relay**: злонамеренный exit подменяет контент (без HSTS/подписи).

## Практический чек-лист

- [ ] `check.torproject.org` подтверждает использование Tor
- [ ] DNS не утекает (проверить через `tcpdump` на интерфейсе)
- [ ] Приложение полностью проксировано (SOCKS5h для DNS)
- [ ] Для цензуры — мосты obfs4/meek
- [ ] Не логиниться в личные аккаунты через Tor
- [ ] Понимать, что Tor не делает вас невидимым для корреляционных атак

## Построение цепи: guard-узлы и почему их нельзя менять часто

Tor выбирает три узла по консенсусу — документу, который Directory Authority подписывают каждый час. Выбор подчинён правилам:

- **Guard** (входной) выбирается на **длительный срок** (месяцы) и хранится в `state` — это защита от атак, где противник подставляет свои входные узлы. Частая смена guard'а облегчила бы корреляцию.
- **Middle** — случайный узел, обеспечивающий слой анонимности.
- **Exit** — выбирается по **exit-policy**; узел может разрешать не все порты. Именно exit видит открытый трафик к назначению.

```bash
# Посмотреть свою цепь и guard (клиент Tor)
# в torrc:  ControlPort 9051  + аутентификация
echo -e 'AUTHENTICATE ""\r\nGETINFO circuit-status\r\nQUIT' | nc 127.0.0.1 9051
# Скачать консенсус и найти узлы
curl -s https://onionoo.torproject.org/details | python3 -c \
  'import sys,json; [print(r["nickname"], r.get("or_addresses",["?"])[0], r["flags"]) for r in json.load(sys.stdin)["relays"][:10]]'
```

**Path bias** — уязвимость: если противник контролирует guard, он видит, что клиент использует Tor, и может коррелировать потоки. Поэтому guard-узлы должны быть стабильными и хорошо проверяемыми по bandwidth-авторитету.

## Onion-сервисы v3: descriptor, HSDir и rendezvous

Onion v3-адрес — это base32 от публичного ключа ed25519, 56 символов, заканчивается на `.onion`. Публикация и подключение:

1. Сервис строит **descriptor** (список introduction points) и публикует его в **HSDir** — распределённой хэш-таблице из узлов, выбранных по времени (blinded key меняется раз в сутки).
2. Клиент скачивает descriptor, выбирает introduction point и через него передаёт сервису «одноразовый» **rendezvous cookie**.
3. Обе стороны строят цепь к **rendezvous point** и встречаются там — ни клиент, ни сервис не знают IP друг друга.

```bash
# Поднять свой onion-сервис v3
cat >> /etc/tor/torrc <<'EOF'
HiddenServiceDir /var/lib/tor/hs/
HiddenServicePort 80 127.0.0.1:8080
EOF
sudo systemctl restart tor
sudo cat /var/lib/tor/hs/hostname        # ваш 56-символьный .onion
sudo cat /var/lib/tor/hs/hs_ed25519_public_key
```

**Onion v2** (16 символов, SHA1) полностью отключён с 2021 года — если в задаче встречается v2-адрес, он нерабочий и, скорее всего, указывает на устаревший артефакт. v3 даёт криптографически стойкий адрес и защиту от impersonation.

## Инструменты: torsocks, proxychains, onion-поиск

```bash
# Прозрачно прогнать произвольную программу через Tor
torsocks curl https://check.torproject.org/api/ip
torsocks ssh user@example.onion       # SSH к onion-сервису
# proxychains (SOCKS5 через Tor)
proxychains4 -q nmap -sT -Pn -p80,443 target.onion
# Проверить цепь и флаг Tor
curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
# {"IsTor":true,"IP":"185.220.x.x"}
# Поднять relay (не exit) — вклад в сеть без риска для себя
# torrc: ORPort 9001, Nickname MyRelay, ContactInfo, ExitRelay 0
```

Для OSINT-разведки onion-ресурсов используют каталоги (Ahmia, dark.fail и др.), но помните: доступ к onion — это **одно из действий**, а не гарантия анонимности. Если вы входите в личный аккаунт через Tor, корреляция и fingerprinting легко вас деанонимизируют.

## Атаки на анонимность: корреляция и фингерпринтинг

| Атака | Механика | Что нужно противнику |
|---|---|---|
| End-to-end correlation | сопоставить вход и выход по таймингам/объёму | контроль обоих концов цепи |
| Website fingerprinting | классификация сайта по паттерну ячеек | пассивный наблюдатель у клиента |
| Application/DNS leak | приложение ходит в сеть мимо SOCKS | невнимательный клиент |
| Exit-node подмена | exit отдаёт изменённый контент | контроль exit + отсутствие HSTS/подписи |
| Guard discovery | заставить клиента использовать свой guard | эксплуатация уязвимости/DoS |

```bash
# Проверить DNS-утечку: DNS-запросы НЕ должны уходить напрямую
sudo tcpdump -i eth0 -n 'udp port 53' &
curl --socks5-hostname 127.0.0.1:9050 https://example.com
# если в tcpdump видны запросы к 8.8.8.8 — утечка (нужен socks5h)
```

Ключевой принцип: Tor защищает **транспортную** анонимность (кто↔куда на сетевом уровне), но не защищает от утечек на уровне приложения и не делает вас невидимым для глобального наблюдателя.

## Детект Tor в корпоративной сети (для SOC)

- **Список relay-узлов** — из консенсуса/Onionoo; блокировка по IP эффективна против публичных узлов, но не против мостов.
- **Характерный паттерн**: TLS к портам 9001/9030/443, 512-байтовые ячейки, постоянный поток без «человеческих» пауз.
- **DNS**: запросы `.onion` — прямой индикатор (если резолвер их видит).
- **Мосты obfs4/meek**: трафик выглядит как случайные байты (obfs4) или HTTPS к CDN (meek) — детектится сложнее, чаще по поведению/объёму.
- **DLP/прокси**: блокировка известных Tor + SNI-фильтрация + профилирование аномалий.

```bash
# Найти в трафике обращения к relay-портам (грубый признак)
tshark -r cap.pcap -Y 'tcp.port==9001 || tcp.port==9030' -T fields -e ip.dst | sort | uniq -c | sort -rn
```

Политика должна различать **легитимное использование** (приватность сотрудника, обход геоблокировки) и **индикатор компромисса** (C2 через Tor). Блокировать всё подряд — плохая идея: сломаете полезные сценарии и не поймаете мосты.

## Квиз

```quiz
- question: "Из каких узлов состоит цепь Tor?"
  options:
    - "Guard, Middle, Exit"
    - "Client, Proxy, Server"
    - "Ingress, Egress, Relay"
    - "DNS, HTTP, TLS"
  answer: 0
  explanation: "Три узла: входной (guard), средний и выходной (exit)."
- question: "Что знает exit-узел Tor?"
  options:
    - "Пункт назначения, но не отправителя"
    - "Отправителя, но не назначение"
    - "И то, и другое"
    - "Ничего"
  answer: 0
  explanation: "Exit видит назначение, но не знает, кто именно отправитель."
- question: "Почему onion-сервисам не нужен exit-узел?"
  options:
    - "Трафик остаётся внутри сети Tor и приходит к сервису напрямую"
    - "Они работают без шифрования"
    - "Они используют только HTTP"
    - "Они обходят DNS"
  answer: 0
  explanation: "Сервис доступен как onion-адрес внутри сети, обе стороны анонимны."
- question: "Какая утечка может деанонимизировать пользователя Tor?"
  options:
    - "DNS-запросы, идущие напрямую вне Tor"
    - "Использование HTTPS"
    - "Длинный пароль"
    - "Кодек G.711"
  answer: 0
  explanation: "Приложения, резолвящие DNS напрямую, раскрывают активность."
- question: "Что помогает обойти блокировку Tor?"
  options:
    - "Bridges с obfs4/meek"
    - "Отключение шифрования"
    - "Использование WEP"
    - "STP"
  answer: 0
  explanation: "Мосты маскируют Tor-трафик, обходя блокировки."
```

## Где пригодится

- **CTF:** задачи с onion-адресами и анонимизацией.
- **Пентест:** обход геоблокировок, доступ к скрытым сервисам.
- **SOC:** детект и политика Tor в корпоративной сети.
- **OSINT:** доступ к onion-ресурсам для разведки.
- **Приватность:** понимание реальных границ анонимности.
