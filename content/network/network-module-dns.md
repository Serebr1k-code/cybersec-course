---
id: network-module-dns
title: "DNS глубоко: записи, резолвинг, перечисление и атаки"
category: network
parent: network-dns-attacks
difficulty: easy
order: 1
tags: [network, dns, records, enumeration, resolver, zone]
prerequisites: [network-arp, network-dns-attacks]
useful_for:
  - "CTF Network (DNS-задачи)"
  - "Пентест: DNS-разведка и атаки"
  - "Работа (SOC): анализ DNS-трафика"
estimated_minutes: 60
summary: "Модуль по DNS: типы записей и их смысл, как работает резолвинг и кэширование, перечисление зоны и поддоменов, база для атак (спуфинг, туннели, rebinding)."
lab:
  kind: shell
  title: "Практика: разведка DNS и TXT-запись"
  toolset: [core, dig, tshark]
  workdir: /home/student/task
  files: [task.md, dns.pcap]
  check: "grep -q 'nto{dns_txt_1s_4_tr34sur3_m4p}' answer.txt"
  hints:
    - "Начни с базовых запросов: `dig example.com A +short` и `dig example.com NS +short`."
    - "В дампе `dns.pcap` видно запрос типа TXT к `vault.corp.local`."
    - "Запроси запись напрямую: `dig vault.corp.local TXT +short`."
    - "Секрет в TXT-ответе: `nto{dns_txt_1s_4_tr34sur3_m4p}`."
---

## Вопрос, с которого всё начинается

Ты знаешь только домен `example.com`. Дальше нужно понять, **какие сервисы за ним стоят и что о них можно узнать из открытых источников**. DNS — «телефонная книга» интернета, и одновременно один из самых недооценённых протоколов с точки зрения безопасности: он разрешает имена в адреса, но почти не аутентифицирован (без DNSSEC), кэшируется и легко превращается в канал.

Этот модуль — про то, как читать DNS-записи и перечислять зону. Он опирается на [`network-dns-attacks`](network-dns-attacks) и [`network-dnssec`](network-dnssec) и ведёт к [`network-dns-records`](network-dns-records) и [`network-dns-enum`](network-dns-enum).

## Наш пример: разведка example.com

Начинаем с базовых запросов:

```
$ dig example.com A +short
93.184.216.34
$ dig example.com NS +short
a.iana-servers.net.
b.iana-servers.net.
$ dig example.com MX +short
0 .
```

Читаем: у домена есть IPv4-адрес (`A`), его зону обслуживают два авторитетных сервера (`NS`), а запись `MX` со значением `0 .` означает «почту не принимаем». Уже эти три запроса дали инфраструктуру.

## Шаг 1: типы записей

| Тип | Назначение |
|---|---|
| A | IPv4-адрес |
| AAAA | IPv6-адрес |
| CNAME | псевдоним (алиас) |
| MX | почтовый сервер |
| NS | авторитетный сервер зоны |
| TXT | произвольный текст (SPF, DKIM, верификации) |
| SOA | описание зоны (serial, TTL) |
| PTR | обратное разрешение (IP→имя) |
| SRV | сервис + порт + хост |
| CAA | кто может выдавать сертификаты |
| DNSKEY/DS/RRSIG | DNSSEC |

```
$ dig example.com TXT +short
"v=spf1 -all"
$ dig -x 93.184.216.34 +short
```

`TXT` с `v=spf1 -all` говорит, что домен не рассылает почту — полезная деталь для оценки фишинга. Запрос `-x` — это обратный (`PTR`) резолвинг: по IP получить имя.

## Шаг 2: как работает резолвинг

1. Клиент спрашивает свой **рекурсивный резолвер** (обычно полученный по DHCP).
2. Резолвер идёт к **root**, затем к серверу зоны верхнего уровня (TLD), затем к **авторитетному** серверу нужной зоны.
3. Ответ **кэшируется** на **TTL** секунд.
4. Клиент получает адрес.

Посмотреть всю цепочку можно флагом `+trace`:

```
$ dig +trace example.com
.            518400  IN  NS  a.root-servers.net.
com.         172800  IN  NS  a.gtld-servers.net.
example.com. 86400   IN  A   93.184.216.34
```

Кэширование — и друг, и враг: оно ускоряет работу, но при отравлении кэша ложный ответ живёт до истечения TTL.

## Шаг 3: TTL, negative caching и serial

- **TTL** — сколько секунд держать ответ в кэше.
- **Negative caching** — кэширование ответа «нет такой записи» (NXDOMAIN) по значению из SOA.
- **SOA serial** — версия зоны; растёт при изменениях и нужна для transfer.

```
$ dig example.com SOA +noall +answer
example.com.  3600  IN  SOA  a.iana-servers.net. noc.dns.icann.org. 2026101201 7200 3600 1209600 3600
```

Здесь `3600` — TTL, `2026101201` — serial зоны, а последнее число — минимум для negative caching.

## Шаг 4: перечисление зоны и поддоменов

Два основных подхода:

- **Zone transfer (AXFR)** — если сервер разрешает, вы получаете всю зону целиком.
- **Брутфорс по словарю** — перебор имён.

```
$ dig AXFR example.com @a.iana-servers.net
; Transfer failed.
$ gobuster dns -d example.com -w subdomains.txt -q
www.example.com
mail.example.com
dev.example.com
```

Zone transfer обычно закрыт (что правильно), поэтому поддомены ищут перебором. Подробно — в [`network-dns-enum`](network-dns-enum).

## Шаг 5: атаки и шифрованный DNS

DNS участвует почти в каждой атаке:

- **DNS spoofing** — поддельный ответ приходит раньше легитимного;
- **cache poisoning** — отравление кэша резолвера;
- **DNS rebinding** — смена адреса между запросами (обход SSRF-фильтров);
- **tunneling** — эксфильтрация через запросы (см. [`network-dns-tunnel`](network-dns-tunnel));
- **amplification** — отражение трафика (см. [`network-udp-deep`](network-udp-deep)).

А **DoH/DoT** (DNS поверх HTTPS/TLS) шифруют запросы и ломают фильтрацию по порту 53:

```
$ curl -s -H 'accept: application/dns-json' \
    'https://cloudflare-dns.com/dns-query?name=example.com&type=A'
{"Status":0,"Answer":[{"name":"example.com.","type":1,"data":"93.184.216.34"}]}
```

## Шаг 6: роли серверов и open resolver

DNS-серверы делятся по роли:

| Роль | Что делает |
|---|---|
| Рекурсивный | отвечает клиенту, обходит иерархию |
| Авторитетный | знает зону и отвечает за неё |
| Forwarder | пересылает запросы выше |
| Stub | минимальный, только кэш |

Смешение ролей — ошибка: **open resolver** (рекурсия для всех) участвует в амплификации. Проверяется просто:

```
$ dig @10.0.0.53 example.com +recurse
;; flags: qr rd ra; QUERY: 1, ANSWER: 1
```

Если внешний сервер отвечает на чужой домен с флагом `ra` (recursion available), он открыт — и его можно использовать как отражатель.

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
$ tshark -r dns.pcap -T fields -e dns.qry.name -e dns.qry.type
example.com	1
vault.corp.local	16
```

Подсказка из лаборатории: `tshark -r <pcap> [-nn] [-Y фильтр] [-T fields -e поле…] — разбор дампа`.

## Что мы теперь знаем

- DNS-разведка начинается с A/NS/MX/TXT/SOA и обратного PTR.
- Резолвинг идёт по иерархии root → TLD → авторитетный сервер, ответ кэшируется на TTL.
- Zone transfer (AXFR) отдаёт всю зону, если сервер разрешает; иначе — брутфорс.
- DNS легко спуфить, травить, использовать для rebinding и туннелей.
- DoH/DoT скрывают запросы и создают слепую зону для мониторинга.
- Открытый рекурсивный резолвер (open resolver) опасен: он участвует в амплификации.
- `CAA`-запись ограничивает, какие удостоверяющие центры могут выдать сертификат домену.

| Транспорт | Порт | Шифрование | Заметность |
|---|---|---|---|
| DNS/UDP | 53 | нет | высокая |
| DNS/TCP | 53 | нет | средняя |
| DoT | 853 | TLS | низкая (TLS) |
| DoH | 443 | HTTPS | очень низкая |
| DoQ | 853/udp | QUIC | низкая |

## Если защита мешает

- **AXFR закрыт** — переходи к брутфорсу по словарю и к сертификатам (crt.sh).
- **Рекурсия ограничена** — внутренние имена не резолвятся снаружи; работай изнутри.
- **DNSSEC** — подделать ответ сложнее, но валидация часто не доходит до клиента.
- **DoH/DoT** — фильтрация по 53 не работает; контролируй через JA3/SNI.
- **RRL (Response Rate Limiting)** — амплификация гасится; ищи другие отражатели.

## Практика: снимок конфигурации домена

```
$ for t in A AAAA MX NS TXT SOA CAA; do echo "== $t"; dig example.com $t +short; done
$ dig +dnssec example.com | grep -i rrsig | head
$ dig +trace example.com
$ sudo tcpdump -i eth0 -nn 'udp port 53'
```

Первый цикл собирает все записи домена, `+dnssec` показывает, подписана ли зона, `+trace` — путь резолвинга, а `tcpdump` — что реально ходит по проводу.

## Квиз

Проверь себя.

```quiz
- question: 'Какой тип записи указывает почтовый сервер домена?'
  options:
    - 'MX'
    - 'A'
    - 'NS'
    - 'CNAME'
  answer: 0
  explanation: 'MX задаёт почтовые серверы для домена.'
- question: 'Что такое TTL в DNS?'
  options:
    - 'Время жизни записи в кэше, в секундах'
    - 'Число хопов'
    - 'Размер пакета'
    - 'Версия протокола'
  answer: 0
  explanation: 'TTL ограничивает время кэширования ответа.'
- question: 'Что даёт успешный zone transfer?'
  options:
    - 'Полный список записей зоны'
    - 'Пароли пользователей'
    - 'Сертификаты TLS'
    - 'MAC-адреса'
  answer: 0
  explanation: 'AXFR отдаёт всю зону, если сервер разрешает transfer.'
- question: 'Зачем нужен DNS rebinding?'
  options:
    - 'Обойти фильтры по адресу, меняя ответ между запросами'
    - 'Ускорить резолвинг'
    - 'Шифровать DNS'
    - 'Сжать ответ'
  answer: 0
  explanation: 'Смена адреса между запросами обманывает проверки и SSRF-фильтры.'
- question: 'Что шифрует DoH?'
  options:
    - 'DNS-запросы, инкапсулируя их в HTTPS'
    - 'TCP-трафик'
    - 'ARP'
    - 'ICMP'
  answer: 0
  explanation: 'DNS over HTTPS прячет запросы в HTTPS, ломая фильтрацию по 53.'
```

## Куда дальше

Мы научились читать DNS-записи и перечислять зону. Дальше — вглубь: [`network-dns-records`](network-dns-records) разберёт записи и их смысл, [`network-dns-enum`](network-dns-enum) — перечисление и zone transfer. А пока запомни: **DNS — одновременно инструмент разведки, вектор атаки и канал эксфильтрации.**

## Где пригодится

- **CTF:** задачи с DNS-записями, зонами, туннелями.
- **Пентест:** перечисление поддоменов, спуфинг, rebinding.
- **SOC:** анализ DNS-трафика, детект туннелей и DoH.
- **Инженерия:** корректные записи, TTL, DNSSEC.
