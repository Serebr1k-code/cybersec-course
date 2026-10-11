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
---

DNS — «телефонная книга» интернета и один из самых недооценённых протоколов с точки зрения безопасности. Он разрешает имена в адреса, но при этом почти не аутентифицирован (без DNSSEC), кэшируется и легко превращается в канал. Этот модуль — база для [`network-dns-records`](network-dns-records) и [`network-dns-enum`](network-dns-enum), опирается на [`network-dns-attacks`](network-dns-attacks) и [`network-dnssec`](network-dnssec).

## Зачем отдельный модуль по DNS

DNS встречается почти в каждой атаке:

- **разведка** — перечисление поддоменов и зон раскрывает инфраструктуру;
- **спуфинг** — поддельный ответ уводит на чужой сервер;
- **туннелирование** — данные прячут в запросах (см. `network-dns-tunnel`);
- **rebinding** — обход SSRF-фильтров (см. `network-dns-attacks`);
- **шифрование** — DoH/DoT ломают мониторинг (см. `network-doh-dot`).

Без понимания записей и резолвинга невозможно ни атаковать, ни защищаться.

## Типы записей DNS

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

```bash
# Запросить разные типы
dig example.com A +short
dig example.com MX +short
dig example.com TXT +short
dig example.com NS +short
dig -x 8.8.8.8 +short       # PTR
```

## Как работает резолвинг

1. Клиент спрашивает свой **рекурсивный резолвер** (обычно через DHCP).
2. Резолвер идёт к **root**, затем к TLD, затем к **авторитетному** серверу зоны.
3. Ответ **кэшируется** на TTL секунд.
4. Клиент получает адрес.

Кэширование — и друг, и враг: оно ускоряет, но при отравлении кэша ложный ответ живёт до истечения TTL.

```bash
# Пошаговый резолвинг через конкретный сервер
dig +trace example.com
# Запрос к авторитетному серверу напрямую
dig @ns1.example.com example.com A
```

## TTL, negative caching и serial

- **TTL** — сколько секунд держать ответ в кэше.
- **Negative caching** — кэширование ответа NXDOMAIN (по SOA minimum).
- **SOA serial** — версия зоны; растёт при изменениях, служит для transfer.

```bash
# Увидеть TTL и serial
dig example.com SOA +noall +answer
# Наблюдать изменение TTL по мере кэширования
dig @8.8.8.8 example.com | grep -A1 "ANSWER SECTION"
```

## Перечисление: зоны и поддомены

Два основных подхода:

- **Zone transfer (AXFR)** — если сервер разрешает, вы получаете всю зону целиком.
- **Брутфорс/словарь** — перебор имён из wordlist.

```bash
# Попытка zone transfer
dig AXFR example.com @ns1.example.com
# Брутфорс поддоменов (puredns/dnsx/gobuster dns)
gobuster dns -d example.com -w subdomains.txt -t 50
# Массовый резолвинг
dnsx -l names.txt -a -resp
```

Подробно — в `network-dns-enum`.

## Атаки: карта векторов

- **DNS spoofing** — поддельный ответ раньше легитимного;
- **cache poisoning** — отравление кэша резолвера;
- **DNS rebinding** — смена адреса между запросами;
- **tunneling** — эксфильтрация через запросы;
- **amplification** — отражение (см. `network-udp-deep`);
- **dangling CNAME** — захват поддомена.

```bash
# Проверить уязвимость к rebinding (лаборатория)
dig +short rebind.example.com
```

## Шифрованный DNS: DoH/DoT/DoQ

DNS over HTTPS/TLS/QUIC шифрует запросы, что мешает фильтрации и мониторингу. С одной стороны — приватность, с другой — «слепая зона» для SOC и удобный канал для туннелей. Подробно — в [`network-doh-dot`](network-doh-dot).

```bash
# DoH-запрос
curl -s -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=example.com&type=A'
# DoT через kdig
kdig -d @1.1.1.1 +tls example.com
```

## Инструменты

| Инструмент | Назначение |
|---|---|
| `dig`/`kdig` | запросы, DNSSEC, DoT |
| `nslookup`/`host` | простые запросы |
| `dnsx`/`puredns` | массовый резолвинг |
| `gobuster dns` | брутфорс поддоменов |
| `dnsrecon`/`dnsenum` | перечисление |
| `tcpdump`/`tshark` | захват DNS |

```bash
# Захват DNS-трафика
sudo tcpdump -i eth0 -nn 'udp port 53'
tshark -r cap.pcap -Y 'dns' -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head
```

## Типовые ошибки

- **Путать CNAME и A** — алиас не адрес.
- **Забывать про TTL** — отравление живёт до истечения.
- **Игнорировать negative caching** — NXDOMAIN тоже кэшируется.
- **Считать AXFR всегда закрытым** — иногда он открыт.
- **Не проверять TXT** — там SPF/DKIM/верификации.
- **Забывать про PTR** — обратная зона раскрывает имена.
- **Не учитывать DoH/DoT** — фильтрация по 53 не работает.

## Что дальше / решение

Пройдите [`network-dns-records`](network-dns-records) и [`network-dns-enum`](network-dns-enum). Для атак — [`network-dns-attacks`](network-dns-attacks), [`network-dns-tunnel`](network-dns-tunnel), [`network-dnssec`](network-dnssec).

## Рекурсия vs авторитетность

| Роль сервера | Что делает |
|---|---|
| Рекурсивный | отвечает клиенту, обходит иерархию |
| Авторитетный | знает зону и отвечает за неё |
| Forwarder | пересылает запросы выше |
| Stub | минимальный, только кэш |

Смешение ролей — ошибка: **open resolver** (рекурсия для всех) участвует в амплификации. Проверка:

```bash
# Уязвим ли сервер как open resolver
dig @10.0.0.53 example.com +recurse
# Если отвечает на внешний домен с RA-флагом — открыт
```

## Лаборатория: свой резолвер

```bash
# Поднять dnsmasq и смотреть запросы
sudo dnsmasq --no-daemon --log-queries --interface=lo &
dig @127.0.0.1 example.com
# Логи покажут запрос и ответ
# Захватить трафик
sudo tcpdump -i lo -nn 'udp port 53'
```

Наблюдение за резолвером — базовый навык: видно, какие имена запрашиваются, как работает кэш, где возникают NXDOMAIN.

## Чек-лист DNS

1. Какие **записи** есть у домена (A/AAAA/MX/TXT/SRV/SOA/CAA)?
2. Разрешён ли **AXFR**?
3. Настроен ли **open resolver** (амплификация)?
4. Есть ли **DNSSEC** (DNSKEY/DS/RRSIG)?
5. Используется ли **DoH/DoT** (слепая зона)?
6. Включён ли **rate-limit** и **RRL**?
7. Мониторятся ли **NXDOMAIN** и аномальные имена?

```bash
# Снимок конфигурации домена
for t in A AAAA MX NS TXT SOA CAA; do echo "== $t"; dig example.com $t +short; done
# Проверка DNSSEC
dig +dnssec example.com | grep -i rrsig | head
```

## Практический вывод

DNS — одновременно инструмент разведки, вектор атаки и канал эксфильтрации. Закрывать нужно все три плоскости: ограничить AXFR и рекурсию, внедрить DNSSEC, мониторить аномалии и контролировать DoH/DoT на периметре.

## Диагностика резолвинга

```bash
# Какой резолвер используется
resolvectl status | grep -A2 'DNS Servers'
cat /etc/resolv.conf
# Пошаговый резолвинг
dig +trace example.com
# Проверить кэш и TTL
dig example.com | grep -A1 'ANSWER SECTION'
# Сравнить ответы разных резолверов
for r in 8.8.8.8 1.1.1.1 9.9.9.9; do echo "== $r"; dig @$r example.com +short; done
```

Расхождение ответов — признак сплит-DNS, кэша или отравления. В корпоративной сети внутренние имена часто резолвятся только внутренним сервером.

## Сравнение DNS-транспортов

| Транспорт | Порт | Шифрование | Заметность |
|---|---|---|---|
| DNS/UDP | 53 | нет | высокая |
| DNS/TCP | 53 | нет | средняя |
| DoT | 853 | TLS | низкая (TLS) |
| DoH | 443 | HTTPS | очень низкая |
| DoQ | 853/udp | QUIC | низкая |

Чем «обычнее» транспорт, тем сложнее фильтровать. DoH на 443 практически неотличим от обычного веба без DPI.

## Практический вывод

DNS нужно анализировать в трёх плоскостях: **содержимое** (записи, аномальные имена), **транспорт** (UDP/TCP/DoH/DoT), **роль** (рекурсия, авторитетность). Мониторинг только порта 53 пропускает DoH/DoT, а анализ только имён не видит туннелей. Комбинация трёх плоскостей даёт полную картину.

## Квиз

```quiz
- question: "Какой тип записи указывает почтовый сервер домена?"
  options:
    - "MX"
    - "A"
    - "NS"
    - "CNAME"
  answer: 0
  explanation: "MX задаёт почтовые серверы для домена."
- question: "Что такое TTL в DNS?"
  options:
    - "Время жизни записи в кэше, в секундах"
    - "Число хопов"
    - "Размер пакета"
    - "Версия протокола"
  answer: 0
  explanation: "TTL ограничивает время кэширования ответа."
- question: "Что даёт успешный zone transfer?"
  options:
    - "Полный список записей зоны"
    - "Пароли пользователей"
    - "Сертификаты TLS"
    - "MAC-адреса"
  answer: 0
  explanation: "AXFR отдаёт всю зону, если сервер разрешает transfer."
- question: "Зачем нужен DNS rebinding?"
  options:
    - "Обойти фильтры по адресу, меняя ответ между запросами"
    - "Ускорить резолвинг"
    - "Шифровать DNS"
    - "Сжать ответ"
  answer: 0
  explanation: "Смена адреса между запросами обманывает проверки и SSRF-фильтры."
- question: "Что шифрует DoH?"
  options:
    - "DNS-запросы, инкапсулируя их в HTTPS"
    - "TCP-трафик"
    - "ARP"
    - "ICMP"
  answer: 0
  explanation: "DNS over HTTPS прячет запросы в HTTPS, ломая фильтрацию по 53."
```

## Где пригодится

- **CTF:** задачи с DNS-записями, зонами, туннелями.
- **Пентест:** перечисление поддоменов, спуфинг, rebinding.
- **SOC:** анализ DNS-трафика, детект туннелей и DoH.
- **Инженерия:** корректные записи, TTL, DNSSEC.
