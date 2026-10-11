---
id: forensics-exfil
title: "Детект эксфильтрации в PCAP"
category: forensics
parent: forensics-network-deep
difficulty: hard
order: 3
tags: [exfiltration, pcap, dns-tunnel, covert-channel, network, dfir]
prerequisites: [forensics-network-deep, forensics-zeek]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 45
summary: "Как обнаруживать утечку данных в трафике: DNS/ICMP/HTTP-туннели, скрытые каналы, аномалии объёмов и таймингов, извлечение переданных данных."
---
Эксфильтрация — это вынос данных за пределы периметра. Атакующий прячет её в легитимных протоколах (DNS, HTTP, ICMP), использует шифрование и разбиение на мелкие части, чтобы обойти DLP. Обнаружение эксфильтрации — задача статистики и корреляции: аномалии объёмов, таймингов и паттернов выдают канал. Этот урок — про скрытые каналы, их признаки и извлечение данных.

## Типы каналов

| Канал | Признаки | Инструмент извлечения |
|-------|----------|----------------------|
| DNS-туннель | длинные поддомены, много запросов, TXT | `tshark`, base32/base64 |
| ICMP-туннель | большие payload в echo | `tshark`, Scapy |
| HTTP(S)-туннель | POST с бинарным/сжатым телом | `tshark`, расшифровка |
| DNS TXT | данные в TXT-записях | `dig`, `tshark` |
| Domain fronting | Host ≠ SNI | `tshark`, Zeek |
| Легитимные сервисы | выгрузка в облако/мессенджер | логи облака |

## DNS-туннели

DNS почти всегда разрешён через firewall, поэтому популярен для C2 и эксфильтрации. Данные кодируются в поддоменах (`<base32>.evil.com`) или в TXT.

```bash
# длинные имена (туннель)
$ tshark -r exfil.pcap -Y dns -T fields -e dns.qry.name | awk '{print length,$0}' | sort -rn | head
# частотный анализ домена
$ tshark -r exfil.pcap -Y dns -T fields -e dns.qry.name | sed 's/.*\.\(evil\.com\)/\1/' | sort | uniq -c | sort -rn
# извлечь данные из поддоменов
$ tshark -r exfil.pcap -Y dns -T fields -e dns.qry.name | cut -d. -f1 | base32 -d 2>/dev/null | strings
# TXT-записи
$ tshark -r exfil.pcap -Y 'dns.resp.type==16' -T fields -e dns.txt | head
```

Типы запросов тоже информативны: туннели часто используют `TXT`, `NULL`, `CNAME`, `A` с длинными именами.

## ICMP-туннели

Данные прячут в payload эхо-запросов (`ping -p`, `ptunnel`, `icmpsh`).

```bash
# извлечь payload ICMP
$ tshark -r exfil.pcap -Y 'icmp.type==8' -T fields -e data.data | xxd -r -p | strings | head
# размер payload (постоянный большой = туннель)
$ tshark -r exfil.pcap -Y 'icmp.type==8' -T fields -e data.len | sort | uniq -c
```

## HTTP(S)-туннели

Данные в теле POST, заголовках (Cookie/Referer), или через domain fronting. При наличии ключей — расшифровка (см. `forensics-tls-decrypt`).

```bash
# POST-тела
$ tshark -r exfil.pcap -Y 'http.request.method=="POST"' -T fields -e http.file_data | head
# подозрительные Cookie
$ tshark -r exfil.pcap -Y 'http.cookie' -T fields -e http.cookie | head
# domain fronting: Host != SNI
$ tshark -r exfil.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name -e http.host
```

## Статистические аномалии

```bash
# объём исходящего по назначению
$ tshark -r exfil.pcap -q -z conv,ip | awk '{print $3, $1}' | sort -rn | head
# эндпоинты
$ tshark -r exfil.pcap -q -z endpoints,ip | head
# тайминги соединений (регулярность)
$ tshark -r exfil.pcap -Y 'ip.dst==203.0.113.9' -T fields -e frame.time_relative | head -20
# размеры пакетов к подозрительному IP
$ tshark -r exfil.pcap -Y 'ip.dst==203.0.113.9' -T fields -e frame.len | sort | uniq -c | sort -rn | head
```

Ключевые метрики: асимметрия (клиент отправил много, получил мало), регулярность (beacon), постоянный размер пакетов (фиксированный чанк туннеля), нестандартные порты.

## Zeek и flow-анализ

`Zeek` строит логи, удобные для агрегации.

```bash
$ zeek -r exfil.pcap
$ cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes | sort -k4 -rn | head
$ cat dns.log | zeek-cut query | awk '{print length,$0}' | sort -rn | head
$ cat http.log | zeek-cut method host uri user_agent | grep -i POST
```

Для больших объёмов — flow-данные (NetFlow/SiLK) и статистика без полного PCAP.

## Разобранный пример

Дан `exfil.pcap`. Ищем утечку.

```bash
# 1. Кто передал больше всех
$ tshark -r exfil.pcap -q -z conv,ip | sort -k3 -rn | head -3
10.0.0.5 <-> 203.0.113.9  4521000 bytes
# 2. Протокол
$ tshark -r exfil.pcap -Y 'ip.dst==203.0.113.9' -q -z io,phs
dns
# 3. Длинные DNS-имена -> туннель
$ tshark -r exfil.pcap -Y dns -T fields -e dns.qry.name | awk '{print length,$0}' | sort -rn | head -1
62 dGhpcyBpcyB0aGUgc2VjcmV0...evil.com
# 4. Декодировать
$ tshark -r exfil.pcap -Y dns -T fields -e dns.qry.name | cut -d. -f1 | base64 -d 2>/dev/null | strings | head
secret document contents
```

Итог: эксфильтрация через DNS-туннель (base64 в поддоменах).

## Справочная таблица

| Признак | Значение |
|---------|----------|
| Длинные поддомены | DNS-туннель |
| Регулярные интервалы | beacon |
| Постоянный размер пакетов | фиксированный чанк |
| Асимметрия объёмов | вынос данных |
| Host ≠ SNI | domain fronting |
| Много TXT/NULL | скрытый канал |

## Частые ошибки

- **Смотреть только TCP/HTTP** — туннели живут в DNS/ICMP.
- **Не строить статистику** — аномалии видны только в агрегатах.
- **Игнорировать тайминги** — регулярность выдаёт канал.
- **Забывать про расшифровку TLS** — данные могут быть внутри HTTPS.
- **Не декодировать base32/base64** — данные останутся «шумом».
- **Пропустить domain fronting** — трафик выглядит легитимным.

## Что дальше / решение

Конвейер: статистика (`-z conv,ip`) → аномалии (длины/тайминги) → извлечь данные (DNS/ICMP/HTTP) → декодировать → расшифровать при необходимости. Связка: `forensics-network-deep` (сеть), `forensics-pcap` (основы), `forensics-zeek` (логи), `forensics-tls-decrypt` (TLS).

## Обход DLP и шифрование

Атакующие обходят DLP: шифруют/сжимают данные перед выносом, разбивают на мелкие части, используют разрешённые сервисы (облако, мессенджеры, git), маскируют под обычный трафик. Отсюда признаки: высокая энтропия в теле, несоответствие размера, регулярные мелкие передачи.

```bash
# энтропия тел POST (высокая = сжато/зашифровано)
$ tshark -r exfil.pcap -Y 'http.request.method=="POST"' -T fields -e http.file_data | head -1 | xxd -r -p | binwalk -E -
# выгрузка в облако (легитимный сервис)
$ tshark -r exfil.pcap -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name | sort | uniq -c | sort -rn | head
# git push / webdav
$ tshark -r exfil.pcap -Y 'http.request.uri contains "git" or http.request.uri contains "webdav"'
```

Для облачной выгрузки смотрите логи сервиса (CloudTrail и др., см. `forensics-cloud-trail`).

## Сводный чек-лист обнаружения

1. Построить статистику разговоров (`-z conv,ip`).
2. Выделить асимметричные пары (клиент >> сервер).
3. Проверить DNS на длинные/частые запросы.
4. Проверить ICMP на большие payload.
5. Проверить HTTP POST на большие/сжатые тела.
6. Проверить регулярность (beacon).
7. Проверить domain fronting (`Host` vs SNI).
8. Расшифровать TLS (если есть ключи).
9. Декодировать найденные данные (base32/64).
10. Свести IOC и объём вынесенного.

## Оценка объёма утечки

Для отчёта важно оценить, **сколько** данных вынесено: суммарный `orig_bytes` к подозрительному направлению, число сессий, восстановленный объём (после декодирования/распаковки). Это помогает оценить серьёзность и ущерб.

## Ограничения

- **Шифрование без ключей** — содержимое не восстановить, только объём и факт.
- **Мелкие чанки** — легко теряются в шуме; нужна агрегация.
- **Легитимный фон** — облачные бэкапы/обновления дают похожие паттерны; важна базовая линия (baseline).
- **Ротация PCAP** — утечка может начаться до начала захвата.

## Квиз

```quiz
- question: "Какой признак типичен для DNS-туннеля?"
  options:
    - "один короткий запрос раз в день"
    - "множество длинных поддоменов с высокой частотой"
    - "только A-записи к localhost"
    - "отсутствие DNS"
  answer: 1
- question: "Где в ICMP может прятаться эксфильтрация?"
  options:
    - "в поле data эхо-запросов (большой payload)"
    - "в TTL"
    - "в checksum"
    - "в типе"
  answer: 0
- question: "Как восстановить данные из поддоменов?"
  options:
    - "декодировать метки (base64/base32/hex) и собрать"
    - "перезапустить DNS"
    - "сменить порт"
    - "никак"
  answer: 0
- question: "Что показывает NetFlow при детекте утечки?"
  options:
    - "содержимое файлов"
    - "кто и сколько байт вынес (объёмы по src/dst)"
    - "пароли"
    - "сертификаты"
  answer: 1
- question: "Почему утечку в HTTPS сложнее заметить?"
  options:
    - "она всегда пустая"
    - "трафик зашифрован; нужны keylog/дамп или анализ метаданных"
    - "HTTPS не используют"
    - "она блокируется"
  answer: 1
```

## Где пригодится

- **CTF:** задачи на DNS/ICMP-туннели и скрытые каналы.
- **DFIR:** оценка объёма и содержания утечки.
- **Threat Hunting:** поиск аномалий DNS/ICMP/HTTP.
- **SOC:** правила на длинные поддомены, редкие DNS-типы, большие ICMP.
- **Судебная экспертиза:** доказательство факта и объёма выноса данных.
