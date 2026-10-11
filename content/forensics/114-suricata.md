---
id: forensics-suricata
title: "Suricata: сигнатурный анализ PCAP и разбор eve.json"
category: forensics
parent: forensics-net-ndr
difficulty: hard
order: 1
tags: [suricata, ids, pcap, eve.json, rules, network-forensics]
prerequisites: [forensics-pcap]
useful_for:
  - "CTF Forensics категория"
  - "Network Forensics"
  - "SOC / Threat Hunting"
estimated_minutes: 52
summary: "Запуск Suricata на PCAP, чтение eve.json (alerts, flows, http/dns/tls), написание и отладка правил, разбор сигнатур и извлечение артефактов из алертов."
---

Suricata — высокопроизводительный IDS/IPS/NSM-движок, который умеет читать не только живой трафик, но и **PCAP-файлы**. Для форензика это ключевой инструмент: вы «проигрываете» захват через набор правил и получаете структурированный JSON со всеми событиями — алертами, потоками, HTTP/DNS/TLS-записями. Вместо ручного просмотра тысяч пакетов вы работаете с индексируемым выводом.

## Установка и базовая проверка

```bash
sudo apt install suricata
suricata --build-info | head -20
# Проверить правила и конфиг
suricata -T -c /etc/suricata/suricata.yaml -v
# Обновить правила (нужен доступ в интернет или локальное зеркало)
sudo suricata-update
ls /var/lib/suricata/rules/
```

`suricata-update` подтягивает ET Open ruleset; в закрытой среде правила кладут вручную в `rules/` и указывают в `suricata.yaml` (`rule-files:`).

## Прогон PCAP

```bash
# Прогон оффлайн, вывод в отдельный каталог
suricata -r capture.pcap -l ./out -c /etc/suricata/suricata.yaml
# -l задаёт каталог для eve.json, fast.log, stats.log
ls ./out
#   eve.json  fast.log  stats.log  suricata.log

# С фильтром по правилам
suricata -r capture.pcap -l ./out -S ./local.rules
# Высокий уровень для коротких захватов
suricata -r capture.pcap -l ./out --set stream.midstream=true
```

По умолчанию Suricata пишет `eve.json` — JSON-lines: одна строка = одно событие. Именно его и парсят.

## Формат eve.json

Каждая строка имеет `event_type`. Основные типы:

| event_type | Что содержит |
|------------|--------------|
| `alert` | срабатывание правила: signature, category, severity |
| `flow` | статистика потока: pkts, bytes, start/end |
| `http` | метод, hostname, url, user-agent, status |
| `dns` | запрос/ответ, rrtype, rdata |
| `tls` | SNI, версия, отпечаток (JA3/JA3S) |
| `fileinfo` | извлечённый файл: имя, размер, md5/sha1 |
| `stats` | счётчики движка |

```bash
# Только алерты
jq -c 'select(.event_type=="alert") | {sig:.alert.signature, src:.src_ip, dst:.dest_ip}' out/eve.json | head
# Все HTTP-хосты
jq -r 'select(.event_type=="http") | .http.hostname' out/eve.json | sort | uniq -c | sort -nr | head
# DNS-запросы
jq -r 'select(.event_type=="dns") | .dns.rrname' out/eve.json | sort | uniq -c | sort -nr | head
```

## Написание правил

Правило Suricata — одна строка:

```
action proto src_ip src_port -> dst_ip dst_port (options)
```

```bash
# Пример: детект GET на /admin
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious admin access"; \
  flow:to_server,established; http.method; content:"GET"; http.uri; \
  content:"/admin"; nocase; classtype:web-application-activity; sid:1000001; rev:1;)

# Детект DNS-запроса к домену
alert dns any any -> any any (msg:"DNS to evil.example"; dns.query; \
  content:"evil.example"; nocase; sid:1000002; rev:1;)

# Детект по User-Agent
alert http any any -> any any (msg:"Suspicious UA"; http.user_agent; \
  content:"curl"; nocase; sid:1000003; rev:1;)
```

Ключевые опции: `flow` (направление/состояние), `content` (байты), `nocase`, `pcre` (regex), `classtype`, `sid` (уникальный ID), `rev` (версия), `threshold`/`detection_filter` (лимиты). Проверяйте правила через `suricata -T -S local.rules`.

## Разобранный пример

```bash
$ suricata -r exfil.pcap -l ./out -S ./local.rules
$ jq -c 'select(.event_type=="alert") | {sig:.alert.signature, src:.src_ip, dst:.dest_ip, port:.dest_port}' out/eve.json
{"sig":"ET POLICY curl User-Agent","src":"10.0.0.5","dst":"203.0.113.9","port":443}
{"sig":"Suspicious admin access","src":"10.0.0.5","dst":"10.0.0.1","port":80}
$ jq -r 'select(.event_type=="http") | .http.hostname + " " + .http.url' out/eve.json | head
pastebin.com /raw/AbC123
$ jq -c 'select(.event_type=="fileinfo") | {name:.fileinfo.filename, size:.fileinfo.size}' out/eve.json
{"name":"dump.zip","size":52428800}
```

Вывод: хост `10.0.0.5` обращался к pastebin, загрузил `dump.zip` на 50 МБ, использовал curl-UA. Дальше — восстановить файл из потока (см. `forensics-exfil`).

## Извлечение файлов

Suricata умеет сохранять файлы при соответствующей настройке `file-store` в `suricata.yaml`:

```yaml
outputs:
  - file-store:
      version: 2
      enabled: yes
      dir: filestore
```

После прогона файлы лежат в `filestore/`, а метаданные — в `eve.json` (`fileinfo`). Это быстрее, чем вручную собирать потоки через `tcpflow`.

## Краевые случаи и подводные камни

- **Домашняя сеть (`$HOME_NET`).** Правила зависят от направления; задайте `HOME_NET` под вашу сеть, иначе часть сигнатур не сработает.
- **Потоковая пересборка.** Правила на уровне HTTP требуют `stream`; при midstream-захвате может понадобиться `--set stream.midstream=true`.
- **Правила не равно истина.** Отсутствие алертов не значит «чисто»; смотрите `http`/`dns`/`tls`-события напрямую.
- **Ложные срабатывания.** ET Open шумный; фильтруйте по `alert.category` и severity.
- **Производительность.** На больших PCAP задайте `-l` на быстром диске; `eve.json` может быть огромным.
- **Обновление правил.** Правила меняются; фиксируйте версию ruleset для воспроизводимости.
- **TLS.** Suricata не расшифрует трафик, но даст SNI и JA3/JA3S — полезно для фингерпринтинга.
- **Каталог вывода.** Если `-l` не задан, файлы идут в `/var/log/suricata`.

## Синтаксис правил: разбор по частям

Правило Suricata читается слева направо. Разберём его на части:

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"..."; flow:to_server,established; \
  http.method; content:"POST"; http.uri; content:"/upload"; nocase; \
  classtype:trojan-activity; sid:1000001; rev:2;)
```

- **action** — `alert`, `drop`, `pass`, `reject`, `rejectsrc`, `rejectdst`. В оффлайн-режиме важен `alert`.
- **proto** — `tcp`, `udp`, `icmp`, `ip`, `http`, `dns`, `tls`, `smb`, `dcerpc`, `ftp`, `ssh`.
- **адреса/порты** — `$HOME_NET any -> $EXTERNAL_NET 443`; можно использовать `!` для исключения и списки `[80,443,8080]`.
- **direction** — `->` (однонаправленно) или `<>` (двунаправленно).
- **options** — `msg`, `flow`, `content`, `pcre`, `nocase`, `depth`/`offset`/`distance`/`within`, `classtype`, `sid`, `rev`, `metadata`, `threshold`.

Ключевые «модификаторы» содержимого:

| Опция | Значение |
|-------|----------|
| `content:"GET"` | искать байты |
| `nocase` | без учёта регистра |
| `depth:N` | искать в первых N байтах буфера |
| `offset:N` | начать с N-го байта |
| `distance:N` | относительно конца предыдущего совпадения |
| `within:N` | в пределах N байт |
| `pcre:"/regex/i"` | регулярное выражение (медленнее) |
| `flow:to_server,established` | направление и состояние |

`pcre` мощнее, но дороже по производительности — используйте `content` там, где возможно, а `pcre` — для сложных условий.

## Отладка и оптимизация правил

```bash
# Проверить синтаксис без запуска
suricata -T -S ./local.rules -c /etc/suricata/suricata.yaml
# Прогнать и посмотреть, какие правила сработали
suricata -r capture.pcap -l ./out -S ./local.rules --set outputs.1.eve-log.types.0.alert.enabled=yes
# Найти медленные/шумные правила
jq -r 'select(.event_type=="alert") | .alert.signature' out/eve.json | sort | uniq -c | sort -nr | head
```

Частые ошибки при написании правил:

- **Забыть `flow`.** Правило сработает на оба направления и даст дубли.
- **Нет `sid`/`rev`.** Suricata предупредит, правило может не загрузиться.
- **Слишком общий `content`.** Даёт лавину ложных срабатываний.
- **`pcre` без `content`-префикса.** Медленно на больших PCAP.

## Взаимодействие с Zeek и файлами

Suricata хорошо дополняет Zeek: Suricata даёт сигнатуры и алерты, Zeek — детальные протокольные логи. Типовая связка:

1. Прогнать PCAP через оба.
2. Из Suricata взять алерты (`eve.json`).
3. Из Zeek — `conn.log`, `http.log`, `dns.log` для контекста.
4. Сопоставить по времени/5-tuple.

```bash
# Все алерты с временем
jq -r 'select(.event_type=="alert") | "\(.timestamp) \(.alert.signature) \(.src_ip):\(.src_port) -> \(.dest_ip):\(.dest_port)"' out/eve.json
```

## Разбор TLS-метаданных

Даже без расшифровки Suricata даёт ценные TLS-поля:

```bash
jq -r 'select(.event_type=="tls") | "\(.tls.sni) \(.tls.version) ja3=\(.tls.ja3.hash)"' out/eve.json | sort -u
```

- **SNI** — какой домен запрошен (даже при ECH реже, но обычно есть).
- **JA3/JA3S** — отпечатки клиента/сервера; известные малвари имеют характерные JA3.
- **Certificate** — issuer/subject, можно найти самоподписанные C2-сертификаты.

## Чек-лист сетевого разбора через Suricata

1. Обновить правила, зафиксировать версию.
2. Прогнать PCAP, получить `eve.json`.
3. Просмотреть алерты по убыванию частоты.
4. Отдельно посмотреть `http`/`dns`/`tls`-события (не только алерты).
5. Извлечь `fileinfo` и файлы.
6. Сопоставить с Zeek/NetFlow и локальными артефактами.

## Производительность и большие захваты

На гигабайтных PCAP время прогона и объём `eve.json` могут быть проблемой. Приёмы:

```bash
# Разбить захват на части перед прогоном
editcap -c 500000 huge.pcap part.pcap
# Отключить лишние типы событий в конфиге (только alert)
# outputs -> eve-log -> types: оставить alert, http, dns, tls, fileinfo
# Запускать несколько инстансов параллельно по частям
for p in part*.pcap; do suricata -r "$p" -l "out_${p%.pcap}" & done; wait
```

Держите под рукой версию правил и конфига — воспроизводимость важнее скорости. И помните: отсутствие алертов при «шумном» ruleset не означает чистоту, а наличие — не всегда атаку; интерпретируйте в контексте.

## Быстрая шпаргалка по jq для eve.json

| Цель | Команда |
|------|---------|
| Только алерты | `jq -c 'select(.event_type=="alert")' out/eve.json` |
| Уникальные сигнатуры | `jq -r 'select(.event_type=="alert")|.alert.signature' out/eve.json \| sort -u` |
| HTTP-хосты | `jq -r 'select(.event_type=="http")|.http.hostname' out/eve.json \| sort \| uniq -c` |
| DNS-имена | `jq -r 'select(.event_type=="dns")|.dns.rrname' out/eve.json \| sort -u` |
| Файлы | `jq -c 'select(.event_type=="fileinfo")' out/eve.json` |
| TLS SNI | `jq -r 'select(.event_type=="tls")|.tls.sni' out/eve.json \| sort -u` |

Держите эту таблицу под рукой — большинство задач по PCAP решаются несколькими `jq`-запросами после прогона Suricata.

## Что дальше / решение

1. `suricata-update` (или положить правила вручную).
2. `suricata -r capture.pcap -l ./out`.
3. `jq` по `eve.json`: сначала алерты, затем HTTP/DNS/TLS.
4. `fileinfo` → извлечённые файлы; при необходимости — собрать поток.
5. Сопоставить с другими артефактами (Zeek, NetFlow).

Дальше — `forensics-tshark-deep` (пакетный уровень) и `forensics-netflow` (потоковые данные).

## Квиз

```quiz
- question: "В каком файле Suricata хранит структурированные события в JSON?"
  options:
    - "fast.log"
    - "eve.json"
    - "stats.log"
    - "suricata.log"
  answer: 1
  explanation: "eve.json — JSON-lines со всеми событиями (alert, http, dns, tls, fileinfo)."
- question: "Какой тип события eve.json содержит срабатывание правила?"
  options:
    - "flow"
    - "alert"
    - "http"
    - "stats"
  answer: 1
  explanation: "event_type=alert описывает срабатывание сигнатуры."
- question: "Зачем задавать HOME_NET в конфиге Suricata?"
  options:
    - "для расшифровки TLS"
    - "правила используют направление, зависящее от HOME_NET"
    - "для сжатия PCAP"
    - "для сборки RAID"
  answer: 1
  explanation: "От HOME_NET зависит трактовка $HOME_NET/$EXTERNAL_NET в правилах."
- question: "Что даёт Suricata по TLS-трафику, не имея ключей?"
  options:
    - "содержимое запросов"
    - "SNI и отпечатки JA3/JA3S"
    - "пароли"
    - "ничего"
  answer: 1
  explanation: "Без ключей доступны метаданные: SNI, версия, JA3/JA3S-фингерпринты."
```

## Где пригодится

- **CTF:** большие PCAP, где нужен автоматический поиск атак.
- **DFIR:** разбор инцидентов на сетевом уровне.
- **SOC:** разработка и отладка правил.
- **Threat Hunting:** фингерпринтинг C2 по JA3 и UA.
