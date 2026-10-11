---
id: network-ids-suricata
title: "Suricata и Zeek: правила, логи и детект сетевых атак"
category: network
parent: network-module-analysis
difficulty: medium
order: 2
tags: [network, ids, ips, suricata, zeek, rules, detection]
prerequisites: [network-module-analysis, network-zeek]
useful_for:
  - "CTF Network (IDS-логи)"
  - "Пентест: обход детекта"
  - "Работа (SOC): настройка и тюнинг IDS"
estimated_minutes: 55
summary: "Suricata и Zeek: сигнатурный vs поведенческий детект, синтаксис правил Suricata, богатые логи Zeek, тюнинг и обход детекта — с командами и примерами."
---

IDS/IPS — «глаза» обороны. Suricata детектирует по сигнатурам и поведению, Zeek пишет структурированные логи для анализа. Понимание их работы нужно и для настройки детекта, и для обхода: зная, что ищет движок, проще не попасть в его правила. Урок продолжает [`network-module-analysis`](network-module-analysis) и опирается на [`network-zeek`](network-zeek).

## Сигнатурный vs поведенческий детект

- **Сигнатуры** — совпадение с шаблоном (строка, байты, regex) в трафике;
- **Аномалии/поведение** — отклонение от baseline (всплеск, нестандартный порт);
- **Протокольный разбор** — понимание протокола (HTTP, DNS, TLS).

Suricata совмещает всё три; Zeek — в первую очередь разбор и логирование.

## Suricata: установка и запуск

```bash
# Обновить правила и запустить
sudo suricata-update
# Прогон pcap
suricata -r capture.pcap -S /etc/suricata/rules/local.rules -l out/
# В режиме IDS на интерфейсе
sudo suricata -i eth0 -l /var/log/suricata
# Посмотреть алерты
cat /var/log/suricata/fast.log | tail
jq . /var/log/suricata/eve.json | head
```

## Синтаксис правил Suricata

```text
action proto src_ip src_port -> dst_ip dst_port (options;)

alert tcp any any -> any 80 (msg:"Possible SQLi"; \
  content:"union select"; nocase; sid:1000001; rev:1;)

alert dns any any -> any any (msg:"Suspicious DNS"; \
  dns_query; content:".evil.com"; sid:1000002; rev:1;)

alert icmp any any -> any any (msg:"Large ICMP payload"; \
  dsize:>1000; sid:1000003; rev:1;)
```

Ключевые опции: `msg`, `content`, `pcre`, `nocase`, `flow`, `dsize`, `threshold`, `sid`, `rev`.

```bash
# Проверить правило
suricata -T -S local.rules
# Прогнать и посмотреть срабатывания
suricata -r capture.pcap -S local.rules -l out/ && cat out/fast.log
```

## Zeek: логи вместо алертов

Zeek генерирует логи по протоколам: `conn.log` (соединения), `dns.log`, `http.log`, `ssl.log`, `files.log`, `notice.log`. Это основа для анализа и корреляции.

```bash
# Прогнать pcap
zeek -r capture.pcap
ls
# Топ соединений по объёму
cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes | sort -k4 -nr | head
# DNS-запросы
cat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head
# HTTP-запросы
cat http.log | zeek-cut host uri | head
```

## Что детектировать

- **скан** — много соединений с одного src;
- **beaconing** — регулярные соединения;
- **туннели** — нестандартные размеры/частоты;
- **эксплойты** — сигнатуры известных CVE;
- **DNS-аномалии** — длинные/энтропийные имена;
- **TLS-аномалии** — self-signed, редкие JA3.

```bash
# Скан: топ источников по числу соединений
cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -rn | head
# DNS-туннель: длинные имена
cat dns.log | zeek-cut query | awk '{print length, $0}' | sort -rn | head
```

## Тюнинг

Ложные срабатывания и пропуски — главная проблема IDS. Тюнинг включает:

- **threshold** — ограничение частоты алертов;
- **suppress** — отключение шумных правил;
- **baseline** — понимание «нормального» трафика;
- **классификация** — приоритезация.

```text
# threshold.config
suppress gen_id 1, sig_id 1000001
threshold gen_id 1, sig_id 1000002, type limit, track by_src, count 5, seconds 60
```

## Обход детекта

- **фрагментация/перекрытие** — см. `network-idps-evasion`;
- **шифрование** — TLS/DoH прячут содержимое;
- **разбиение сессии** — обход корреляции;
- **кодирование/обфускация** — base64, chunked;
- **тайминг** — low-and-slow;
- **протокольные расхождения** — парсеры IDS и цели видят по-разному.

## Частые ошибки

- **Не тюнить правила** — лавина алертов.
- **Игнорировать шифрованный трафик** — слепая зона.
- **Доверять сигнатурам без поведения** — обходятся кодированием.
- **Не хранить логи Zeek** — нет контекста.
- **Считать IDS «защитой»** — IPS блокирует, IDS только алертит.
- **Забывать про асимметрию** — IDS видит не все пакеты.
- **Не проверять правила** — синтаксические ошибки.

## Что дальше / решение

После IDS переходите к [`network-proxy-cdn-waf`](network-proxy-cdn-waf). Для обхода — [`network-idps-evasion`](network-idps-evasion).

## Практика: свои правила и логи

```bash
# Правило на подозрительный User-Agent
cat > local.rules <<'EOF'
alert http any any -> any any (msg:"Suspicious UA"; \
  http.user_agent; content:"sqlmap"; nocase; sid:1000010; rev:1;)
alert dns any any -> any any (msg:"Long DNS name"; \
  dns_query; pcre:"/^.{60,}/"; sid:1000011; rev:1;)
EOF
suricata -T -S local.rules
suricata -r capture.pcap -S local.rules -l out/ && cat out/fast.log
# Zeek: анализ соединений
zeek -r capture.pcap
cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes | sort -k4 -nr | head
cat dns.log | zeek-cut query | awk '{print length,$0}' | sort -rn | head
```

## Сравнение Suricata и Zeek

| Свойство | Suricata | Zeek |
|---|---|---|
| Назначение | IDS/IPS | network security monitor |
| Выход | алерты (fast.log, eve.json) | логи по протоколам |
| Правила | сигнатуры | скрипты |
| Режим | inline/пассив | пассив |
| Сильная сторона | детект | анализ/корреляция |

## Итог по IDS

Suricata и Zeek дополняют друг друга: первый — быстрый детект по сигнатурам и поведению, второй — богатые логи для анализа. Ключевые задачи: **тюнинг** (threshold/suppress), **понимание слепых зон** (шифр, туннели), **корреляция** с NetFlow/DNS. Для пентестера знание правил означает возможность обойти детект (кодирование, фрагментация, тайминг), а для SOC — возможность закрыть эти обходы.

## Практика тюнинга и детекта

Тюнинг — половина работы с IDS. Начните с baseline: прогоните недельный трафик без правил-«шумовиков» и посмотрите, что нормально для сети. Затем включайте правила порциями, отслеживая ложные срабатывания.

```bash
# Сводка алертов по правилам
jq -r 'select(.event_type=="alert") | .alert.signature' /var/log/suricata/eve.json \
  | sort | uniq -c | sort -rn | head
# Топ источников алертов
jq -r 'select(.event_type=="alert") | .src_ip' /var/log/suricata/eve.json \
  | sort | uniq -c | sort -rn | head
# Zeek: топ соединений и DNS
cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -rn | head
cat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head
```

Практический детект-чеклист: скан (много соединений), beaconing (регулярность), туннели (размеры/частоты), DNS-аномалии (длина/энтропия), TLS-аномалии (self-signed, редкий JA3), эксплойты (сигнатуры CVE).

```text
# Пример suppress для шумного правила
suppress gen_id 1, sig_id 2100498
# Threshold: не более 5 алертов в минуту на источник
threshold gen_id 1, sig_id 1000010, type limit, track by_src, count 5, seconds 60
```

## Итоговый вывод

IDS без тюнинга бесполезен: либо тонет в ложных срабатываниях, либо молчит на реальных атаках. Регулярный пересмотр правил, baseline, корреляция с Zeek/NetFlow и понимание слепых зон делают детект реальным. Для пентеста те же знания дают карту того, где вас «видно», и где можно остаться в тени легитимного трафика.

## Квиз

```quiz
- question: "Чем IPS отличается от IDS?"
  options:
    - "IPS блокирует трафик, IDS только алертит"
    - "IDS быстрее"
    - "IPS не пишет логи"
    - "IDS шифрует"
  answer: 0
  explanation: "IPS — inline и блокирует, IDS — пассивный."
- question: "Что генерирует Zeek?"
  options:
    - "Структурированные логи (conn, dns, http, ssl)"
    - "Только алерты"
    - "NetFlow"
    - "TLS-сертификаты"
  answer: 0
  explanation: "Zeek пишет логи по протоколам."
- question: "Какая опция правила Suricata задаёт сигнатуру (SID)?"
  options:
    - "sid"
    - "msg"
    - "content"
    - "rev"
  answer: 0
  explanation: "sid — уникальный идентификатор правила."
- question: "Почему шифрование — слепая зона IDS?"
  options:
    - "Содержимое TLS недоступно сигнатурам"
    - "TLS замедляет"
    - "TLS блокирует порты"
    - "TLS меняет MAC"
  answer: 0
  explanation: "Без расшифровки виден только метаданные."
- question: "Что такое тюнинг IDS?"
  options:
    - "Настройка threshold/suppress и baseline"
    - "Установка правил"
    - "Обновление ОС"
    - "Шифрование трафика"
  answer: 0
  explanation: "Тюнинг снижает ложные и пропуски."
```

## Где пригодится

- **CTF:** задачи с IDS-логами и pcap.
- **Пентест:** понимание и обход детекта.
- **SOC:** настройка, тюнинг, охота.
- **Инженерия:** развёртывание Suricata/Zeek.
