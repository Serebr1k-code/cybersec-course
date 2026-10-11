---
id: forensics-zeek
title: "Zeek/NetFlow и артефакты IDS"
category: forensics
parent: forensics-network-deep
difficulty: hard
order: 2
tags: [zeek, netflow, ids, suricata, network, forensics, logs]
prerequisites: [forensics-network-deep, forensics-pcap]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting / SOC"
estimated_minutes: 40
summary: "Сетевая форензика через Zeek: conn/dns/http/ssl/files логи, извлечение файлов, NetFlow-анализ объёмов и артефакты IDS (Suricata) для восстановления картины атаки."
---

## Зачем Zeek, если есть PCAP

PCAP содержит всё, но для больших объёмов трафика он неудобен: его нельзя «просуммировать» одним запросом. **Zeek** (бывший Bro) — сетевой анализатор, который превращает трафик в **структурированные логи** (TSV/JSON): соединения, DNS, HTTP, TLS, файлы, SSL-сертификаты. Это позволяет отвечать на вопросы «кто с кем говорил», «какие домены запрашивались», «какие файлы передавались» — быстро и по всей сети.

## Логи Zeek

| Лог | Содержимое |
|---|---|
| `conn.log` | все соединения (5-tuple, длительность, байты, состояние) |
| `dns.log` | DNS-запросы и ответы |
| `http.log` | HTTP-запросы (метод, URI, User-Agent, коды) |
| `ssl.log` | TLS-сессии (SNI, версия, JA3, сертификат) |
| `files.log` | переданные файлы (тип, хэш, источник) |
| `notice.log` | срабатывания политик |
| `weird.log` | аномалии протоколов |
| `x509.log` | сертификаты |

```bash
# Запуск на PCAP
zeek -r capture.pcap
# JSON-вывод
zeek -r capture.pcap LogAscii::use_json=T
```

## Анализ conn.log

```bash
# Топ по объёму (эксфильтрация?)
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes | sort -k5 -n | tail
# Долгие соединения (C2 beacon?)
zeek-cut duration id.orig_h id.resp_h < conn.log | sort -rn | head
# Периодичность (beaconing): группировка по парам
zeek-cut ts id.orig_h id.resp_h < conn.log | awk '{print $2,$3}' | sort | uniq -c | sort -rn | head
```

**Beaconing** — регулярные соединения к одному адресу с примерно одинаковым интервалом — признак C2. Ищите по постоянству интервалов.

## Анализ DNS

```bash
# Топ доменов
zeek-cut query < dns.log | sort | uniq -c | sort -rn | head
# Подозрительные (длинные, энтропийные — DNS-туннели)
zeek-cut query < dns.log | awk '{ if (length($1) > 30) print }'
# TXT-запросы (часто используются для туннелей)
zeek-cut qtype_name query < dns.log | grep TXT
```

## Извлечение файлов

```bash
# Zeek сохраняет файлы в extract_files (если настроено)
zeek -r capture.pcap 'Files::add_analyzer(Files::ANALYZER_EXTRACT)'
# или
zeek -r capture.pcap /usr/share/zeek/policy/frameworks/files/extract-all-files.zeek
# Файлы будут в ./extract_files/
ls extract_files/ | head
# Хэши в files.log
zeek-cut mime_type filename md5 < files.log | head
```

Извлечённые файлы — для статического анализа (malware, документы, архивы).

## NetFlow

NetFlow (или IPFIX) — агрегированные данные о потоках: 5-tuple, время, байты, пакеты. Меньше деталей, чем PCAP, но масштабируется на гигабиты.

```bash
# Анализ NetFlow (nfdump)
nfdump -r nfcapd.20240101 -s srcip/bytes -n 20
nfdump -r nfcapd.20240101 'src ip 10.0.0.5 and dst port 443' -s record/bytes
```

NetFlow помогает найти аномалии объёмов (эксфильтрация) и топ-разговаривающих.

## Suricata и IDS-артефакты

Suricata — IDS/IPS, генерирующий `eve.json` (JSON-события) с alerts, flows, DNS, HTTP, TLS. Это богаче Zeek по части детектов.

```bash
suricata -r capture.pcap -l out/
jq -c 'select(.event_type=="alert") | {ts, src_ip, dest_ip, alert}' out/eve.json
jq -c 'select(.event_type=="http") | .http.host' out/eve.json | sort | uniq -c
```

Алерты содержат `signature`, `severity`, `category` — готовые индикаторы.

## Практический пример: картина атаки

1. **Найдите внешние соединения** из внутренней сети (`conn.log`).
2. **Топ доменов** (`dns.log`) — C2/эксфильтрация.
3. **HTTP User-Agent** (`http.log`) — подозрительные клиенты.
4. **TLS SNI + JA3** (`ssl.log`) — нестандартные отпечатки.
5. **Извлеките файлы** (`files.log`) — malware.
6. **Сведите таймлайн** и сопоставьте с host-артефактами.

## Инструменты и команды

```bash
sudo apt install zeek suricata
zeek -r capture.pcap
suricata -r capture.pcap -l out/
# zeek-cut входит в поставку Zeek
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes
```

## JA3/JA3S: отпечатки TLS

**JA3** — отпечаток TLS-клиента (набор версий, шифров, расширений, эллиптических кривых). **JA3S** — отпечаток сервера. Одинаковый JA3 у множества хостов выдаёт **одно и то же malware/инструмент** (Cobalt Strike, Metasploit, curl). Это мощный способ кластеризации C2.

```bash
# Zeek генерирует ja3/ja3s в ssl.log
zeek-cut ja3 ja3s server_name < ssl.log | sort | uniq -c | sort -rn
# Известные JA3: база ja3er.com, abuse.ch/ja3
```

Если видите **нестандартный** JA3 (например, PowerShell/.NET-клиент, Go-клиент) на необычном порту — это C2.

## Извлечение и hunting по логам

```bash
# Файлы с хэшами
zeek-cut filename md5 sha256 < files.log | grep -v '^$'
# HTTP-методы и User-Agent
zeek-cut method user_agent < http.log | sort | uniq -c | sort -rn | head
# Подозрительные UA
zeek-cut user_agent < http.log | grep -iE 'powershell|curl|wget|python-requests'
# Долгие/большие соединения (эксфильтрация)
zeek-cut id.orig_h id.resp_h orig_bytes resp_bytes duration < conn.log | sort -k4 -n | tail -20
# Порт-скан (много соединений с одного IP на разные порты)
zeek-cut id.orig_h id.resp_p < conn.log | sort | uniq -c | sort -rn | head
```

## Корреляция с host-артефактами

Сетевые логи отвечают на «куда», host-логи — на «что». Совмещайте: Zeek `conn.log` (внешний IP C2) + Sysmon 3 (процесс, установивший соединение) + 4104 (скрипт) → полная картина. Таймлайн из Zeek (`ts`) и EVTX (timestamps) сводится в единую хронологию.

## Настройка и кастомизация Zeek

```bash
# Кастомный скрипт: логировать нестандартные порты
cat > local.zeek <<'EOF'
redef Site::local_nets = { 10.0.0.0/8, 192.168.0.0/16 };
event http_request(c: connection, method: string, uri: string) {
    if (|uri| > 200) print fmt("long URI from %s: %s", c$id$orig_h, uri);
}
EOF
zeek -r capture.pcap local.zeek
```

```bash
# Готовые политики
zeek -r cap.pcap /usr/share/zeek/policy/frameworks/files/extract-all-files.zeek
zeek -r cap.pcap /usr/share/zeek/policy/protocols/ssl/validate-certs.zeek
```

## Инструменты и команды

```bash
sudo apt install zeek suricata
zeek -r capture.pcap LogAscii::use_json=T
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes
cat ssl.log | zeek-cut server_name ja3 ja3s
suricata -r capture.pcap -l out/ && jq -c 'select(.event_type=="alert")' out/eve.json
nfdump -r nfcapd.20240101 -s srcip/bytes -n 20
```

## Разбор: восстановление файла из трафика

```bash
# 1. Запуск Zeek с извлечением файлов
zeek -r capture.pcap /usr/share/zeek/policy/frameworks/files/extract-all-files.zeek
# 2. Файлы в ./extract_files/
ls -la extract_files/
# 3. Тип и хэши
file extract_files/*
zeek-cut mime_type filename md5 sha1 < files.log
# 4. Анализ
strings extract_files/FILE | head
```

Так извлекаются malware, документы, архивы, картинки — без ручного follow stream.

## Частые ошибки

- **Игнорировать Zeek, работая с огромным PCAP.** Логи быстрее.
- **Не извлекать файлы.** Упустите malware.
- **Забыть про beaconing.** Регулярность — ключевой признак C2.
- **Смотреть только alerts.** flows/dns/http дают контекст.
- **Путать NetFlow и PCAP.** NetFlow — агрегаты без содержимого.
- **Не проверять DNS-туннели.** Длинные/энтропийные запросы.

## Как не застрять

- **Zeek-логи** — основа сетевой форензики.
- **conn.log** — топ объёмов и beaconing.
- **dns.log** — туннели и C2.
- **files.log** — извлечение образцов.
- **Suricata** — готовые алерты.
- **NetFlow** — масштаб и аномалии.

## Квиз

```quiz
- question: "Что делает Zeek с PCAP?"
  options:
    - "шифрует"
    - "превращает в структурированные логи (conn/dns/http/ssl/files)"
    - "сжимает"
    - "удаляет"
  answer: 1
- question: "Какой признак C2-beacon в conn.log?"
  options:
    - "случайность"
    - "регулярные соединения с постоянным интервалом"
    - "короткая длительность"
    - "высокая скорость"
  answer: 1
- question: "Что искать в dns.log для DNS-туннеля?"
  options:
    - "короткие имена"
    - "длинные/энтропийные запросы и TXT"
    - "localhost"
    - "ничего"
  answer: 1
- question: "Где Suricata хранит события?"
  options:
    - "conn.log"
    - "eve.json"
    - "access.log"
    - "syslog"
  answer: 1
- question: "Чем NetFlow отличается от PCAP?"
  options:
    - "ничем"
    - "агрегированные метаданные потоков без содержимого"
    - "содержит payload"
    - "это шифр"
  answer: 1
```

## Где пригодится

- **CTF Forensics** — задачи с сетевыми логами.
- **DFIR** — восстановление картины сетевой атаки.
- **SOC/Threat Hunting** — детекты и hunting.
- **Network security monitoring** — постоянный мониторинг.
- **Malware analysis** — извлечение образцов из трафика.
