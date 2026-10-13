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
lab:
  kind: shell
  title: "Практика: разбор eve.json Suricata"
  toolset: [core]
  workdir: /home/student/task
  files: [task.md, notes.txt, eve.json]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Посмотри события: `grep event_type eve.json`."
    - "Алерт с сигнатурой `DNS Exfil` содержит `rrname`."
    - "Метка домена — base64 до `.evil.example`."
    - "`grep rrname eve.json | cut -d'\"' -f4 | cut -d. -f1 | base64 -d > found.txt`."

---

## Вопрос, с которого всё начинается

В прошлом уроке мы разбирали PCAP руками — через фильтры и статистику `tshark`. Но когда в захвате сотни тысяч пакетов, вручную не успеть. Нужен инструмент, который сам «проиграет» трафик через набор известных правил и покажет подозрительные места. Это и есть **IDS** (Intrusion Detection System).

## Наш пример: подозрительный захват exfil.pcap

Есть файл `exfil.pcap` — трафик с хоста, который, по слухам, что-то выгружал. Прогоним его через **Suricata** — движок IDS/IPS, умеющий читать не только живой трафик, но и готовые PCAP-файлы.

Сначала проверим, что движок и правила на месте:

```bash
$ suricata --build-info | head -3
Suricata 7.0.0
$ suricata-update            # подтянуть ET Open ruleset
$ suricata -T -c /etc/suricata/suricata.yaml -v   # проверка конфига
```

Ключевой момент: правила, которые не удалось загрузить, просто не сработают — поэтому `-T` (test) запускают до боевого прогона.

## Шаг 1: прогоняем PCAP

```bash
$ suricata -r exfil.pcap -l ./out -c /etc/suricata/suricata.yaml
$ ls ./out
eve.json  fast.log  stats.log  suricata.log
```

Флаг `-l` задаёт каталог вывода. Главный результат — **`eve.json`**: файл в формате JSON-lines, где одна строка = одно событие. Именно его и разбирают.

## Шаг 2: смотрим алерты

Каждое событие имеет поле `event_type`. Тип `alert` — срабатывание правила. Достаём их через `jq` (консольный фильтр JSON):

```bash
$ jq -c 'select(.event_type=="alert") | {sig:.alert.signature, src:.src_ip, dst:.dest_ip, port:.dest_port}' out/eve.json
{"sig":"ET POLICY curl User-Agent","src":"10.0.0.5","dst":"203.0.113.9","port":443}
{"sig":"Suspicious admin access","src":"10.0.0.5","dst":"10.0.0.1","port":80}
```

Читаем: хост `10.0.0.5` использует **curl** (инструмент командной строки, нетипичный для обычного браузера) и обращается к `203.0.113.9:443`. Это гипотеза, которую надо подтвердить.

Основные типы событий `eve.json`:

| event_type | Что содержит |
|------------|--------------|
| `alert` | срабатывание правила: signature, category, severity |
| `flow` | статистика потока: pkts, bytes, start/end |
| `http` | метод, hostname, url, user-agent, status |
| `dns` | запрос/ответ, rrtype, rdata |
| `tls` | SNI, версия, отпечаток (JA3/JA3S) |
| `fileinfo` | извлечённый файл: имя, размер, md5/sha1 |

## Шаг 3: ищем улики не только в алертах

Важное правило: **отсутствие алертов ≠ чисто**. Правила видят только то, что описано сигнатурами. Смотрим `http`/`dns`/`tls`-события напрямую:

```bash
$ jq -r 'select(.event_type=="http") | .http.hostname + " " + .http.url' out/eve.json | head
pastebin.com /raw/AbC123
$ jq -r 'select(.event_type=="dns") | .dns.rrname' out/eve.json | sort | uniq -c | sort -nr | head
$ jq -c 'select(.event_type=="fileinfo") | {name:.fileinfo.filename, size:.fileinfo.size}' out/eve.json
{"name":"dump.zip","size":52428800}
```

Картина ясна: хост обращался к `pastebin.com`, скачал `dump.zip` на 50 МБ, использовал curl-UA. Дальше — восстановить файл из потока (см. `forensics-exfil`).

## Шаг 4: как устроено правило

Правило Suricata — одна строка такого вида:

```
action proto src_ip src_port -> dst_ip dst_port (options)
```

```bash
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious admin access"; \
  flow:to_server,established; http.method; content:"GET"; http.uri; \
  content:"/admin"; nocase; classtype:web-application-activity; sid:1000001; rev:1;)
```

Разберём части:

- **action** — `alert`, `drop`, `pass`, `reject`. В оффлайн-режиме важен `alert`.
- **proto** — `tcp`, `udp`, `http`, `dns`, `tls`, `smb`, `ftp`.
- **адреса/порты** — `$HOME_NET any -> $EXTERNAL_NET 443`; `$HOME_NET` задаётся в конфиге и определяет направление.
- **options** — `msg` (текст), `flow` (направление/состояние), `content` (байты для поиска), `nocase` (без учёта регистра), `sid` (уникальный ID), `rev` (версия).

Проверить правило до запуска: `suricata -T -S local.rules`. Частые ошибки — забыть `flow` (правило сработает в обе стороны и даст дубли) или `sid` (правило может не загрузиться).

## Шаг 5: TLS без расшифровки

Даже не имея ключей, Suricata даёт ценные TLS-метаданные:

```bash
$ jq -r 'select(.event_type=="tls") | "\(.tls.sni) \(.tls.version) ja3=\(.tls.ja3.hash)"' out/eve.json | sort -u
```

- **SNI** — какой домен запрошен.
- **JA3/JA3S** — отпечатки клиента/сервера; у известных малварей характерные JA3.

## Полный разбор: от PCAP к алерту и артефакту

Соберём прогон `exfil.pcap` в один сценарий.

1. **Запускаем:** `suricata -r exfil.pcap -l ./out` — в `./out` появятся `eve.json`, `fast.log`.
2. **Смотрим алерты:**
   ```bash
   $ jq -c 'select(.event_type=="alert") | {sig:.alert.signature, src:.src_ip, dst:.dest_ip}' out/eve.json
   ```
3. **Ищем улики вне алертов.** В `eve.json` есть `flow`, `http`, `dns`, `tls` — даже без сигнатур.
4. **Разбираем правило.** Сигнатура = header (протокол, адреса, порты, направление) + опции (`msg`, `content`, `flow`, `sid`).
5. **TLS без расшифровки.** Видны SNI, сертификат, JA3; алерты строят на метаданных.

Ключ: Suricata даёт **детект по сигнатурам**, а `eve.json` — структурированные данные для дальнейшего анализа.

## Шпаргалка правил

| Опция | Значение |
|-------|----------|
| `msg` | текст алерта |
| `content` | байты для поиска |
| `flow` | направление (`to_server`, `established`) |
| `sid`/`rev` | идентификатор/версия правила |
| `threshold` | подавление флуда |

Пример правила:

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious POST"; \
  flow:to_server,established; content:"POST"; http_method; \
  content:"/gate.php"; http_uri; sid:1000001; rev:1;)
```

## Частые вопросы

**Suricata vs Zeek.** Suricata — сигнатуры/алерты; Zeek — подробные логи. Дополняют друг друга.

**Много ложных срабатываний.** Настройте `HOME_NET`/`EXTERNAL_NET`, используйте `threshold`, обновите правила (`suricata-update`).

**Скорость на большом PCAP.** Ограничьте правила набором, используйте несколько потоков (`--runmode`), загружайте только нужный трафик.

**Где взять правила?** Emerging Threats (ET Open/Pro) и встроенный набор; пишите свои под инцидент.

## Что мы теперь знаем

- Suricata прогоняет PCAP через правила и пишет **`eve.json`** (JSON-lines, одна строка = событие).
- Тип `alert` — срабатывание сигнатуры; но нужно смотреть и `http`/`dns`/`tls`/`fileinfo`.
- Правило: `action proto src -> dst (options)`; проверяют через `suricata -T`.
- `$HOME_NET` в конфиге определяет направление в правилах.
- Без ключей по TLS доступны SNI и JA3/JA3S.
- Отсутствие алертов не означает «чисто» — правила покрывают лишь описанное.

## Если не сработало: производительность и ложные срабатывания

Несколько практических оговорок:

- **Правила не равно истина.** Отсутствие алертов не значит «чисто»: правила покрывают лишь описанное. Всегда смотрите `http`/`dns`/`tls`-события напрямую.
- **ET Open шумный.** Один и тот же хост может дать десятки ложных алертов. Фильтруйте по `alert.category` и severity, а частые сигнатуры считайте через `jq … | sort | uniq -c`.
- **Потоковая пересборка.** Правила уровня HTTP требуют собранного потока; при захвате «с середины» помогает `--set stream.midstream=true`.
- **Большие захваты.** `eve.json` на гигабайтном PCAP огромен; разбейте вход через `editcap -c` и держите вывод `-l` на быстром диске.
- **Воспроизводимость.** Зафиксируйте версию ruleset и конфига — иначе результат не повторить.

```bash
# Самые частые сигнатуры (шум)
$ jq -r 'select(.event_type=="alert") | .alert.signature' out/eve.json | sort | uniq -c | sort -nr | head
```

Suricata хорошо дополняет Zeek: Suricata даёт сигнатуры и алерты, Zeek — детальные протокольные логи; сопоставляют их по времени и 5-tuple.

## Квиз

Проверь себя.

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
- question: "Как проверить синтаксис правила до прогона?"
  options:
    - "suricata -T -S local.rules"
    - "jq . local.rules"
    - "tshark -Y"
    - "nfdump -r"
  answer: 0
  explanation: "suricata -T тестирует загрузку правил и конфига без обработки трафика."
```

## Куда дальше

Мы научились прогонять трафик через сигнатуры и читать `eve.json`. В следующем уроке (`forensics-netflow`) разберём **потоковые данные** — NetFlow/IPFIX, где нет содержимого, но видно, кто, куда и сколько передал. А пока главное запомни: **Suricata превращает PCAP в структурированный `eve.json`, а `jq` вытаскивает из него алерты, HTTP/DNS/TLS и файлы**.

## Где пригодится

- **CTF:** большие PCAP, где нужен автоматический поиск атак.
- **DFIR:** разбор инцидентов на сетевом уровне.
- **SOC:** разработка и отладка правил.
- **Threat Hunting:** фингерпринтинг C2 по JA3 и UA.
