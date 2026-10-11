---
id: forensics-cobaltstrike
title: "Артефакты Cobalt Strike и C2-беконов"
category: forensics
parent: forensics-malware-yara
difficulty: expert
order: 2
tags: [cobaltstrike, c2, beacon, malleable, network, malware, dfir]
prerequisites: [forensics-malware-yara, forensics-network-deep]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting"
estimated_minutes: 50
summary: "Как распознавать Cobalt Strike Beacon и другие C2 в трафике и памяти: JA3, named pipes, watermark, sleep-маскировка, конфиги malleable C2."
---
Cobalt Strike (CS) — коммерческий C2-фреймворк, ставший стандартом и для red team, и для злоумышленников. Его Beacon живёт в памяти, общается с сервером и маскируется под обычный трафик через Malleable C2 профиль. Обнаружение требует анализа сети (JA3/JA3S, ритм), памяти (конфиг, строки) и хоста (named pipes, инъекции). Этот урок — про распознавание CS Beacon и других C2.

## Как устроен Beacon

- **Beacon** — имплант в памяти, часто инжектится в `rundll32.exe`, `dllhost.exe`, `svchost.exe`, `explorer.exe`.
- **Sleep** — периодичность связи (по умолчанию 60 с с jitter). Сеть видит «ровный» ритм.
- **Malleable C2 профиль** — настраивает HTTP-заголовки, URI, кодировку, чтобы трафик выглядел как jQuery/Amazon/др.
- **Stager/Stage** — маленькая первая стадия догружает полный stage.
- **Named pipes** — IPC: дефолтные профили используют `msagent_*`, `mojo_*`, `postex_*`, `status_*`, `MSSE-*`.

## Сетевые артефакты

```bash
# ритм и размеры в pcap
$ tshark -r c2.pcap -Y 'http' -T fields -e ip.dst -e http.host -e http.request.uri | sort | uniq -c | sort -rn
# JA3/JA3S (отпечаток TLS-клиента/сервера)
$ grep -i ja3 zeek/ssl.log | sort | uniq -c | sort -rn | head
# дефолтные URI (если профиль не изменён)
$ tshark -r c2.pcap -Y 'http.request.uri contains "/submit.php" or http.request.uri contains "/__utm.gif"'
# периодичность соединений (beacon check-in)
$ tshark -r c2.pcap -Y 'ip.dst==185.220.101.7 && tcp.flags.syn==1' -T fields -e frame.time_relative
```

Характерные признаки:
- **Ровный период** соединений (check-in) с jitter.
- **Несоответствие** User-Agent и реального TLS-отпечатка (curl UA + Java JA3).
- **Малые POST** с base64/hex-телом и большим ответом (или наоборот).
- **Domain Fronting**/CDN в `Host`, но реальный IP — C2.

## Хостовые артефакты

```bash
# named pipes (Sysmon 17/18 или память)
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==17 or .Event.System.EventID==18) | .Event.EventData.PipeName' | grep -iE 'msagent|mojo|postex|status|MSSE'
# mutex (имя фреймворка)
$ vol -f mem.raw windows.mutantscan | grep -iE 'cobalt|msf|meterpreter'
# инъекции (Sysmon 8/10)
$ evtx_dump -o json Sysmon.evtx | jq 'select(.Event.System.EventID==8) | .Event.EventData | {SourceImage,TargetImage}'
```

**Watermark** — 4-байтовый маркер Beacon (у лицензионных копий связан с лицензией; у утёкших сборок может совпадать между кампаниями). Извлечение watermark связывает образцы.

## Анализ конфига Beacon

Конфиг (C2-адреса, sleep, jitter, профиль, public key) лежит в памяти зашифрованным, но извлекается.

```bash
# 1. Снять дамп процесса
$ vol -f mem.raw windows.malfind --pid 4120 --dump
# 2. Извлечь конфиг
$ python3 parse_beacon_config.py beacon.bin
# -> C2: 185.220.101.7:443, port, sleep, jitter, UA, pipe name, watermark
# 3. dissect.cobaltstrike
$ pip install dissect.cobaltstrike
$ cobaltstrike-beacon beacon.bin
$ cobaltstrike-config-extractor beacon.bin
```

```bash
# Volatility: дамп подозрительного процесса и поиск Beacon
$ vol -f mem.raw windows.memmap --pid 4120 --dump
$ strings -el pid.4120.dmp | grep -iE 'beacon|msagent|jquery'
```

## Другие C2

Тот же подход работает для **Sliver**, **Mythic**, **Metasploit Meterpreter**, **Brute Ratel**, **Havoc**:

- аномальный процесс с сетью и инъекцией;
- ритмичный трафик к одному IP;
- несоответствие TLS-отпечатка и заголовков;
- named pipes/mutex фреймворка.

```bash
# Meterpreter: mutex 'Msf', pipe 'meterpreter'
$ vol -f mem.raw windows.mutantscan | grep -i msf
$ vol -f mem.raw windows.handles | grep -i meterpreter
```

## Разобранный пример

Дан `mem.raw` и `c2.pcap`. Нужно атрибутировать C2.

```bash
# 1. Подозрительный процесс с сетью
$ vol -f mem.raw windows.netscan | grep ESTABLISHED
dllhost.exe 4120 10.0.0.5:49152 185.220.101.7:443 ESTABLISHED
# 2. Странный родитель
$ vol -f mem.raw windows.pstree | grep -A2 dllhost
# 3. Инъекция
$ vol -f mem.raw windows.malfind --pid 4120
# 4. Дамп и конфиг
$ vol -f mem.raw windows.malfind --pid 4120 --dump
$ python3 parse_beacon_config.py pid.4120.dmp
# -> C2: 185.220.101.7:443, sleep 60, jitter 20, UA "Mozilla/5.0 (compatible; MSIE 9.0)", pipe msagent_1
# 5. Сеть: ритм и JA3
$ tshark -r c2.pcap -Y 'ip.addr==185.220.101.7 && tcp.port==443' -T fields -e frame.time_relative | head
$ grep -i ja3 zeek/ssl.log | grep 185.220.101.7
```

Итог: `dllhost.exe` инжектирован Beacon, конфиг извлечён, ритм и JA3 подтверждают C2.

## Справочная таблица

| Задача | Инструмент |
|--------|-----------|
| Конфиг Beacon | `parse_beacon_config`, `dissect.cobaltstrike` |
| JA3/JA3S | Zeek `ssl.log`, `tshark` |
| Named pipes | Sysmon 17/18, `windows.handles` |
| Mutex | `windows.mutantscan` |
| Инъекции | `windows.malfind` |
| Watermark | конфиг-парсеры |

## Частые ошибки

- **Искать только сигнатуры файлов** — Beacon в памяти, файла нет.
- **Верить User-Agent** — Malleable C2 подделывает; сверяйте с JA3/JA3S.
- **Игнорировать периодичность** — ровный ритм выдаёт beacon.
- **Не дампить память** — конфиг исчезнет после перезагрузки.
- **Путать named pipes ОС и фреймворка** — нужен список дефолтных имён.
- **Забывать про watermark** — он связывает кампании.

## Что дальше / решение

Конвейер: `netscan`/`pstree` (процесс+сеть) → `malfind` (инъекция) → дамп → конфиг-парсер → JA3/Zeek (сеть) → named pipes/mutex (хост). Связка: `forensics-network-deep` (сеть), `forensics-malware-yara` (YARA), `forensics-memory-injection` (инъекции), `forensics-exfil` (эксфильтрация).

## Malleable C2 профили и обход

Malleable C2 — это язык описания профиля, который задаёт URI, заголовки, User-Agent, кодировку тела, jitter и даже «фейковый» контент. Профиль позволяет Beacon выглядеть как обычный сайт.

```
http-get {
    set uri "/jquery-3.3.1.min.js";
    client {
        header "Host" "code.jquery.com";
        metadata { base64url; prepend "session="; header "Cookie"; }
    }
    server { output { base64; print; } }
}
http-post {
    set uri "/api/1.0/updates";
    client { id { uri-append; } output { base64; print; } }
    server { output { base64; print; } }
}
```

Признаки: URI, похожие на CDN/API; заголовки, дублирующие реальные сервисы; домен в `Host`, не совпадающий с реальным IP. **Domain fronting** использует CDN: SNI — легитимный домен, `Host` — C2.

## Сводный чек-лист атрибуции C2

1. Найти аномальный процесс с исходящим соединением (`netscan`).
2. Проверить родителя (`pstree`) — Word→dllhost и т. п.
3. Обнаружить инъекцию (`malfind`, Sysmon 8/10).
4. Снять дамп региона/процесса.
5. Извлечь конфиг (`parse_beacon_config`, `dissect.cobaltstrike`).
6. Проверить JA3/JA3S (`zeek ssl.log`).
7. Искать named pipes (`msagent_*`, `mojo_*`) и mutex (`Msf`, `cobalt`).
8. Извлечь watermark для связи кампаний.
9. Свести IOC (C2-IP, домен, URI, UA, pipe, watermark).

## Отличие легитимного трафика от C2

Не всякий «странный» трафик — C2. Обращайте внимание на совокупность: регулярность + инъекция + named pipes + несоответствие TLS-отпечатка. Одиночный признак (например, необычный UA) может быть легитимным приложением. Стройте корреляцию «сеть ↔ память ↔ хост».

## Квиз

```quiz
- question: "Что такое Beacon в Cobalt Strike?"
  options:
    - "файл на диске"
    - "имплант в памяти, общающийся с C2"
    - "журнал событий"
    - "тип шифрования"
  answer: 1
- question: "Что настраивает Malleable C2 профиль?"
  options:
    - "пароль пользователя"
    - "сетевые индикаторы: заголовки, URI, кодировку трафика"
    - "файловую систему"
    - "EVTX"
  answer: 1
- question: "Какой признак в сети типичен для beacon check-in?"
  options:
    - "ровный периодический ритм соединений"
    - "случайные скачки трафика"
    - "отсутствие соединений"
    - "только ICMP"
  answer: 0
- question: "Как связать разные образцы Cobalt Strike?"
  options:
    - "по watermark"
    - "по размеру диска"
    - "по имени пользователя"
    - "по таймзоне"
  answer: 0
- question: "Каким инструментом извлечь конфиг Beacon?"
  options:
    - "exiftool"
    - "CobaltStrikeParser / parse_beacon_config"
    - "binwalk"
    - "foremost"
  answer: 1
```

## Где пригодится

- **CTF:** задачи на сетевую/памятную атрибуцию C2.
- **DFIR:** обнаружение активного Beacon и извлечение конфига.
- **Threat Hunting:** охота на ритмичный трафик и инъекции.
- **SOC:** правила на JA3, named pipes, цепочки процессов.
- **Red team awareness:** понимание, какие индикаторы оставляет CS.
