---
id: osint-threat-intel
title: "Threat Intelligence: IOC, TTP, MISP и Diamond Model"
category: osint
parent: osint-intro
difficulty: hard
order: 4
tags: [threat-intel, ioc, ttp, mitre, misp, diamond-model]
prerequisites: [osint-intel-lifecycle]
useful_for:
  - "Threat intelligence"
  - "SOC / Incident Response"
  - "CTF категория OSINT"
estimated_minutes: 50
summary: "Как превращать разведданные в аналитику угроз: индикаторы (IOC), TTP, MITRE ATT&CK, Diamond Model, обмен через MISP/STIX и оценка достоверности."
---

Threat Intelligence (TI) — это OSINT **плюс анализ угроз**: не просто «собрать данные», а понять противника, его инструменты и цели. Здесь данные превращаются в решения: что блокировать, за чем следить.

## Уровни разведки

| Уровень | Для кого | Что даёт |
|---|---|---|
| Стратегический | руководство | риски, тренды, бюджет |
| Операционный | SOC/IR | кампании, TTP, приоритеты |
| Тактический | аналитики | IOC: хэши, домены, IP |
| Технический | инструменты | сигнатуры, правила |

Не путайте: список IP — это тактический уровень, а понимание кампании — операционный.

## IOC — индикаторы компрометации

IOC — «следы» атакующего:

- **Сетевые**: IP, домены, URL, JA3.
- **Хостовые**: хэши файлов (MD5/SHA256), пути, ключи реестра.
- **Почтовые**: адреса, темы, вложения.

Проблема: IOC **быстро устаревают** (атакующий меняет IP/домен). Поэтому ценнее TTP.

## TTP и MITRE ATT&CK

**TTP** — тактики, техники и процедуры: *как* действует противник. MITRE ATT&CK — каталог техник (T1566 phishing, T1059 command execution...).

Маппинг находки на ATT&CK:

```
Наблюдение: фишинговый email с макросом
→ T1566.001 Spearphishing Attachment
→ T1204.002 User Execution: Malicious File
→ T1059.005 Command and Scripting: Visual Basic
```

TTP устойчивее IOC: смена IP не меняет почерк.

## Diamond Model

Четыре вершины для описания кампании:

```
        Adversary
         /     \
 Capability       Infrastructure
         \     /
          Victim
```

- **Adversary** — кто (группа, APT).
- **Capability** — чем (malware, эксплойт).
- **Infrastructure** — через что (C2, домены).
- **Victim** — против кого.

Заполнив модель, вы видите связи и пробелы: «есть инфраструктура и жертва, но неизвестен инструмент».

## Cyber Kill Chain

Семь этапов: Recon → Weaponization → Delivery → Exploitation → Installation → C2 → Actions. Помогает расположить находку на таймлайне атаки и понять, где её прервать.

## Обмен и форматы

- **STIX** — язык описания угроз (объекты и связи).
- **TAXII** — транспорт для обмена STIX.
- **MISP** — платформа обмена IOC/событиями. Экспорт/импорт STIX, корреляция.

```bash
# Пример: получить событие из MISP по API
curl -s -H "Authorization: $MISP_KEY" -H "Accept: application/json" \
  "https://misp.example.org/events/restSearch" -d '{"tags":["apt"]}' | jq '.response[].Event.info'
```

## Оценка достоверности

Каждый IOC/вывод маркируется уровнем уверенности (low/moderate/high) и оценкой источника (Admiralty). Не публикуйте непроверенное как факт — это классическая ошибка TI.

## Практический конвейер

1. **Сбор**: OSINT + сенсоры + фиды.
2. **Нормализация**: единый формат (STIX-подобный).
3. **Обогащение**: контекст (WHOIS, VT, passive DNS).
4. **Анализ**: маппинг на ATT&CK, Diamond Model.
5. **Распространение**: MISP/отчёт, правила детекции (Sigma/YARA).
6. **Обратная связь**: что сработало, что нет.

## Разобранный пример

Найден домен `evil.example`, используемый для C2.

1. Passive DNS → связанные IP и домены.
2. VT → хэши файлов, семейство malware.
3. Маппинг: C2 → T1071 (Application Layer Protocol).
4. Diamond Model: Adversary(?), Capability(malware X), Infra(evil.example), Victim(отрасль Y).
5. Публикация события в MISP + правила детекции.

## Частые ошибки

- **Гнаться за IOC** и игнорировать TTP.
- **Публиковать непроверенные индикаторы.**
- **Не указывать уровень уверенности.**
- **Не обогащать контекстом** (IOC без контекста бесполезен).
- **Хранить TI в разрозненных таблицах** без стандарта.
- **Путать тактический и операционный уровни** в отчётах.

## Инструменты и платформы

| Инструмент | Назначение |
|---|---|
| MISP | обмен событиями/IOC, корреляция |
| OpenCTI | граф знаний об угрозах |
| AlienVault OTX | публичные пульсы, обмен |
| MITRE ATT&CK Navigator | визуализация покрытия техник |
| TheHive + Cortex | IR-платформа и обогащение |
| YARA / Sigma | правила детекции (файлы/логи) |

```bash
# ATT&CK Navigator: слой с техниками кампании
# (JSON-слой загружается в веб-интерфейс Navigator)
```

## От индикатора к детекции

Цель TI — не список, а **правила**:

1. IOC → обогащение → понимание поведения (TTP).
2. TTP → маппинг на ATT&CK.
3. ATT&CK → правила Sigma (логи) и YARA (файлы).
4. Правила → в SIEM/EDR.
5. Обратная связь: ложные/пропуски → уточнение.

```yaml
# пример Sigma-правила (упрощённо)
title: Suspicious PowerShell Download
logsource: {product: windows, service: powershell}
detection:
  selection: {ScriptBlockText|contains: 'DownloadString'}
  condition: selection
level: high
```

## Программы обмена (ISAC)

Отраслевые **ISAC** (Information Sharing and Analysis Centers) обмениваются TI внутри сектора (финансы, энергетика, здравоохранение). Участие даёт ранние предупреждения и контекст, недоступный публично. Для организаций — важная часть зрелой TI-программы.

## STIX/TAXII: машиночитаемый обмен

IOC сами по себе бесполезны, если их нельзя автоматически передавать. **STIX 2.1** — язык описания угроз (объекты: Indicator, Malware, ThreatActor, AttackPattern, Relationship). **TAXII 2.1** — транспорт (HTTPS + коллекции) для обмена STIX.

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<uuid>",
  "created": "2026-01-01T00:00:00Z",
  "pattern": "[file:hashes.'SHA-256' = 'abc...']",
  "pattern_type": "stix",
  "valid_from": "2026-01-01T00:00:00Z",
  "labels": ["malicious-activity"]
}
```

Коллекции TAXII: `discovery` → `api-root` → `collections`. Многие ISAC и вендоры отдают фиды именно так.

## MISP: практическая работа

MISP — де-факто стандарт платформы обмена. Ключевые понятия: **event** (инцидент/кампания), **attribute** (IOC), **tag**, **galaxy** (ATT&CK-кластеры), **correlation**.

```bash
# PyMISP: поиск по событиям
pip install pymisp
python3 - <<'PY'
from pymisp import PyMISP
m = PyMISP("https://misp.example", "APIKEY", ssl=False)
ev = m.search(controller="events", tags=["tlp:amber"], type_attribute="ip-dst")
for e in ev:
    print(e["Event"]["info"], [a["value"] for a in e["Event"].get("Attribute", [])])
PY
# добавить IOC
python3 -c "from pymisp import PyMISP, MISPEvent; m=PyMISP('https://misp.example','KEY',False); e=MISPEvent(); e.add_attribute('ip-dst','203.0.113.9'); m.add_event(e)"
```

**Correlation** автоматически связывает одинаковые IOC между событиями — так находятся общие кампании.

## OpenCTI и ATT&CK Navigator

- **OpenCTI** — графовая платформа знаний: связывает IOC, акторов, malware, кампании в один граф; удобна для больших расследований.
- **ATT&CK Navigator** — визуализация покрытия TTP: какие техники использует группа и какие детектируются.

```bash
# экспорт слоя Navigator из MISP galaxy
curl -s "https://misp.example/events/export/navigator/1.json" -H "Authorization: KEY" -o layer.json
# импорт слоя в Navigator UI (attacker techniques heatmap)
```

## Pyramid of Pain: почему TTP ценнее хэша

Дэвид Бьянко предложил «пирамиду боли»: чем выше индикатор, тем дороже его сменить атакующему.

| Уровень | Индикатор | Боль для атакующего |
|---------|-----------|---------------------|
| Низ | хэш файла | тривиально (пересобрать) |
| ↓ | IP-адрес | легко (сменить VPS) |
| ↓ | домен | средне |
| ↓ | сетевой артефакт | ощутимо |
| Высок | инструмент (TTP) | дорого (переписать) |

Вывод: гоняйтесь за TTP и поведением, а не только за IOC — иначе детект устаревает через сутки.

## Sigma-правила: от индикатора к детекции

IOC нужно превратить в детекцию. **Sigma** — вендор-независимый формат правил, конвертируемый в SIEM-запросы.

```yaml
title: Suspicious Cobalt Strike Named Pipe
logsource:
  product: windows
  category: pipe_created
detection:
  selection:
    PipeName|startswith: '\MSSE-'
  condition: selection
level: high
```

```bash
pip install sigma-cli
sigma convert -t splunk rule.yml          # в Splunk SPL
sigma convert -t elasticsearch rule.yml   # в ES DSL
```

Так фид из MISP превращается в работающие алерты.

## Конвейер обогащения IOC

```text
Сбор (фиды, MISP, honeypot, SOC) 
  → Нормализация (STIX/CSV, дедуп)
  → Обогащение (VirusTotal, PassiveTotal, Shodan, WHOIS)
  → Оценка (Admiralty: источник × достоверность)
  → Публикация (MISP event, TAXII)
  → Детекция (Sigma/ATT&CK)
  → Обратная связь (что сработало)
```

```bash
# VT enrichment для хэша
curl -s "https://www.virustotal.com/api/v3/files/<sha256>" -H "x-apikey: $VT_KEY" \
  | jq '.data.attributes.last_analysis_stats'
# passive DNS для домена (пример API)
curl -s "https://api.passivetotal.org/v2/dns/passive?query=evil.example" -u "$PT_USER:$PT_KEY"
```

## Практический разбор: от IOC к кампании

Дано: хэш из фишинга.

1. VT → 30+ детектов, family = `AgentTesla`.
2. Обогащение: домен C2 из отчёта → passive DNS → исторические IP → ASN хостера.
3. MISP: ищем, есть ли эти IOC в чужих событиях → находим общую кампанию с TLP:amber.
4. ATT&CK: мапим TTP (T1566 phishing, T1071 C2) → Navigator показывает пробелы детекта.
5. Sigma: пишем правило на named pipe/процесс, конвертируем в SIEM.

## Частые ошибки аналитика

- **Доверять одному источнику** — верифицируйте через 2–3.
- **Игнорировать TLP** — `tlp:red` нельзя передавать дальше.
- **Публиковать IOC без контекста** — бесполезно и опасно (ложные блокировки).
- **Забыть про срок годности** — IOC стареет; фиксируйте `valid_from`/`valid_until`.
- **Путать атрибуцию и индикацию** — «совпадает с APT28» ≠ «это APT28».

## Квиз

```quiz
- question: "Чем TTP ценнее IOC?"
  options:
    - "TTP описывают поведение противника и устойчивы к смене инфраструктуры"
    - "TTP дешевле"
    - "IOC никогда не устаревают"
    - "Ничем, это одно и то же"
  answer: 0
- question: "Что описывает Diamond Model?"
  options:
    - "Четыре вершины: adversary, capability, infrastructure, victim"
    - "Этапы атаки"
    - "Формат хэшей"
    - "Типы шифрования"
  answer: 0
- question: "Что такое STIX?"
  options:
    - "Язык описания угроз для обмена данными"
    - "Сканер портов"
    - "Тип malware"
    - "Протокол DNS"
  answer: 0
- question: "Для чего используют MISP?"
  options:
    - "Для обмена и корреляции индикаторов угроз между организациями"
    - "Для сканирования сетей"
    - "Для расшифровки трафика"
    - "Для хранения паролей"
  answer: 0
- question: "Что обязательно указывать рядом с индикатором?"
  options:
    - "Уровень уверенности и оценку источника"
    - "Свой пароль"
    - "Только дату"
    - "Ничего"
  answer: 0
```

## Где пригодится

- **SOC/IR:** обогащение инцидентов и построение детекций.
- **CTF (OSINT):** структурировать разрозненные подсказки в кампанию.
- **Threat intel:** публикация и обмен качественными данными.
- **Работа:** стратегические отчёты о рисках.
