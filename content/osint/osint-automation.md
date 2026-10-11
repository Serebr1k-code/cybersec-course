---
id: osint-automation
title: "Автоматизация OSINT: recon-ng, SpiderFoot, Maltego"
category: osint
parent: osint-intro
difficulty: medium
order: 3
tags: [automation, recon-ng, spiderfoot, maltego, theharvester, tooling]
prerequisites: [osint-intro, osint-search-operators]
useful_for:
  - "Масштабная разведка"
  - "Bug bounty и пентест"
  - "CTF категория OSINT"
estimated_minutes: 45
summary: "Фреймворки для автоматизации разведки: recon-ng, SpiderFoot, Maltego, theHarvester; конвейеры, API-ключи, визуализация и ограничения."
---

Когда источников десятки, ручной сбор не масштабируется. Фреймворки автоматизируют запросы, объединяют результаты и строят **графы связей**. Здесь — обзор и практические конвейеры.

## theHarvester

Простейший старт: собирает email, поддомены, хосты, имена из публичных источников.

```bash
theHarvester -d example.com -b google,bing,linkedin,duckduckgo -l 500 -f report.html
```

Флаги: `-d` домен, `-b` источники, `-l` лимит, `-f` вывод. Работает с API-ключами (Shodan, Hunter, SecurityTrails).

## recon-ng

Модульный фреймворк с «рабочими пространствами». Логика: создаёте workspace → добавляете домен → запускаете модули → результаты складываются в БД.

```bash
recon-ng
# внутри:
workspaces create example
db insert domains
# ввести домен example.com
marketplace install all
modules load recon/domains-hosts/hackertarget
run
modules load recon/hosts-ports/shodan_ip
run
show hosts
```

Модули покрывают: поддомены, порты, email, контакты, соцсети. Всё сохраняется в SQLite — можно экспортировать.

## SpiderFoot

Автоматический сканер-«краулер» по сотням модулей. Запускает цепочку: домен → поддомены → IP → порты → сервисы → утечки.

```bash
spiderfoot -s example.com -t DOMAIN_NAME -m all -o csv -q
# или веб-интерфейс:
spiderfoot -l 127.0.0.1:5001
```

Сильная сторона — **граф связей** и автоматическое обогащение. Минус — шум и много запросов (риск раскрытия).

## Maltego

Визуальный инструмент: сущности (домен, email, человек, IP) соединяются **трансформами**. Отлично для **презентации** связей.

- Community Edition бесплатна (лимит трансформов).
- Строит граф: `person → email → username → account`.
- Экспорт в отчёт.

## Организация конвейера

1. **Вход**: seed (домен, email, компания).
2. **Сбор**: несколько инструментов параллельно.
3. **Дедуп/нормализация**: `sort -u`, `jq`, объединение в общую таблицу.
4. **Обогащение**: прогон через Shodan/HIBP/API.
5. **Визуализация**: Maltego/граф.
6. **Отчёт**.

```bash
# Пример: собрать поддомены и проверить, что живо
subfinder -d example.com -silent > subs.txt
cat subs.txt | httpx -silent -status-code -title > live.txt
```

## API-ключи

Большинство модулей требуют ключей (Shodan, Censys, Hunter, VirusTotal, SecurityTrails). Храните их **вне репозитория** (env-переменные, менеджер секретов), не коммитьте.

## Ограничения и риски

- **Шум**: автоматические запросы видны цели (DNS, сканы).
- **Ложные срабатывания**: агрегированные данные требуют проверки.
- **Стоимость**: платные API быстро расходуются.
- **Качество**: «собрать всё» ≠ «понять». Автоматизация ускоряет, но анализ за вами.

## Разобранный пример

Задача: за 30 минут получить карту `example.com`.

1. `theHarvester -d example.com -b all` → email и поддомены.
2. `subfinder -d example.com` → ещё поддомены.
3. `httpx` → какие живые, заголовки, коды.
4. `spiderfoot -s example.com` → граф и обогащение.
5. Сводка в отчёт с пометками достоверности.

## Частые ошибки

- **Запускать всё «на максимум»** без ограничения → бан и шум.
- **Коммитить API-ключи** в репозиторий.
- **Верить автоматическим результатам** без проверки.
- **Игнорировать OPSEC** (все запросы идут с вашего IP).
- **Дублировать источники** и терять дедупликацию.
- **Не логировать источник** каждого результата.

## Сравнение фреймворков

| Фреймворк | Сильная сторона | Слабость |
|---|---|---|
| theHarvester | быстрый старт, email/хосты | мало модулей |
| recon-ng | модульность, БД, workspace | устаревшие модули |
| SpiderFoot | автоматизация, граф, сотни модулей | шум, ресурсоёмкость |
| Maltego | визуализация, трансформы | лицензии, ручной запуск |
| SpiderFoot HX | облако, коллаборация | платно |

Выбор: быстрая разведка → theHarvester; структурированный сбор → recon-ng; комплексный скан → SpiderFoot; презентация связей → Maltego.

## Нормализация и объединение результатов

Автоматика даёт разнородные форматы. Приведите их к единой схеме:

```bash
# собрать поддомены из разных источников, дедуплицировать
{ subfinder -d example.com -silent; assetfinder --subs-only example.com; \
  curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value'; } \
  | tr '[:upper:]' '[:lower:]' | sort -u > all_subs.txt
wc -l all_subs.txt
```

Дальше — обогащение (резолв, HTTP, технологии) и запись в общую таблицу. Ключ: **дедупликация** и **источник** каждого результата.

## Планирование и мониторинг

Разовая разведка устаревает. Настройте регулярный прогон:

```bash
# cron: ежедневно собирать и диффить новые поддомены
0 3 * * * cd /opt/recon && ./collect.sh example.com >> run.log 2>&1
```

```bash
# collect.sh: новый результат сравнить с прошлым
new=$(mktemp)
subfinder -d example.com -silent | sort -u > "$new"
comm -13 prev_subs.txt "$new" > newly_found.txt
mv "$new" prev_subs.txt
[ -s newly_found.txt ] && notify "новые поддомены: $(wc -l < newly_found.txt)"
```

Так вы ловите новые активы сразу, а не через месяцы.

## theHarvester: флаги и источники

`theHarvester` — быстрый сбор email, поддоменов, хостов и имён из десятков источников.

```bash
theHarvester -d example.com -b all -l 500 -f out.html
# -d домен, -b источник (bing, duckduckgo, crtsh, virustotal, dnsdumpster, all)
# -l лимит результатов, -f отчёт (html/xml)
# -s начало диапазона для перебора хостов, -v вербозно
theHarvester -d example.com -b crtsh,virustotal,dnsdumpster
# выгрузить email и хосты
theHarvester -d example.com -b all | tee harvest.txt
grep -oE '[a-z0-9._%+-]+@[a-z0-9.-]+' harvest.txt | sort -u > emails.txt
```

Комбинация `crtsh` + `virustotal` + `dnsdumpster` даёт лучший охват поддоменов; поисковики — email и имена.

## recon-ng: рабочие модули

recon-ng — модульный фреймворк с БД; результаты сохраняются и обогащаются между модулями.

```bash
recon-ng
> marketplace search shodan
> marketplace install recon/domains-hosts/hackertarget
> marketplace install recon/hosts-ports/shodan_ip
> db insert domains
domain (TEXT): example.com
> modules load recon/domains-hosts/hackertarget
> run
> show hosts
> modules load recon/hosts-ports/shodan_ip
> run
> show ports
> reporting list
> reporting run pushpin hosts -o /tmp/hosts.html
```

Ключ: recon-ng хранит всё в SQLite, поэтому модули «видят» результаты друг друга (домен → хосты → порты → контакты). API-ключи задаются через `keys add shodan_api <key>`.

## SpiderFoot: API и автоматизация

SpiderFoot агрегирует 200+ модулей и умеет запускаться как сервис с REST API.

```bash
# сканирование из CLI
spiderfoot -s example.com -t DOMAIN_NAME -m all -o csv -q > sf.csv
# как сервис (веб/API)
spiderfoot -l 127.0.0.1:5001
curl -s "http://127.0.0.1:5001/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"scanname":"ex","scantarget":"example.com","modulelist":"all"}'
# получить результаты
curl -s "http://127.0.0.1:5001/api/v1/scaneventresults?scan_id=<id>"
```

SpiderFoot автоматически коррелирует: email ↔ домен ↔ IP ↔ соцсети, строя граф связей.

## Maltego: трансформы и графы

Maltego — визуальный граф-инструмент; ценность — в **трансформах** (запрос к внешнему источнику). Логика работы:

1. Кладём сущность (Domain, Email, Person).
2. Запускаем трансформы (To DNS Name, To Email addresses, To Social Media).
3. Строим граф, ищем кластеры и мосты.

```bash
# собственный трансформ: HTTP-сервис, возвращающий XML
python3 - <<'PY'
from flask import Flask, request, Response
app = Flask(__name__)
@app.route("/domain_to_subdomains")
def t():
    dom = request.args.get("domain")
    subs = ["www","mail","vpn"]
    items = "".join(f"<Entity Type='DNSName' Value='{s}.{dom}'/>" for s in subs)
    return Response(f"<MaltegoMessage><Entities>{items}</Entities></MaltegoMessage>")
app.run(port=8080)
PY
```

## Организация конвейера: единая точка входа

Автоматизация = цепочка «сбор → нормализация → обогащение → отчёт».

```bash
#!/usr/bin/env bash
set -euo pipefail
DOM="$1"; OUT="recon_$DOM"; mkdir -p "$OUT"
subfinder -d "$DOM" -silent | sort -u > "$OUT/subs.txt"
theHarvester -d "$DOM" -b all 2>/dev/null | tee "$OUT/harvest.txt"
grep -oE '[a-z0-9._%+-]+@[a-z0-9.-]+' "$OUT/harvest.txt" | sort -u > "$OUT/emails.txt"
# обогащение: живы ли поддомены
httpx -l "$OUT/subs.txt" -silent -o "$OUT/alive.txt"
# отчёт
printf 'subs=%s emails=%s alive=%s\n' "$(wc -l <"$OUT/subs.txt")" "$(wc -l <"$OUT/emails.txt")" "$(wc -l <"$OUT/alive.txt")"
```

## Нормализация и объединение результатов

Разные инструменты дают разный формат. Приводите к единой схеме и дедуплицируйте.

```python
import json, csv
rows = []
for line in open("sf.csv"):
    _, _, evt, _, src, data, _, conf = line.rstrip().split(",")
    rows.append({"type": evt, "data": data, "source": src, "confidence": conf})
# дедуп по (type,data)
seen, uniq = set(), []
for r in rows:
    k = (r["type"], r["data"])
    if k not in seen:
        seen.add(k); uniq.append(r)
json.dump(uniq, open("normalized.json", "w"), ensure_ascii=False, indent=2)
```

## Планирование и мониторинг

Для непрерывного мониторинга запускайте пайплайн по расписанию и **диффите** результаты:

```bash
# cron: ежедневный сбор + дифф с прошлым
0 3 * * * /opt/recon/run.sh example.com && diff <(sort recon_example.com/subs.txt) <(sort prev/subs.txt)
```

Новый поддомен/email в диффе → алерт. Это ловит появление новой инфраструктуры, а не только разовый срез.

## Ограничения и риски

- **API-ключи и квоты**: Shodan/Censys/VT имеют лимиты; считайте бюджет запросов.
- **Шум и бан**: агрессивные модули ловят блокировку поисковиков/сайтов.
- **Ложные данные**: без отрицательного контроля FP накапливаются.
- **Юридические границы**: активные модули (порт-скан, brute) требуют авторизации (osint-legal-ethics).
- **OPSEC**: прямые запросы от своего IP видны; при необходимости — прокси/пассивные источники.

## Квиз

```quiz
- question: "Что делает theHarvester?"
  options:
    - "Собирает email, поддомены и хосты из публичных источников"
    - "Сканирует порты"
    - "Расшифровывает пароли"
    - "Строит графы"
  answer: 0
- question: "В чём сильная сторона Maltego?"
  options:
    - "Визуализация связей между сущностями через трансформы"
    - "Сканирование портов"
    - "Брутфорс"
    - "Шифрование"
  answer: 0
- question: "Как хранить API-ключи для инструментов?"
  options:
    - "Вне репозитория — в переменных окружения или менеджере секретов"
    - "В коде"
    - "В README"
    - "В git-коммите"
  answer: 0
- question: "Что важнее всего помнить при автоматизации?"
  options:
    - "Она создаёт шум и требует ручной проверки результатов"
    - "Она полностью невидима"
    - "Она заменяет анализ"
    - "Она не расходует API"
  answer: 0
- question: "Какой конвейер собирает поддомены и проверяет живые?"
  options:
    - "`subfinder | httpx`"
    - "`nmap | sqlmap`"
    - "`whois | dig`"
    - "`gitleaks | trufflehog`"
  answer: 0
```

## Где пригодится

- **Bug bounty:** быстрый старт с широкой картой активов.
- **CTF (OSINT):** автоматизировать перебор источников.
- **Пентест:** собрать поверхность за минуты.
- **Работа:** масштабная разведка и построение графов связей.
