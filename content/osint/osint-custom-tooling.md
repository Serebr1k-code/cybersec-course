---
id: osint-custom-tooling
title: "Кастомные OSINT-инструменты и автоматизация API"
category: osint
parent: osint-automation
difficulty: hard
order: 4
tags: [automation, api, tooling, scripting, osint, python]
prerequisites: [osint-automation]
useful_for:
  - "CTF OSINT"
  - "Bug bounty"
  - "Threat intel"
  - "Работа: автоматизация разведки"
estimated_minutes: 50
summary: "Как строить собственные OSINT-инструменты: работа с API, нормализация данных, граф связей и пайплайн сбора с соблюдением rate limit."
---
Готовые инструменты (SpiderFoot, Maltego, recon-ng) закрывают 80% задач, но реальная разведка требует своей автоматизации: объединить источники, нормализовать данные, построить граф и повторять по расписанию. В этом уроке — как писать собственные инструменты: от работы с API и лимитов до нормализации, хранения, визуализации и мониторинга.

## Архитектура OSINT-пайплайна

1. **Сбор (collectors):** модули на каждый источник (DNS, CT, WHOIS, Shodan, соцсети).
2. **Нормализация:** приведение к единой схеме (entity: type, value, source, confidence).
3. **Обогащение (enrichment):** добавление данных к сущностям (IP → ASN, email → домен).
4. **Корреляция:** связывание сущностей (граф).
5. **Хранение:** SQLite/Neo4j/JSON.
6. **Визуализация:** Graphviz, Maltego, Neo4j Browser.
7. **Планирование:** cron/очереди, ретраи, rate limit.

Ключевые принципы: идемпотентность, дедупликация, учёт лимитов API, логирование источника для каждой сущности.

## Модель сущностей и нормализация

Единая схема — фундамент: без неё данные из разных источников не склеиваются.

```python
# {type, value, source, confidence}
add("subdomain", "dev.example.com", "crt.sh", 0.9)
add("ip", "203.0.113.10", "dns", 0.7)
add("asn", "AS12345", "bgp", 0.8)
```

Типы: domain, subdomain, ip, asn, email, person, org, cert, url, hash. `confidence` — вес источника; итоговая оценка — взвешенная.

## Работа с API: аутентификация, лимиты, пагинация

- **Ключи** — только в переменных окружения (`os.environ["SHODAN_API_KEY"]`).
- **Лимиты** — читайте заголовки `X-RateLimit-Remaining`; уважайте 429.
- **Пагинация** — `start_index`/`page`/`cursor`; собирайте до пустой страницы.
- **Таймауты** — всегда ставьте `timeout`, иначе скрипт «зависнет».

```python
import os, time, requests

KEY = os.environ["CRTSH"]  # не хардкодим

def get(url, headers=None, tries=3):
    for i in range(tries):
        try:
            r = requests.get(url, headers=headers, timeout=20)
            if r.status_code == 429:            # rate limit
                time.sleep(2 ** i)              # экспоненциальный backoff
                continue
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            if i == tries - 1:
                print("FAIL", url, e)
                return None
            time.sleep(2 ** i)
```

## Код сборщика: crt.sh + DNS

```python
import json, socket

ENTITIES = []

def add(etype, value, source, conf=0.5):
    ENTITIES.append({"type": etype, "value": value, "source": source, "confidence": conf})

def crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for row in requests.get(url, timeout=30).json():
        for name in row["name_value"].split("\n"):
            add("subdomain", name.strip().lower(), "crt.sh", 0.9)

def resolve(domain):
    try:
        for ip in socket.gethostbyname_ex(domain)[2]:
            add("ip", ip, "dns", 0.7)
    except socket.gaierror:
        pass

def save(path):
    seen, uniq = set(), []
    for e in ENTITIES:
        k = (e["type"], e["value"])
        if k not in seen:
            seen.add(k); uniq.append(e)
    json.dump(uniq, open(path, "w"), ensure_ascii=False, indent=2)

if __name__ == "__main__":
    crtsh("example.com")
    save("entities.json")
```

## Хранение: SQLite и идемпотентность

Для масштаба нужна структура, а не JSON на диске:

```python
import sqlite3
db = sqlite3.connect("osint.db")
db.execute("""CREATE TABLE IF NOT EXISTS entities(
  type TEXT, value TEXT, source TEXT, confidence REAL, ts TEXT,
  PRIMARY KEY(type, value, source))""")
db.execute("INSERT OR IGNORE INTO entities VALUES (?,?,?,?,datetime('now'))",
           ("subdomain", "dev.example.com", "crt.sh", 0.9))
db.commit()
```

`PRIMARY KEY` + `INSERT OR IGNORE` даёт идемпотентность и дедупликацию «бесплатно».

## Граф связей и визуализация

```python
import networkx as nx, json
G = nx.DiGraph()
for e in json.load(open("entities.json")):
    G.add_node(e["value"], type=e["type"])
nx.drawing.nx_pydot.write_dot(G, "graph.dot")
```

```bash
dot -Tpng graph.dot -o graph.png
dot -Tsvg graph.dot -o graph.svg
```

Читаем граф: **кластеры** = инфраструктура одной организации; **изолированные узлы** = новые активы; **мосты** = критичные связи (шлюзы, подрядчики); **диффы во времени** = новые риски.

## Разобранный пример: пайплайн для домена

Дано: цель `example.com`.

1. Сбор поддоменов из CT (crt.sh) и DNS-перебора.
2. Резолв в IP, обогащение ASN/geo через API.
3. Нормализация в единый JSON (type/value/source/confidence).
4. Дедупликация и приоритизация по confidence.
5. Граф домен → поддомен → IP → ASN.
6. Запуск по cron ежедневно, дифф с прошлым результатом → алерты на новые сущности.

## Диффы и мониторинг

```bash
# сравнить два прогона и вывести только новые значения
comm -13 <(jq -r '.[].value' old.json | sort -u) \
         <(jq -r '.[].value' new.json | sort -u)
```

Дифф — сердце мониторинга: новые поддомены, сертификаты, IP появляются между прогонами. Настройте уведомления (Telegram-бот, email).

## Частые ошибки

- **Хардкод ключей.** Утечка через репозиторий; используйте env.
- **Игнорировать лимиты.** Бан API и потеря источника.
- **Нет дедупликации.** Дубли искажают граф и выводы.
- **Потеря источника.** Без source невозможно оценить достоверность.
- **Монолитный скрипт.** Тяжело поддерживать; делите на модули.
- **Забыть про идемпотентность.** Повторный запуск не должен дублировать данные.
- **Бесконечный ретрай.** Всегда ограничивайте число попыток.

## Справочные таблицы

| Слой | Инструмент |
|---|---|
| Сбор | requests, httpx, curl |
| Нормализация | Python dataclass/dict |
| Хранение | SQLite, PostgreSQL, Neo4j |
| Граф | networkx, igraph |
| Визуализация | Graphviz, Maltego, Gephi |
| Планирование | cron, APScheduler, Celery |

## Что дальше / решение

Собрав минимальный пайплайн, наращивайте: добавляйте collectors по источникам, вводите confidence-модель, подключайте уведомления. Решение по архитектуре: «один скрипт» для разовой задачи, «модульный пайплайн + БД» для регулярной разведки, «граф + диффы» для мониторинга бренда. Никогда не храните ключи в коде и всегда логируйте источник каждой сущности.

## Плагинная архитектура

```python
COLLECTORS = {}
def collector(name):
    def deco(fn):
        COLLECTORS[name] = fn
        return fn
    return deco

@collector("crtsh")
def crtsh(domain): ...
@collector("dns")
def dns(domain): ...

def run(domain):
    for name, fn in COLLECTORS.items():
        try:
            fn(domain)
        except Exception as e:
            print("collector", name, "failed:", e)
```

Единый интерфейс `collect(target)` позволяет добавлять источники без правки ядра. Изоляция ошибок: падение одного коллектора не роняет весь прогон.

## Обогащение и корреляция

- **IP → ASN/geo** (ipinfo, Team Cymru, MaxMind).
- **Email → домен → MX/SPF**.
- **Домен → CT → поддомены → IP**.
- **Хэш → VirusTotal/MalwareBazaar** (IOC-обогащение).

```python
def enrich_ip(ip, key):
    time.sleep(1)  # лимит
    r = requests.get(f"https://ipinfo.io/{ip}/json?token={key}", timeout=20)
    return r.json() if r.ok else {}
```

Корреляция: одна ASN, сертификат или адрес у разных доменов → общая инфраструктура.

## Интеграция с готовыми инструментами

Свой пайплайн не отменяет чужих инструментов — вызывайте их как подпроцессы и парсите вывод:

```python
import subprocess, json
def subfinder(domain):
    out = subprocess.run(["subfinder", "-d", domain, "-silent", "-json"],
                         capture_output=True, text=True, timeout=300).stdout
    for line in out.splitlines():
        add("subdomain", json.loads(line)["host"], "subfinder", 0.85)
```

Так `subfinder`, `amass`, `httpx`, `nuclei` встраиваются в единый конвейер, а результаты нормализуются в вашу схему.

## Секреты и безопасность пайплайна

- Ключи — в env или менеджере секретов (Vault, SOPS), не в коде и не в git.
- `.gitignore` для дампов и БД (там PII и токены).
- Логи не должны содержать ключи и пароли.
- Ограничивайте права API-ключей (read-only, где возможно).

## Масштабирование и параллелизм

```python
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=8) as ex:
    ex.map(lambda d: resolve(d), subdomains)
```

Параллелизм ускоряет сбор, но соблюдайте лимиты: общий rate-limiter на источник, семафоры, очереди. Для больших прогонов — Celery/Redis.

## Тестирование и качество

- Юнит-тесты коллекторов на записанных ответах (fixtures) — не бейте реальные API в тестах.
- Валидация схемы сущностей (type/value непустые, confidence в [0,1]).
- Логирование: для каждой сущности — источник и время.
- Метрики: сколько сущностей собрал каждый коллектор, сколько ошибок.

## Практический пример: минимальный инструмент целиком

```python
#!/usr/bin/env python3
import sys, json, socket, requests

def add(store, etype, value, source, conf=0.5):
    store.append({"type": etype, "value": value, "source": source, "confidence": conf})

def crtsh(store, domain):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        for row in r.json():
            for n in row["name_value"].split("\n"):
                add(store, "subdomain", n.strip().lower(), "crt.sh", 0.9)
    except Exception as e:
        print("crt.sh:", e, file=sys.stderr)

def resolve(store, name):
    try:
        for ip in socket.gethostbyname_ex(name)[2]:
            add(store, "ip", ip, "dns", 0.7)
    except socket.gaierror:
        pass

def main(domain):
    store = []
    crtsh(store, domain)
    for s in {e["value"] for e in store if e["type"] == "subdomain"}:
        resolve(store, s)
    seen, uniq = set(), []
    for e in store:
        k = (e["type"], e["value"])
        if k not in seen:
            seen.add(k); uniq.append(e)
    json.dump(uniq, open("entities.json", "w"), ensure_ascii=False, indent=2)
    print(f"{len(uniq)} уникальных сущностей")

if __name__ == "__main__":
    main(sys.argv[1])
```

Запуск:

```bash
python3 recon.py example.com
```

Вывод:

```text
142 уникальных сущностей
```

## Критерии «хорошего» инструмента

| Критерий | Почему важно |
|---|---|
| Идемпотентность | повторный запуск не плодит дубли |
| Источник у каждой сущности | оценка достоверности |
| Ограничение лимитов | не потерять API |
| Модульность | легко добавлять источники |
| Логи и метрики | видно, что упало |
| Безопасность секретов | нет утечек |

## Дополнительные заметки и анти-паттерны

- **Секреты в git** — самая частая утечка; используйте pre-commit-хуки со сканером секретов.
- **Нет таймаутов** — скрипт зависает на медленном источнике; ставьте `timeout` везде.
- **Игнорирование ошибок** — молчаливый `except: pass` прячет сломанный источник.
- **Отсутствие версионирования схемы** — при смене полей старые данные ломают анализ.
- **Нет лимитов на параллелизм** — тысячи потоков забанят источник и ваш IP.

Хороший пайплайн логирует каждый шаг, хранит источник и уважает лимиты; плохой — «работает на моей машине один раз».

## Квиз

```quiz
- question: "Какой шаг в OSINT-пайплайне приводит данные к единой схеме?"
  options:
    - "Сбор"
    - "Нормализация"
    - "Визуализация"
    - "Планирование"
  answer: 1
- question: "Зачем каждой сущности хранить поле source?"
  options:
    - "Для красоты"
    - "Чтобы оценивать достоверность и прослеживать происхождение"
    - "Чтобы ускорить DNS"
    - "Чтобы сменить MX"
  answer: 1
- question: "Как безопасно хранить ключи API в инструменте?"
  options:
    - "В коде"
    - "В переменных окружения"
    - "В README"
    - "В комментарии"
  answer: 1
- question: "Что даёт ежедневный дифф прогонов?"
  options:
    - "Пароли"
    - "Обнаружение новых сущностей (поддомены, сертификаты)"
    - "Смену TLS"
    - "Удаление DNS"
  answer: 1
- question: "Почему важна дедупликация сущностей?"
  options:
    - "Экономит место"
    - "Дубли искажают корреляцию и выводы"
    - "Ускоряет сеть"
    - "Меняет SPF"
  answer: 1
```

## Где пригодится

- **CTF (OSINT):** быстро собрать все источники по цели одним скриптом.
- **Bug bounty:** непрерывный мониторинг новых поддоменов и активов.
- **Threat intel:** пайплайн обогащения IOC.
- **Работа:** построение внутренней разведывательной платформы.
