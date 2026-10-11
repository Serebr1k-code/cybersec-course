---
id: osint-cert-transparency
title: "Certificate Transparency: добыча поддоменов из CT-логов"
category: osint
parent: osint-infra-network
difficulty: medium
order: 2
tags: [ct, crt.sh, subdomain, certificates, recon]
prerequisites: [osint-dns-recon]
useful_for:
  - "Bug bounty: полный охват поддоменов"
  - "Пентест: карта внешней поверхности"
estimated_minutes: 45
summary: "Как устроены Certificate Transparency-логи, как из них вытаскивать поддомены через crt.sh, Censys и API, и как читать SAN."
---

Certificate Transparency (CT) — публичный, только-дописываемый журнал всех выпущенных TLS-сертификатов. Каждый удостоверяющий центр обязан публиковать выданные сертификаты. Для разведки это золотая жила: в сертификате перечислены **все имена**, на которые он выдан (поле SAN), включая внутренние, dev- и давно забытые хосты.

Главное свойство CT-логов — они **append-only**: запись нельзя удалить. Даже если компания отозвала сертификат и снесла DNS-запись, имя навсегда останется в публичном журнале. Именно поэтому CT — лучший пассивный источник поддоменов: вы ничего не отправляете на цель и не «светитесь» перед её firewall.

## Что такое CT-лог

В экосистеме CT три роли (RFC 6962):

- **Log** — сервер, принимающий цепочки сертификатов (`ct/v1/add-chain`) и возвращающий подписанное обещание (SCT). Примеры: `ct.googleapis.com/logs/argon2024`, `oak.ct.letsencrypt.org/2024h1`, Cloudflare Nimbus.
- **Monitor** — клиент, который забирает все записи (`ct/v1/get-entries`) и ищет интересные домены. Именно монитором работает crt.sh.
- **Auditor** — проверяет криптографическую целостность лога (Merkle-доказательства).

Ключевые термины:

- **SCT** (Signed Certificate Timestamp) — доказательство, что сертификат занесён в лог. Браузеры Chrome/Safari требуют наличия SCT, иначе считают сертификат недоверенным.
- **Merkle tree** — структура из хэшей, позволяющая доказать включение записи, не скачивая весь лог.
- **Precertificate / final certificate** — в логе часто две записи на один сертификат: precert (с «poison»-расширением) и финальный.

Практический вывод: если домен выпускал сертификат на `vpn.example.com`, `*.dev.example.com`, `jenkins.example.com` — эти имена навсегда остались в публичных логах, даже если DNS уже не резолвится.

## crt.sh: самый простой вход

crt.sh — публичный поисковик по CT-логам, не требует ключей и умеет отдавать JSON.

```bash
# все записи по домену, включая поддомены
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | python3 -c 'import sys,json;print("\n".join(sorted({n.strip() for e in json.load(sys.stdin) for n in e["name_value"].split(chr(10))})))'

# только не истёкшие и выданные после даты
curl -s "https://crt.sh/?q=%25.example.com&exclude=expired&output=json" -o ct.json

# одним jq-однострочником
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | tr '[:upper:]' '[:lower:]' | sort -u
```

Разбор `name_value`: в одном сертификате может быть несколько имён, разделённых переводом строки; `%25` — это URL-кодирование `%`, то есть wildcard `%.example.com`. Всегда убирайте дубликаты и отдельно сохраняйте записи вида `*.example.com` (они маскируют реальные имена, но подтверждают зону).

Полезные параметры crt.sh:

| Параметр | Смысл |
|---|---|
| `q=%25.example.com` | все записи, содержащие подстроку (включая поддомены) |
| `q=example.com` | точное совпадение по имени |
| `exclude=expired` | убрать истёкшие сертификаты |
| `exclude=ca` | убрать записи CA-сертификатов |
| `output=json` | машиночитаемый вывод |
| `output=csv` | CSV для таблиц |

Учтите: crt.sh бывает перегружен и отдаёт `502`. В скриптах добавляйте `--retry 3 --retry-delay 5` к curl.

## API CT-логов напрямую

Когда crt.sh недоступен, запросы идут к самому логу. Каждый лог реализует набор методов RFC 6962.

```bash
# signed tree head — размер и корень дерева
curl -s "https://ct.googleapis.com/logs/argon2024/ct/v1/get-sth"

# диапазон записей лога (индекс start..end)
curl -s "https://ct.googleapis.com/logs/argon2024/ct/v1/get-entries?start=0&end=63" \
  | python3 -c 'import sys,json;[print(e["leaf_input"][:40]) for e in json.load(sys.stdin)["entries"]]'
```

`leaf_input` — base64 MerkleTreeLeaf; имена внутри закодированы ASN.1. Разбирать листья вручную не нужно — используйте `ctutils`, библиотеку `certstream` или агрегаторы. Список всех активных логов держит Google в `https://www.gstatic.com/ct/log_list/v3/log_list.json`.

## Censys, FOFA и SSLMate

Агрегаторы удобнее «сырого» лога, потому что индексируют имена и хостят поиск:

- **Censys** — запрос `services.tls.certificates.leaf_data.names: example.com` находит все хосты, где в цепочке встречается это имя.
- **FOFA** — `cert="example.com"` (аналогично для поддоменов).
- **Shodan** — `ssl.cert.subject.CN:example.com` и `ssl.cert.extensions` с SAN.
- **SSLMate certspotter** — `https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names`.

```bash
# SSLMate certspotter: все имена по домену через API
curl -s "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names" \
  | jq -r '.[].dns_names[]' | sort -u
```

## certstream: мониторинг в реальном времени

`certstream` подписывается на поток новых сертификатов и отдаёт их в момент выпуска. Это идеально для мониторинга: как только у цели появится новый `staging.example.com`, вы узнаете об этом сразу.

```python
import certstream

def on_message(message, context):
    if message["message_type"] != "certificate_update":
        return
    for name in message["data"]["leaf_cert"]["all_domains"]:
        if "example.com" in name:
            print(name)

certstream.listen_for_events(on_message, url="wss://certstream.calidog.io/")
```

## Wildcard и SAN: как читать правильно

| Что видно | Что это значит |
|---|---|
| `*.example.com` | wildcard — реальные имена скрыты, но сертификат подтверждает существование зоны |
| `a.example.com`, `b.example.com` в одном SAN | один сервер обслуживает несколько хостов — связь |
| `dev.example.com` в CT, но DNS не резолвится | «мёртвый» хост: кандидат на subdomain takeover |
| Сертификат от Let's Encrypt на `internal.example.com` | внутренний хост случайно засветился в публичном логе |
| Сертификат на IP-адрес | сервис без домена — прямой кандидат на порт-скан |

Важный нюанс: wildcard `*.example.com` НЕ раскрывает конкретные имена, но подтверждает, что зона живёт и кто-то выпускает для неё сертификаты. Комбинируйте CT с перебором DNS (например, `dnsx` по словарю) — wildcard подскажет, что перебор имеет смысл.

## От CT к реальной карте

1. Выгрузите все имена (`crt.sh` или certspotter).
2. Нормализуйте: нижний регистр, убрать `*`, убрать дубли, отфильтровать `example.com` и `www.example.com`.
3. Проверьте резолв (`dnsx -d example.com -w names.txt`), отделив живые от мёртвых.
4. Мёртвые имена с CNAME на сторонний сервис — проверьте на **subdomain takeover**.
5. Свежие записи (последние недели) часто указывают на активную разработку — `dev`, `staging`, `api-v2`.

## Полный сквозной пример

```bash
# 1) выгрузка имён из CT
curl -s --retry 3 "https://crt.sh/?q=%25.example.com&exclude=expired&output=json" \
  | jq -r '.[].name_value' | tr '[:upper:]' '[:lower:]' | tr ',' '\n' | sort -u > names.txt
wc -l names.txt

# 2) нормализация: убрать wildcard и apex
grep -v '^\*' names.txt | grep -v '^example.com$' | sort -u > clean.txt

# 3) проверка резолва (живые/мёртвые)
dnsx -l clean.txt -a -resp -o alive.txt
comm -23 <(sort clean.txt) <(cut -d' ' -f1 alive.txt | sort) > dead.txt

# 4) проверка мёртвых на CNAME (takeover-кандидаты)
while read h; do dig +short CNAME "$h"; done < dead.txt | sort -u
```

Ожидаемый вывод: `alive.txt` содержит хосты с A-записями, `dead.txt` — имена без DNS, но с сертификатом. Строки вида `foo.example.com. CNAME cname.vercel-dns.com.` в шаге 4 — сигнал проверить takeover.

## Инструменты и флаги

| Инструмент | Команда | Назначение |
|---|---|---|
| crt.sh | `curl "https://crt.sh/?q=%25.d&output=json"` | массовая выгрузка имён |
| subfinder | `subfinder -d example.com -all -silent` | агрегирует CT + другие источники |
| amass | `amass enum -passive -d example.com` | пассивный сбор, включая CT |
| dnsx | `dnsx -l names.txt -a -resp` | проверка резолва |
| httpx | `httpx -l alive.txt -title -status-code` | живой веб-слой |
| certstream | python-библиотека | поток новых сертификатов |
| ctutils | `ctutils` | разбор листьев лога |

## Частые ошибки

- **Игнорировать wildcard**: `*.example.com` не даёт имён, но подтверждает зону — не считайте это пустым результатом.
- **Забыть про `exclude=expired`**: без него crt.sh вернёт тысячи исторических записей, часть уже неактуальна.
- **Не проверять DNS**: имя из CT ≠ живой хост; многие сертификаты выданы на тестовые среды.
- **Считать CT пассивным «навсегда»**: сам crt.sh пассивен, но активные DNS-запросы к найденным именам уже заметны цели.
- **Терять SAN-мусор**: `name_value` может содержать запятые и переводы строк — нормализуйте перед дедупликацией.

## Что делать дальше / решение

- **Нужен полный охват** → `subfinder -all` + crt.sh + certspotter, объединить и дедуплицировать.
- **Нужны свежие хосты** → включите certstream и мониторьте выпуск новых сертификатов.
- **Нужны takeover-кандидаты** → отфильтруйте нерезолвящиеся имена и проверьте их CNAME на висячие записи (`network`-урок про DNS).
- **Нужен живой веб-слой** → прогоните `alive.txt` через `httpx -title -tech-detect`.

## Мониторинг и инвентаризация сертификатов

CT полезен не только для атаки, но и для защиты — инвентаризации собственных сертификатов:

- **Обнаружение теневого выпуска**: если кто-то выпустил сертификат на ваш домен без ведома команды — это сигнал компрометации DNS/аккаунта.
- **Контроль поддоменов**: периодический прогон crt.sh показывает новые хосты, появившиеся между релизами.
- **Проверка после инцидента**: имена в CT подскажут, какие внутренние хосты «засветились» наружу.
- **Автоматизация**: cron + `curl crt.sh` + diff против прошлого списка → алерт на новое имя.

```bash
# ежедневный diff новых имён
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u > today.txt
comm -13 <(sort prev.txt) today.txt   # только новые
```

Так CT превращается в дешёвую систему раннего предупреждения о новых активах и утечках имён.

## Квиз

```quiz
- question: "Какое поле сертификата перечисляет все имена, на которые он выдан?"
  options:
    - "CN"
    - "SAN (Subject Alternative Name)"
    - "SCT"
    - "Merkle root"
  answer: 1
- question: "Почему CT-логи — хороший источник поддоменов?"
  options:
    - "Они хранят пароли администраторов"
    - "Каждый выданный сертификат публикуется и содержит список имён"
    - "Они содержат только активные DNS-записи"
    - "Они доступны только пентестерам"
  answer: 1
- question: "Что означает запись `*.example.com` в CT?"
  options:
    - "Конкретный поддомен"
    - "Wildcard-сертификат: зона существует, но имена скрыты"
    - "Ошибку в логе"
    - "Почтовый сервер"
  answer: 1
- question: "Имя есть в CT, но DNS не резолвится. Что это может быть?"
  options:
    - "Ошибка CT-лога"
    - "Мёртвый хост — кандидат на subdomain takeover"
    - "Всегда действующий сервис"
    - "Указатель на почтовый сервер"
  answer: 1
- question: "Как убрать из вывода crt.sh истёкшие сертификаты?"
  options:
    - "Параметром `exclude=expired`"
    - "Ключом `--alive`"
    - "Флагом `-x`"
    - "Никак, crt.sh их не возвращает"
  answer: 0
```

## Где пригодится

- **CTF:** задачи на поиск скрытого поддомена, где имя утекло только в CT.
- **Bug bounty:** расширение охвата scope за счёт забытых dev/staging-хостов.
- **Пентест:** картирование внешней поверхности и поиск целей для subdomain takeover.
- **Blue team:** инвентаризация собственных сертификатов и поиск утечек внутренних имён.
