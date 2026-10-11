---
id: osint-censys-fofa
title: "Censys, FOFA и ZoomEye: глубокий поиск по интернету"
category: osint
parent: osint-shodan-dorks
difficulty: medium
order: 1
tags: [censys, fofa, zoomeye, search, fingerprint]
prerequisites: [osint-shodan-dorks]
useful_for:
  - "Картирование внешней поверхности"
  - "Поиск уязвимых сервисов по fingerprint"
estimated_minutes: 50
summary: "Синтаксис поиска Censys/FOFA/ZoomEye, различия в покрытии, поиск по сертификатам, баннерам, favicon и заголовкам, автоматизация через API."
---

Shodan — самый известный, но не единственный сканер интернета. Censys, FOFA и ZoomEye покрывают другие срезы: Censys силён в TLS-сертификатах и хостах, FOFA — в веб-технологиях и favicon, ZoomEye — в азиатском сегменте и промышленных устройствах. Комбинируя их, вы находите то, что пропускает один движок.

## Синтаксис запросов

**Censys** (`search.censys.io`) — поиск по полям хостов и сервисов:

```
services.service_name: HTTP
services.tls.certificates.leaf_data.names: example.com
services.http.response.headers.location: /admin
services.software.product: "nginx"
services.banner: "220 ProFTPD"
```

**FOFA** (`fofa.info`) — фокус на веб-отпечатках:

```
domain="example.com"
cert="example.com"
title="Admin Panel"
header="X-Powered-By: PHP"
body="login"
icon_hash="-1234567890"
port="2375" && country="RU"
```

**ZoomEye** (`zoomeye.org`) — синтаксис, похожий на Shodan:

```
site:example.com
app:"Apache httpd"
port:8080
title:"dashboard"
device:"webcam"
```

## Что искать

- **По домену/сертификату** — все хосты, где встречается имя: находит поддомены и origin-IP.
- **По favicon hash** — уникальный отпечаток иконки (FOFA `icon_hash`); находит все серверы того же продукта, включая закрытые CDN.
- **По баннеру/заголовку** — устаревшие версии (`Apache 2.4.49`), панели (`Grafana`, `Jenkins`).
- **По телу ответа** — строки вроде `X-Debug-Token`, `phpMyAdmin`, `X-Jenkins`.
- **По порту и стране** — `port:2375 country:RU` (открытый Docker API), `port:9200` (Elasticsearch).
- **По устройству** — камеры, роутеры, АСУ ТП.

## Автоматизация через API

```bash
# Censys v2 hosts search
curl -s "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.names%3Aexample.com&per_page=50" \
  -u "$CENSYS_ID:$CENSYS_SECRET" | python3 -m json.tool

# FOFA: qbase64 — base64 от запроса
Q=$(echo -n 'domain="example.com"' | base64)
curl -s "https://fofa.info/api/v1/search/all?key=$FOFA_KEY&qbase64=$Q&fields=host,ip,port,title&size=100" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);[print(r) for r in d.get("results",[])]'

# ZoomEye API
curl -s "https://api.zoomeye.org/host/search?query=app%3A%22nginx%22&page=1" \
  -H "API-KEY: $ZOOMEYE_KEY" | python3 -m json.tool
```

## Favicon-хэшинг

Favicon-хэш — мощный приём: иконка часто одинакова на всех серверах одного продукта/компании, даже за CDN.

```bash
# получить mmh3-хэш favicon (FOFA использует mmh3 без base64)
python3 - <<'PY'
import mmh3, requests
r = requests.get("https://example.com/favicon.ico")
print(mmh3.hash(r.content))          # FOFA icon_hash
PY
# затем в FOFA: icon_hash="<значение>"
```

Так находят origin-серверы за Cloudflare: контент с тем же favicon отдаёт другой IP.

## Сравнение покрытия

| Движок | Сильная сторона | Ограничение |
|---|---|---|
| Shodan | широта, IoT, баннеры | лимиты бесплатного API |
| Censys | TLS/сертификаты, точность | платные запросы |
| FOFA | веб-фингерпринты, favicon | лучший охват Азии |
| ZoomEye | азиатский сегмент, ICS | интерфейс EN/CN |

Всегда проверяйте одну и ту же цель в 2–3 движках: они индексируют разные порты и в разное время.

## Разбор кейса

Задача: найти все инстансы Grafana у организации.

```
# FOFA
title="Grafana" && cert="example.com"
# Censys
services.http.response.html_title: "Grafana" and services.tls.certificates.leaf_data.names: example.com
# ZoomEye
title:"Grafana" site:example.com
```

Результаты объединяем, отсеиваем дубликаты, проверяем версии (`/login` отдаёт версию) и находим устаревшие.

## Частые ошибки

- **Один движок как истина** — покрытие различается; отсутствие результата ≠ отсутствие сервиса.
- **Забыть про устаревание индекса** — баннер мог измениться; подтверждайте активным запросом.
- **Игнорировать favicon/cert-поиск** — часто единственный способ найти origin за CDN.
- **Слепо копировать dorks** — адаптируйте под синтаксис конкретного движка.
- **Не учитывать rate-limit** — API-ключи бесплатных тарифов быстро исчерпываются.

## Практические dorks по движкам

Готовые запросы под типовые задачи:

**Поиск панелей и сервисов:**

```
# Shodan
http.title:"Grafana" country:RU
product:"Elastic" port:9200
"X-Jenkins" 
# FOFA
app="Grafana"
port="2375" && country="RU"
body="phpMyAdmin"
```

**Поиск по сертификатам (origin discovery):**

```
# Censys
services.tls.certificates.leaf_data.names: example.com
# FOFA
cert="example.com"
```

**Поиск по favicon:**

```
# FOFA
icon_hash="-1234567890"
# Shodan
http.favicon.hash:-1234567890
```

## Автоматизация и лимиты

Бесплатные тарифы быстро расходуются, поэтому автоматизируйте экономно:

```bash
# FOFA: запрос + пагинация
Q=$(echo -n 'domain="example.com"' | base64)
for p in 1 2 3; do
  curl -s "https://fofa.info/api/v1/search/all?key=$FOFA_KEY&qbase64=$Q&size=100&page=$p" \
    | jq -r '.results[][0]'
  sleep 2
done
```

Кэшируйте результаты локально, соблюдайте rate-limit, используйте `fields` для экономии квоты.

## Атрибуция и обогащение результатов

Найденные хосты нужно обогатить:

1. **ASN/владелец** — по IP (см. osint-whois-asn).
2. **Домен** — по reverse DNS (см. osint-reverse-dns).
3. **Технология/версия** — по баннеру и заголовкам.
4. **Уязвимость** — по версии (CVE) в связке с vuln-сканерами.
5. **Гео/хостинг** — страна, облако, CDN.

Так «список IP» превращается в приоритизированный список целей.

## Продвинутый синтаксис: поля, операторы и логика

У каждого движка своя «грамматика» полей. Понимание полей важнее заучивания примеров.

**Censys (v2, язык «CenQL»):**

| Поле | Смысл | Пример |
|------|-------|--------|
| `services.service_name` | протокол сервиса | `services.service_name: MYSQL` |
| `services.port` | порт | `services.port: 9200` |
| `services.tls.certificates.leaf_data.subject.common_name` | CN сертификата | `...common_name: "*.example.com"` |
| `services.http.response.html_title` | `<title>` | `...html_title: "Kibana"` |
| `services.http.response.headers.server` | заголовок Server | `...server: "Apache/2.4.49"` |
| `location.country` | страна хоста | `location.country: "Germany"` |
| `autonomous_system.asn` | ASN | `autonomous_system.asn: 13335` |

Операторы: `and`/`or`/`not`, скобки, `*` (wildcard), диапазоны (`services.port: 8000-9000`). Регистр значений важен для строк.

**FOFA** использует `=` (точное), `==` (точное без нечёткости), `!=`, `&&`, `||` и усечённые поля: `domain`, `host`, `ip`, `port`, `protocol`, `title`, `header`, `body`, `cert`, `icon_hash`, `fid`, `server`, `os`, `country`, `region`, `city`. Комбинация `cert="example.com" && country="RU"` ищет все хосты с сертификатом на домен, физически в РФ — классический приём для origin-hunting.

**ZoomEye** делит пространство на `host` и `web` (эндпоинты) и поддерживает facets: `app:`, `device:`, `service:`, `os:`, `ver:`, `cidr:`. Отчёт по фасетам даёт агрегаты — сколько серверов какой версии.

```bash
# ZoomEye: агрегаты по приложениям для запроса
curl -s "https://api.zoomeye.org/host/search?query=port%3A22%20country%3A%22RU%22&facets=app,os" \
  -H "API-KEY: $ZOOMEYE_KEY" | python3 -m json.tool | head -40
```

## SDK и CLI вместо ручного curl

Ручной curl удобен разово, но для пайплайнов берут SDK.

```bash
pip install censys
export CENSYS_API_ID=... CENSYS_API_SECRET=...
# поиск хостов
censys search "services.software.product: \"GitLab\"" --index-type hosts --per-page 50
# скачать сертификаты организации
censys search "parsed.names: example.com" --index-type certificates | jq -r '.results[].parsed.names[]' | sort -u
```

```python
# FOFA через Python
import requests, base64
q = base64.b64encode(b'cert="example.com"').decode()
r = requests.get("https://fofa.info/api/v1/search/all",
                 params={"key": KEY, "qbase64": q, "fields": "host,ip,port,domain", "size": 500})
for host, ip, port, dom in r.json()["results"]:
    print(host, ip, port)
```

Важно: FOFA возвращает `qbase64` **без** url-safe-замены; для curl используйте `python3 -c "import base64,sys;print(base64.b64encode(sys.argv[1].encode()).decode())" 'domain="x"'`.

## JARM и TLS-фингерпринты: пивот без баннера

Когда сервис отдаёт только TLS-handshake (нет HTTP), работают фингерпринты TLS. **JARM** — активный фингерпринт: серверу шлют 10 специально сформированных ClientHello и хэшируют ответы в 62-символьную строку.

```bash
pip install pyjarm
python3 -m pyjarm example.com
# -> 29d29d15d29d29d21c29d29d29d29d...  (JARM)
# затем в Censys: services.tls.jarm.fingerprint: "29d29d..."
```

Один и тот же JARM у C2-фреймворков (Cobalt Strike, Metasploit) позволяет искать **всю** инфраструктуру одного оператора. Это техника threat-intel (см. osint-threat-intel).

## Пайплайн «cert → поддомены → origin»

Самый продуктивный пайплайн внешней разведки:

1. **Сбор имён из CT-логов** — crt.sh / Censys certificates по организации.
2. **Обогащение через сканеры** — прогнать имена по Censys/FOFA, собрать IP и порты.
3. **Поиск origin за CDN** — сравнить favicon-hash, JARM и заголовки origin-IP с CDN-ответом.

```bash
# 1. имена из CT
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u > names.txt
# 2. прогнать по FOFA
while read n; do
  echo "cert=\"$n\"" | base64 | xargs -I{} curl -s "https://fofa.info/api/v1/search/all?key=$FOFA_KEY&qbase64={}&fields=ip,port"
done < names.txt
# 3. origin: тот же icon_hash, но НЕ в диапазонах Cloudflare
```

Результат — список реальных IP серверов, включая те, что CDN маскирует за собой.

## Разбор кейса 2: поиск утёкшего Elasticsearch

Задача: найти открытые Elasticsearch организации вне периметра.

```text
# FOFA: индексная страница Elasticsearch + сертификат домена
port="9200" && (title="You Know, for Search" || body="\"cluster_name\"") && cert="example.com"
# Censys
services.port: 9200 and services.http.response.html_title: "Elasticsearch" and services.tls.certificates.leaf_data.names: example.com
# ZoomEye
port:9200 +site:example.com
```

Найденные хосты проверяем на `_cat/indices` (без авторизации) — если отдаёт список индексов, это критическая утечка. Всегда фиксируем: IP, версию (`/` возвращает `version.number`), доступность без auth.

## Ограничения, лимиты и этика

| Движок | Бесплатно | Лимит API | Особенность |
|--------|-----------|-----------|-------------|
| Censys | ограниченно | ~250 запросов/мес | точность TLS |
| FOFA | ограниченно | по тарифу, есть rate-limit | лучший favicon/CN |
| ZoomEye | ограниченно | по тарифу | ICS/азиатский сегмент |
| Shodan | 1 запрос/сек | по тарифу | широта |

Этические правила: сканеры индексируют **публично доступное**; активная проверка найденного (запрос к сервису) — уже взаимодействие, требующее авторизации. Не логиньтесь в чужие панели, не эксплуатируйте найденное; фиксируйте находку и передавайте владельцу. Кэш движка может быть устаревшим (сервис уже закрыт) — всегда перепроверяйте актуальность перед выводом.

## Квиз

```quiz
- question: "Чем Censys особенно силён?"
  options:
    - "IoT-устройствами"
    - "TLS-сертификатами и точным индексом хостов"
    - "Китайским сегментом"
    - "Паролями"
  answer: 1
- question: "Что такое favicon-хэш в контексте FOFA?"
  options:
    - "Хэш пароля"
    - "Отпечаток иконки сайта для поиска серверов того же продукта"
    - "Хэш сертификата"
    - "Тип DNS-записи"
  answer: 1
- question: "Зачем искать один и тот же хост в нескольких движках?"
  options:
    - "Они все одинаковы"
    - "У них разное покрытие и время индексации"
    - "Так дешевле"
    - "Так требует API"
  answer: 1
- question: "Какой запрос Censys найдёт хосты по имени в сертификате?"
  options:
    - "`port:443`"
    - "`services.tls.certificates.leaf_data.names: example.com`"
    - "`title=example`"
    - "`site:example.com`"
  answer: 1
- question: "Что означает отсутствие результата в одном движке?"
  options:
    - "Сервис точно отсутствует"
    - "Движок мог его не проиндексировать — проверьте другие"
    - "Хост выключен навсегда"
    - "Это ошибка запроса"
  answer: 1
```

## Где пригодится

- **CTF:** поиск конкретного сервиса/панели по fingerprint.
- **Bug bounty:** расширение охвата и поиск origin за CDN.
- **Пентест:** инвентаризация внешней поверхности и устаревших сервисов.
- **Blue team:** поиск собственных случайно опубликованных сервисов.
