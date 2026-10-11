---
id: osint-infrastructure
title: "Сканеры интернета: Shodan, Censys, FOFA и Certificate Transparency"
category: osint
parent: osint-dns-core
difficulty: medium
order: 2
tags: [shodan, censys, fofa, certificates, tls, scanning]
prerequisites: [osint-dns-recon]
useful_for:
  - "CTF категория OSINT"
  - "Bug bounty и пентест"
  - "Attack surface management"
estimated_minutes: 44
summary: "Как использовать Shodan/Censys/FOFA/ZoomEye для поиска открытых сервисов, фильтры и API, а также продвинутый анализ TLS-сертификатов."
---

Сканеры интернета — это постоянно обновляемые базы данных о том, что открыто на портах по всему миру. Вместо того чтобы сканировать цель напрямую (шумно и заметно), вы можете **посмотреть уже собранные данные**. Для разведки это бесценно: вы видите сервисы, версии, сертификаты и иногда даже содержимое без единого пакета в сторону цели. Certificate Transparency — отдельный, но тесно связанный источник: каталог всех выпущенных TLS-сертификатов, из которого можно вытащить поддомены и связи между доменами.

## Теория: как работают сканеры интернета

Shodan, Censys и подобные сервисы непрерывно сканируют весь IPv4-пространство (а иногда и IPv6), собирают баннеры сервисов, TLS-сертификаты, HTTP-заголовки и складывают в поисковый индекс. Когда вы делаете запрос, вы ищете по этому индексу, а не по живой сети.

Что можно найти:

- Открытые базы данных (Elasticsearch, MongoDB, Redis без пароля).
- Панели управления (Kibana, Grafana, Jenkins, RDP).
- IoT-устройства с дефолтными паролями.
- Версии ПО → известные CVE.
- TLS-сертификаты → поддомены и внутренние имена.

## Практика: Shodan

### Базовые фильтры

| Фильтр | Значение | Пример |
|--------|----------|--------|
| `hostname:` | Обратный DNS/имя | `hostname:example.com` |
| `net:` | CIDR-диапазон | `net:93.158.134.0/24` |
| `org:` | Организация | `org:"Yandex"` |
| `asn:` | Номер AS | `asn:AS200350` |
| `port:` | Порт | `port:27017` |
| `product:` | Продукт | `product:MongoDB` |
| `version:` | Версия | `version:2.4.1` |
| `country:` | Страна | `country:RU` |
| `city:` | Город | `city:Moscow` |
| `os:` | ОС | `os:"Windows Server 2019"` |
| `ssl:` | Содержимое сертификата | `ssl:"example.com"` |
| `http.title:` | Заголовок страницы | `http.title:"Kibana"` |
| `http.favicon.hash:` | Хеш favicon | `http.favicon.hash:-305179312` |
| `vuln:` | Известная уязвимость | `vuln:CVE-2021-44228` |

Примеры запросов:

```
hostname:example.com
net:93.158.134.0/24 port:22
ssl.cert.subject.cn:"*.example.com"
http.title:"Index of /"
product:MongoDB -authentication
```

### CLI и API

```bash
pipx install shodan
shodan init <YOUR_API_KEY>
shodan host 93.158.134.210
shodan search 'hostname:example.com'
shodan count 'net:93.158.134.0/24'
shodan download results.json.gz 'ssl.cert.subject.cn:"example.com"'
shodan parse --fields ip_str,port,hostnames results.json.gz
```

Бесплатный аккаунт даёт ограниченное число запросов; API-ключ — больше. Для разведки в CTF хватит веб-поиска.

## Практика: Censys

Censys (search.censys.io) похож на Shodan, но сильнее в TLS и сертификатах.

```
services.service_name: HTTP
services.tls.certificates.leaf_data.subject.common_name: example.com
services.http.response.html_title: "Grafana"
services.port: 27017
```

Через API:

```bash
curl -s "https://search.censys.io/api/v2/hosts/93.158.134.210" \
  -u "$CENSYS_API_ID:$CENSYS_API_SECRET" | jq '.result.services[].port'
```

## Практика: FOFA и ZoomEye

- **FOFA** (`fofa.info`) — популярен в Китае, хорош по IoT и панелям. Синтаксис: `domain="example.com"`, `ip="93.158.134.210"`, `title="admin"`, `body="password"`.
- **ZoomEye** (`zoomeye.org`) — аналог, есть поиск по `site:`, `title:`, `app:`.
- **BinaryEdge**, **Netlas**, **GreyNoise** — дополнительные источники.

Используйте их **вместе**: один сервис пропускает то, что видит другой.

## Certificate Transparency: глубокое погружение

CT — публичный лог всех сертификатов. Каждый выпущенный для домена сертификат попадает в логи (RFC 6962), и их можно читать.

### crt.sh

```bash
# все сертификаты для домена и поддоменов
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[] | [.name_value, .issuer_name, .not_before] | @tsv' | sort -u

# только уникальные имена
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' | sort -u
```

### Что искать в сертификатах

- **SAN (Subject Alternative Names)** — все домены в одном сертификате. Wildcard-сертификат `*.example.com` выдаёт паттерн; сертификат с 50 SAN — карту поддоменов.
- **Issuer** — Let's Encrypt vs DigiCert vs внутренний CA (внутренний CA = признак корпоративной PKI).
- **Даты** — когда появился новый сервис.
- **Serial/CT logs** — новые сертификаты появляются в реальном времени → можно мониторить новые сервисы.

### Мониторинг новых сертификатов

Сервисы вроде `certstream` (Telegram/веб) уведомляют о новых сертификатах. Полезно для отслеживания, когда цель поднимает новый поддомен.

## Разобранный пример: от IP к полной картине

Дано: IP `93.158.134.210`.

Шаг 1 — Shodan host:

```bash
shodan host 93.158.134.210
```

Видим порты 80/443, сертификат на `*.example.com`, версию nginx.

Шаг 2 — Censys для деталей TLS:

```
services.ip: 93.158.134.210
```

Смотрим SAN-список → новые поддомены.

Шаг 3 — CT по найденному домену:

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u
```

Шаг 4 — корреляция: поддомены → резолв → новые IP → снова Shodan. Получаем граф.

Шаг 5 — поиск «интересного»: открытые Elasticsearch (`port:9200 product:Elastic`), Grafana (`http.title:Grafana`), Jenkins. Это уже потенциальные цели.

## Автоматизация и агрегаторы

- **`shodan` CLI** + скрипты для массовой выгрузки.
- **`uncover`** (ProjectDiscovery) — единый интерфейс к Shodan/Censys/FOFA/Quake:
  ```bash
  uncover -q 'ssl:"example.com"' -e shodan,censys,fofa -silent
  ```
- **`asnmap`** — получить CIDR по ASN для дальнейшего поиска.
- **Attack Surface Management (ASM)** платформы автоматизируют всё это, но для CTF достаточно CLI.

## Частые ошибки

- **Вера, что индекс свежий.** Shodan/Censys обновляют хосты не мгновенно — данные могут быть месячной давности.
- **Путать `ssl:` и `hostname:`.** `hostname:` — обратный DNS, `ssl:` — содержимое сертификата; результаты различаются.
- **Игнорирование фильтров исключения.** `product:MongoDB -authentication` найдёт открытые базы; без `-` — все.
- **Превышение лимитов API.** Бесплатные ключи строго ограничены; кэшируйте результаты.
- **Забыть про CT-мониторинг.** Новые поддомены появляются в реальном времени — это живые цели.
- **Считать CDN-сертификат origin-ом.** Сертификат Cloudflare не указывает на ваш сервер.

## Практика: Shodan CLI — полный справочник

Установка и инициализация:

```bash
pipx install shodan
shodan init <API_KEY>
shodan info                     # лимиты аккаунта
shodan myip                     # ваш внешний IP
```

Ключевые команды и их флаги:

```bash
shodan host 93.158.134.210                       # всё о хосте
shodan host --history 93.158.134.210             # история баннеров
shodan search 'hostname:example.com' --fields ip_str,port,org,product
shodan search --limit 100 'net:93.158.134.0/24'
shodan count 'product:nginx country:RU'
shodan download results.json.gz 'ssl.cert.subject.cn:"example.com"'
shodan parse --fields ip_str,port,hostnames results.json.gz
shodan stats --facets port 'org:"Example"'
shodan alert create example 93.158.134.0/24      # мониторинг сети
shodan stream --ports 22 --limit 5               # live-поток баннеров
```

Модификаторы фильтров: `-` (исключение), `+` (обязательное включение), кавычки для строк с пробелами. Примеры: `product:MongoDB -authentication`, `http.title:"Index of /" -http.title:"400"`. Фасетный анализ `shodan stats --facets org,country,port 'product:Apache'` отдаёт агрегированную статистику вместо длинного списка.

## Практика: Censys CLI и API v2

```bash
pipx install censys
censys config                                     # задать API ID/Secret
censys search 'services.service_name: HTTP' --index-type hosts
censys view 93.158.134.210 --index-type hosts
censys search 'services.tls.certificates.leaf_data.subject.common_name: example.com'
```

Через REST API v2:

```bash
curl -s "https://search.censys.io/api/v2/hosts/93.158.134.210" \
  -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
  | jq '{ip:.result.ip, ports:[.result.services[].port], certs:[.result.services[].tls.certificates.leaf_data.names[]?]}'
```

Censys силён в TLS: поля `leaf_data.names`, `issuer_dn` и `fingerprint_sha256` позволяют найти все хосты с сертификатом одной и той же CA или с одинаковым набором SAN.

## Практика: FOFA API и синтаксис

FOFA использует собственные операторы `domain=`, `host=`, `ip=`, `title=`, `body=`, `header=`, `cert=`, `icon_hash=`:

```bash
FOFA_Q='domain="example.com" && title="admin"'
curl -s "https://fofa.info/api/v1/search/all?email=$FOFA_EMAIL&key=$FOFA_KEY&qbase64=$(printf '%s' "$FOFA_Q" | base64 -w0)&fields=host,ip,port,title&size=100" \
  | jq -r '.results[] | @tsv'
```

`size` — до 10000 строк на платном тарифе, `page` — пагинация. FOFA особенно силён в азиатском сегменте: панели, IoT-устройства и самописные админки, которых нет в Shodan.

## Certificate Transparency: автоматизация

certstream слушает поток новых сертификатов в реальном времени:

```bash
pipx install certstream
python3 -c "import certstream; certstream.listen_for_events(lambda m,c: print(m['data']['leaf_cert']['all_domains']))"
```

crtsh с фильтром по дате — мониторинг свежих поддоменов:

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[] | select(.not_before > "2024-01-01") | .name_value' | sort -u
```

## Справочник: интересные порты и сервисы

| Порт | Сервис | Что искать |
|---|---|---|
| 9200 | Elasticsearch | `product:Elastic` без аутентификации |
| 27017 | MongoDB | `product:MongoDB -authentication` |
| 6379 | Redis | `product:Redis` без пароля |
| 2375 | Docker API | `port:2375` — управление контейнерами |
| 6443 | Kubernetes API | `port:6443` |
| 3389 | RDP | `port:3389 os:Windows` |

## Что дальше / решение

Индекс сканеров устаревает: всегда проверяйте, жив ли хост (`httpx -sc -title`) и не переехал ли сервис. Объединяйте источники — то, что не видит Shodan, покажет Censys, и наоборот. Найденные открытые базы и панели без аутентификации — это уже кандидаты в цели, их стоит сразу обогатить версией ПО для поиска CVE.

## Практика: выбор движка под задачу

Не существует «лучшего» сканера — у каждого своя сильная сторона. Shodan исторически лучший по глобальному охвату и нестандартным сервисам (промышленные протоколы, IoT, старые баннеры). Censys точнее в TLS-сертификатах и структурированных полях, поэтому незаменим при пивотинге по сертификату. FOFA и ZoomEye заметно полнее покрывают азиатский сегмент и панели, которые не попадают в другие индексы. GreyNoise, наоборот, не про поиск хостов, а про отделение целевых атак от массового интернет-шума. Практический приём — прогонять один и тот же запрос через два-три движка и брать объединение результатов: то, что пропустил один, найдёт другой. ProjectDiscovery `uncover` делает это одной командой:

```bash
uncover -q 'ssl:"example.com"' -e shodan,censys,fofa,quake -silent | httpx -silent -sc -title
```

Помните про лимиты: бесплатные ключи жёстко ограничены, поэтому кэшируйте выгрузки и не повторяйте один и тот же запрос дважды. `asnmap` превращает ASN организации в CIDR-диапазоны, которые затем можно прогнать по всем движкам для полного покрытия периметра.

## Квиз

```quiz
- question: "Что ищет фильтр Shodan `ssl.cert.subject.cn:"example.com"`?"
  options:
    - "Сайты с паролем example.com"
    - "Хосты с TLS-сертификатом, у которого CN содержит example.com"
    - "DNS-запись example.com"
    - "Файлы с именем example.com"
  answer: 1
- question: "Почему сканеры интернета считаются пассивной разведкой?"
  options:
    - "Потому что они не работают"
    - "Потому что вы читаете уже собранный индекс, не сканируя цель"
    - "Потому что они медленные"
    - "Потому что они запрещены"
  answer: 1
- question: "Что такое Certificate Transparency?"
  options:
    - "Шифрование трафика"
    - "Публичный лог всех выпущенных TLS-сертификатов"
    - "Протокол DNS"
    - "Вид WAF"
  answer: 1
- question: "Какой фильтр Shodan найдёт открытые базы MongoDB?"
  options:
    - "`port:80`"
    - "`product:MongoDB -authentication`"
    - "`hostname:mongodb`"
    - "`title:MongoDB`"
  answer: 1
- question: "Что полезно извлекать из TLS-сертификата?"
  options:
    - "Приватный ключ"
    - "SAN (список доменов) и issuer"
    - "Пароль администратора"
    - "Исходный код"
  answer: 1
```

## Где пригодится

- **CTF (OSINT):** найти сервис/панель по IP/домену и вытащить подсказку.
- **Bug bounty:** обнаружение открытых сервисов и dev-инстансов без активного скана.
- **Пентест:** составление инвентаря внешней инфраструктуры и версий ПО.
- **ASM/Blue team:** понять, что о вашей организации видно извне, и закрыть лишнее.
- **Threat intel:** отслеживание инфраструктуры и новых сертификатов атакующих.
