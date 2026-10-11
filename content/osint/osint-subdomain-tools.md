---
id: osint-subdomain-tools
title: "Инструменты поддоменного перечисления: subfinder, amass, httpx"
category: osint
parent: osint-dns-core
difficulty: medium
order: 3
tags: [subfinder, amass, httpx, subdomain, takeover]
prerequisites: [osint-dns-recon]
useful_for:
  - "Полное картографирование внешней поверхности"
  - "Поиск takeover-кандидатов"
estimated_minutes: 55
summary: "Пассивные и активные инструменты, конвейер subfinder→dnsx→httpx, поиск dangling CNAME и subdomain takeover."
---

Ручной сбор поддоменов (crt.sh + dig) работает, но на реальных целях имён бывают сотни. Здесь нужен **конвейер** инструментов: собрать → проверить → отфильтровать живые.

## subfinder (пассивный)

ProjectDiscovery-инструмент, опрашивает десятки пассивных источников (CT, пассивный DNS, поисковики):

```bash
subfinder -d example.com -silent
subfinder -d example.com -all -silent -o subs.txt
subfinder -dL domains.txt -silent          # список доменов
```

Флаги: `-all` (все источники), `-recursive`, `-t` (потоки). Пассивен и незаметен для цели.

## amass (пассивный + активный)

Мощнее и «тяжелее». Режимы:

```bash
# пассивный (без запросов к цели)
amass enum -passive -d example.com -o amass.txt

# активный (с брутфорсом и разрешением)
amass enum -active -d example.com -brute -w words.txt

# разведка инфраструктуры
amass intel -whois -d example.com
amass intel -asn 200350
```

`amass intel -asn` особенно полезен — перечисляет домены, связанные с автономной системой.

## Другие источники

- **assetfinder** (Tomnomnom): `assetfinder --subs-only example.com`.
- **findomain**: быстрый пассивный сбор.
- **chaos** (ProjectDiscovery): публичная база поддоменов `chaos -d example.com`.
- **crt.sh / certspotter** — вручную (см. урок про CT).
- **github-subdomains**, **gau** (URL-ы из архивов) — дополняют картину.

## Конвейер: собрать → резолвить → проверить

```bash
# 1) собрать
subfinder -d example.com -silent > subs.txt
assetfinder --subs-only example.com >> subs.txt
sort -u subs.txt -o subs.txt

# 2) резолвить (dnsx из ProjectDiscovery)
dnsx -l subs.txt -silent -a -resp -o resolved.txt

# 3) проверить живые веб-сервисы (httpx)
httpx -l subs.txt -silent -status-code -title -tech-detect -o live.txt
```

`httpx` покажет статус, заголовок, технологии и (при `-sc -td`) — сразу отфильтрует интересное.

## Работа с большими целями

На крупных программах поддоменов тысячи, и наивный перебор упирается в скорость DNS:

- **Резолверы**: используйте свой список (`-r resolvers.txt`) вместо системного — это в разы быстрее и устойчивее.
- **Массовый резолв**: `massdns`/`puredns` для десятков тысяч имён.
- **Потоки**: `dnsx -t 100`, `httpx -t 100`, но следите за нагрузкой.
- **Разбиение**: обрабатывайте по источникам/зонам, кэшируйте между запусками.

```bash
# puredns: быстрый и корректный массовый резолв
puredns resolve subs.txt -r resolvers.txt -w resolved.txt
```

## Приоритизация результатов

После сбора отсортируйте по «интересности»:

1. **Живые** (200/401/403) важнее мёртвых.
2. **Имена-намёки**: `admin`, `dev`, `staging`, `test`, `internal`, `jenkins`, `git`, `vpn`, `api`, `db`.
3. **Нестандартные порты** (`:8080`, `:8443`) — часто внутренние сервисы.
4. **Дубли по IP** — один сервер, много имён.

## Subdomain takeover (dangling CNAME)

Сценарий: поддомен имеет `CNAME` на внешний сервис (GitHub Pages, Heroku, S3), который **больше не обслуживается**. Атакующий регистрирует этот ресурс и «занимает» поддомен.

Проверка:

```bash
# найти CNAME
dig +short sub.example.com CNAME
# проверить признак "не найден" в теле
curl -s "http://sub.example.com" | grep -iE 'NoSuchBucket|There isn.t a GitHub Pages site|Heroku |No such app'
```

Инструменты: **subjack**, **nuclei -t takeovers/**, **can-i-take-over-xyz** (список сервисов и признаков).

```bash
nuclei -l subs.txt -t http/takeovers/ -silent
```

## Расширение: сертификаты, архивы, code-репозитории

Дополнительные источники поддоменов, которые часто забывают:

- **CT-логи** (`crt.sh`) — см. отдельный урок; самый богатый пассивный источник.
- **Wayback/gau** — URL из архивов выдают имена, которых нет в DNS сегодня.
- **GitHub/GitLab** — внутренние хосты в коде, конфигах, README.
- **JS-файлы** — URL API-хостов и CDN внутри бандлов.
- **SPF/MX/TXT** — сервисы и поддомены почтовой инфраструктуры.

```bash
gau example.com | grep -oE '[a-z0-9.-]+\.example\.com' | sort -u
```

## Автоматизация и приоритизация конвейера

Для больших целей конвейер запускают одной командой и сразу фильтруют результат:

```bash
subfinder -d example.com -silent \
  | dnsx -silent -a -resp \
  | httpx -silent -sc -title -td -o live.txt

# только интересные имена
grep -iE 'admin|dev|staging|test|internal|jenkins|git|vpn|api|db|jira|grafana' live.txt
```

Полезные флаги `httpx`: `-sc` (статус), `-title`, `-td` (tech-detect), `-favicon` (хэш иконки), `-jarm` (отпечаток TLS), `-cdn` (за CDN или нет), `-p` (порты). Комбинируя `-favicon` и `-jarm`, вы группируете хосты одного продукта — это находит «забытые» стенды.

## Практика и осторожность

- Пассивные инструменты — безопасны, но **не дают 100%** покрытия; комбинируйте несколько.
- Активный брутфорс — заметен и создаёт нагрузку на DNS; в bug bounty проверяйте правила.
- Не эксплуатируйте takeover даже если нашли — сначала убедитесь, что домен **в scope**, и следуйте правилам программы.
- Логируйте всё: источник, дата, инструмент.

## Инструменты и флаги

| Инструмент | Команда | Назначение |
|---|---|---|
| subfinder | `-d d -all -silent` | пассивный сбор |
| amass | `enum -passive/-active`, `intel -asn` | пассив+актив |
| assetfinder | `--subs-only` | быстрый пассив |
| chaos | `-d d` | публичная база |
| dnsx | `-a -resp` | резолв |
| httpx | `-sc -title -td` | живой веб-слой |
| puredns | `resolve -r resolvers.txt` | массовый резолв |
| subjack/nuclei | takeover-проверка | dangling CNAME |

## Частые ошибки

- Использовать один инструмент и считать охват полным.
- Забывать про активный брутфорс там, где он разрешён (терять имена).
- Не проверять резолв — половина списка мертва.
- Игнорировать takeover-признаки в теле ответа.
- Эксплуатировать takeover вне scope.

## Что делать дальше / решение

- **Нужен полный охват** → subfinder `-all` + assetfinder + chaos + crt.sh, объединить.
- **Нужны живые** → `dnsx` → `httpx -sc -title -td`.
- **Нужны takeover** → subjack + nuclei takeovers + ручная проверка.
- **Нужен масштаб** → puredns/massdns со своим списком резолверов.

## Wildcard DNS и как его обходить

Крупные цели часто включают **wildcard DNS**: `*.example.com` резолвится в один и тот же IP, из-за чего любой случайный поддомен «жив». Это ломает наивный перебор — вы получаете тысячи ложных попаданий. Определить wildcard: `dig +short random123.example.com` — если отвечает, значит wildcard активен. Обход:

- Сравнивайте ответы: если все резолвятся в один IP/набор IP, фильтруйте по этому признаку.
- `puredns` умеет `--wildcard-tests` и отбрасывает совпадающие ответы автоматически.
- Используйте уникальные метки (`random-<uuid>.example.com`) для детекта.
- Отбрасывайте «пустые» ответы CDN, которые отдают одинаковый контент-заглушку.

Без учёта wildcard конвейер выдаёт мусор, и реальные хосты теряются среди тысяч одинаковых. Всегда проверяйте наличие wildcard перед массовым резолвом.

## Специфика больших программ (scope и темп)

На больших bug bounty-программах объём поддоменов — тысячи, и важна дисциплина:

- **Scope**: сверяйте каждый найденный домен с правилами; `*.example.com` в scope не означает, что можно сканировать IP-соседей на том же хостинге.
- **Темп**: активный брутфорс и `httpx` создают нагрузку; держите разумные потоки (`-t 50`) и паузы.
- **Разделение пассивного и активного**: сначала всё пассивное (subfinder/CT/архивы), только потом активный брутфорс — и лишь если это разрешено.
- **Инкрементальность**: храните прошлые списки, считайте diff, чтобы видеть новые хосты между запусками.

```bash
comm -13 <(sort prev.txt) <(sort subs.txt)   # новые имена с прошлого прогона
```

## Продвинутые источники: JARM, favicon и ASN

Когда базовый конвейер собран, добавляются источники, которые находят «невидимые» хосты:

- **JARM** — отпечаток TLS-сервера; одинаковый JARM выдаёт хосты одного продукта/стенда. `httpx -jarm`.
- **Favicon hash** — `httpx -favicon` или `python3 favfreak.py`, затем поиск хэша в Shodan/FOFA — находит забытые стенды и origin.
- **ASN** — `amass intel -asn <N>` и `asnmap` перечисляют домены, анонсируемые организацией; это расширяет охват за пределы одного домена.
- **TLS SAN** — имена из сертификатов (`crt.sh`) часто содержат внутренние хосты.
- **CDN-признак** — `httpx -cdn` показывает, за CDN ли хост; хосты без CDN — прямые цели.

```bash
httpx -l subs.txt -silent -jarm -favicon -cdn -o enriched.txt
asnmap -a AS200350 -silent | httpx -silent -sc -title
```

Комбинируя эти признаки, вы группируете хосты по «владельцу стенда» и находите то, что не видно по именам.

## Быстрая шпаргалка по конвейеру

```bash
# пассивный сбор из многих источников
subfinder -d example.com -all -silent | sort -u > subs.txt
assetfinder --subs-only example.com >> subs.txt
chaos -d example.com >> subs.txt
gau example.com | grep -oE '[a-z0-9.-]+\.example\.com' >> subs.txt
sort -u subs.txt -o subs.txt

# резолв + живой веб-слой + обогащение
dnsx -l subs.txt -silent -a -resp \
  | httpx -silent -sc -title -td -favicon -jarm -cdn -o live.txt

# takeover-кандидаты
subjack -w subs.txt -t 100 -ssl -o takeovers.txt
nuclei -l subs.txt -t http/takeovers/ -silent
```

Держите `subs.txt`/`live.txt` между запусками и считайте diff — так вы замечаете новые хосты, а не гоняете одно и то же.

## Квиз

```quiz
- question: "Какой инструмент опрашивает десятки пассивных источников поддоменов?"
  options:
    - "nmap"
    - "subfinder"
    - "sqlmap"
    - "hashcat"
  answer: 1
- question: "Что делает `amass intel -asn 200350`?"
  options:
    - "Сканирует порты"
    - "Ищет домены, связанные с автономной системой"
    - "Брутит пароли"
    - "Проверяет сертификаты"
  answer: 1
- question: "Что такое subdomain takeover?"
  options:
    - "Захват DNS-сервера"
    - "Занятие поддомена с «висячим» CNAME на несуществующий сервис"
    - "Подмена HTTPS-сертификата"
    - "Брутфорс поддоменов"
  answer: 1
- question: "Что проверяет `httpx -status-code -title -tech-detect`?"
  options:
    - "Пароли сайтов"
    - "Живость, статус, заголовок и технологии"
    - "Открытые порты на всех IP"
    - "WHOIS домена"
  answer: 1
- question: "Почему в bug bounty осторожны с активным брутфорсом DNS?"
  options:
    - "Он медленный"
    - "Он заметен и создаёт нагрузку — проверяйте правила"
    - "Он не даёт результатов"
    - "Он стоит денег"
  answer: 1
```

## Где пригодится

- **CTF:** полный охват домена из задания.
- **Bug bounty:** максимизация охвата scope + поиск takeover (часто награждается).
- **Пентест:** инвентаризация внешней поверхности перед атакой.
- **Blue team:** контроль собственных «висячих» записей.
