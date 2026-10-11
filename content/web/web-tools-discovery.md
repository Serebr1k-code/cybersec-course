---
id: web-tools-discovery
title: "Разведка и фаззинг: от живых хостов до скрытых путей"
category: web
parent: web-tooling
difficulty: easy
order: 2
tags: [recon, fuzzing, httpx, katana, nuclei, ffuf, gobuster, tooling]
prerequisites: [web-tooling, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Модуль-навигатор по разведке и фаззингу: httpx/katana/nuclei для карты и известных багов, ffuf/gobuster/wfuzz для скрытых путей и параметров."
---

Разведка веб-приложения — это конвейер из нескольких этапов: **живые хосты → технологический стек → пути и параметры → скрытые поверхности**. Каждый этап решается своим инструментом, и путать их неэффективно: `nuclei` не заменяет `ffuf`, а `subfinder` не находит скрытые каталоги. Этот урок — практический справочник по всему разведочному конвейеру с флагами и примерами.

## Конвейер разведки

Порядок действий задаётся стоимостью: сначала дёшево (пассивно, быстро), потом дорого (активные запросы).

1. **Поддомены и хосты** — `subfinder`, `amass`, `dnsx`.
2. **Живые веб-сервисы** — `httpx`.
3. **Стек и технологии** — `httpx -td`, `whatweb`.
4. **Контент и пути** — `ffuf`, `gobuster`, `feroxbuster`.
5. **Краулинг и эндпоинты** — `katana`, `gau`, `waybackurls`.
6. **CVE и мисконфиги** — `nuclei`.
7. **Параметры** — `arjun`, `paramspider`.

```bash
# полный конвейер одной строкой
subfinder -d target.local -silent \
  | httpx -silent -sc -td -server \
  | tee live.txt \
  | nuclei -silent -severity critical,high -o cve.txt
```

## subfinder, amass, dnsx: поддомены

```bash
# пассивный сбор поддоменов
subfinder -d target.local -all -silent -o subs.txt
amass enum -passive -d target.local -o amass.txt

# проверка, какие резолвятся, с IP
dnsx -l subs.txt -a -resp -silent -o resolved.txt
# поиск wildcard DNS
dnsx -d target.local -wc -silent
```

| Инструмент | Режим | Ключевые флаги |
|-----------|-------|----------------|
| subfinder | пассивный | `-all -silent -o` |
| amass | passive/active | `enum -passive`/`-active` |
| dnsx | резолв | `-a -resp -wc` |
| assetfinder | быстрый | `--subs-only` |

Wildcard DNS — важный крайний случай: если `*.target.local` резолвится в один IP, то любой несуществующий поддомен «жив», и все проверки нужно фильтровать по содержимому, а не по коду ответа.

## httpx: живые хосты и стек

```bash
# проверить список хостов: код, заголовок, сервер, технологии
httpx -l subs.txt -sc -title -server -td -silent -o live.txt
# с портами и редиректами
httpx -l subs.txt -p 80,443,8080,8443 -sc -fr -silent
# сохранить тела ответов и заголовки
httpx -l subs.txt -sr -srd /tmp/bodies -silent
# показать только живые (по умолчанию прячет мёртвые)
cat all.txt | httpx -silent
```

| Флаг | Что делает |
|------|-----------|
| `-sc` | код состояния |
| `-td` | tech-detect (технологии) |
| `-title` | заголовок страницы |
| `-server` | заголовок Server |
| `-fr` | follow redirects |
| `-sr -srd DIR` | сохранить ответы |
| `-mc/-fc` | фильтр по коду (match/filter) |
| `-json` | JSON-вывод для парсинга |

## ffuf, gobuster, feroxbuster: контент и пути

```bash
# ffuf: перебор каталогов с фильтром «как 404»
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
     -u https://t/FUZZ -mc 200,204,301,302,401,403 -fs 0 -t 40

# ffuf: vhost-фаззинг (Host: FUZZ.t)
ffuf -w subs.txt -u https://t/ -H 'Host: FUZZ.target.local' -fs 1234

# ffuf: параметры GET
ffuf -w params.txt -u 'https://t/api?FUZZ=1' -fs 0

# gobuster: dir с расширениями
gobuster dir -u https://t -w dirs.txt -x php,html,bak,zip -t 50 -q
# gobuster: vhost и dns
gobuster vhost -u https://t -w subs.txt --append-domain -q
gobuster dns -d target.local -w subs.txt --show-ips -q

# feroxbuster: рекурсия из коробки
feroxbuster -u https://t -w dirs.txt -x php,bak -d 3 --auto-tune -q
```

| Инструмент | Сильная сторона | Ключевые флаги |
|-----------|-----------------|----------------|
| ffuf | любые позиции, фильтры | `-mc -fs -fw -fl -recursion -H` |
| gobuster | простота, dir/dns/vhost | `-x -t -q --append-domain` |
| feroxbuster | авто-рекурсия | `-d -x --auto-tune` |

## katana, gau, waybackurls: краулинг

```bash
# краулинг с исполнением JS и известных источников
katana -u https://t -jc -d 3 -silent -o urls.txt
# только эндпоинты, найденные в JS
katana -u https://t -jc -silent | grep -oE 'https?://[^"]+'
# исторические URL из Wayback
gau target.local | tee gau.txt
waybackurls target.local | sort -u | tee wb.txt
# собрать параметры из всех URL
cat urls.txt gau.txt | grep '?' | unfurl keys | sort -u
```

## nuclei: CVE и мисконфиги

```bash
# полный скан с тегами
nuclei -u https://t -silent -severity critical,high,medium -o out.txt
# по тегам (cve, exposure, misconfig)
nuclei -u https://t -tags cve,exposure -silent
# список хостов + JSON для парсинга
nuclei -l live.txt -json -silent -o out.json
# обновить шаблоны перед сканом
nuclei -update-templates
```

Важно: `nuclei` находит по **содержимому**, а не по имени. Не грепайте библиотеку шаблонов по названию продукта — CVE-шаблоны названы по CVE-id. Просто запустите `nuclei -u <target>` и дайте ему отработать (при необходимости поднимите таймаут).

## Разобранный пример: от домена до CVE

```bash
$ subfinder -d shop.target.local -silent | tee subs.txt
shop.target.local
api.target.local
staging.target.local

$ httpx -l subs.txt -sc -title -td -silent
https://shop.target.local [200] [Shop] [nginx/1.18.0, PHP/7.4]
https://api.target.local [401] [Unauthorized] [Express]
https://staging.target.local [200] [Staging] [next.js/13.4]

$ nuclei -l subs.txt -tags cve -silent
[staging.target.local] [CVE-2023-XXXX] [critical] Next.js RCE

# подтверждение одной командой
$ curl -s 'https://staging.target.local/api/...' | head
```

Артефакт — воспроизводимый ответ, подтверждающий CVE. Только после этого находка идёт в отчёт.

## Крайние случаи и подводные камни

- **Wildcard DNS** — любой поддомен «жив»; фильтруйте по `-fs` (размер) или по содержимому, а не по коду.
- **Мягкие 404** — сервер отдаёт 200 на несуществующие пути; используйте `-fs`/`-fw`/`-fl`.
- **Rate limiting** — снижайте `-t`, добавляйте задержки (`ffuf -p 0.1`), иначе получите бан.
- **Кодировки** — URL-encoded и необычные пути (`/%2e/`) могут находить то, что не находит обычный перебор.
- **SPA** — одностраничные приложения отдают один HTML на все пути; краульте JS (`katana -jc`), а не каталоги.
- **Записи словарей** — не запускайте один и тот же список к `host:port` повторно: это шум без новой информации.

## Что делать дальше / решение

1. **Соберите поверхность** — поддомены (`subfinder`), живые хосты (`httpx`).
2. **Определите стек** — `httpx -td`, `whatweb`; сверьте версии с CVE.
3. **Найдите контент** — `ffuf`/`gobuster`/`feroxbuster` с подходящим словарём (запишите, каким).
4. **Скраульте** — `katana`/`gau` для эндпоинтов и параметров.
5. **Прогоните nuclei** — по тегам `cve,exposure,misconfig`.
6. **Триаж находок** — каждую подтвердите вручную (`curl`), прежде чем считать находкой.
7. **Тупик** — вернитесь к непроверенным веткам (vhost, параметры, JS-эндпоинты).

## Справочная таблица «этап → инструмент»

| Этап | Инструмент | Пример |
|------|-----------|--------|
| Поддомены | subfinder | `subfinder -d t -all` |
| Резолв | dnsx | `dnsx -l subs.txt -a` |
| Живые хосты | httpx | `httpx -l subs.txt -sc -td` |
| Пути | ffuf | `ffuf -u https://t/FUZZ -w dirs.txt` |
| Рекурсия | feroxbuster | `feroxbuster -u https://t -d 3` |
| Краул | katana | `katana -u https://t -jc` |
| История | gau/waybackurls | `gau t` |
| Параметры | arjun | `arjun -u https://t` |
| CVE | nuclei | `nuclei -u https://t -tags cve` |

## Словари: где брать и как выбирать

Качество дискавери определяется словарём не меньше, чем инструментом. Плохой выбор — запустить `rockyou` по каталогам или `common.txt` по API. Правильный выбор — подобрать список под задачу и стек.

Основные источники: **SecLists** (`Discovery/Web-Content/` — от `common.txt` до `raft-*-directories.txt`), **Assetnote Wordlists** (собраны из реального краулинга и часто богаче SecLists), собственные списки из `katana`/`gau` (URL конкретной цели — самый точный источник), списки под технологии (`/api/`, `/graphql`, `/_next/`, `.php`, `.jsp`).

Практическое правило: начинайте с `raft-medium-directories.txt` для каталогов, `raft-medium-words.txt` для файлов, отдельный список для параметров (`burp-parameter-names.txt`, `arjun`), отдельный для vhost (`subdomains-top1million-5000.txt`). Перед запуском всегда проверяйте, не применялся ли уже этот словарь к данному `host:port:tool_type` — повторный прогон не даёт новой информации, только шум и риск бана.

```bash
ls /usr/share/seclists/Discovery/Web-Content/ | grep -iE 'raft|common|directories'
# Assetnote
wget https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
```

## Rate limiting и обнаружение

Активное дискавери — это тысячи запросов, и оно легко приводит к бану IP или к замедлению, которое вы принимаете за «ничего не найдено». Признаки проблем: резкий рост времени ответа, ответы `429 Too Many Requests`, `503`, внезапная капча, обрывы соединений. Против этого — снижение параллелизма (`-t`), пауза между запросами (`ffuf -p 0.1`), случайный User-Agent, распределение по нескольким хостам.

Важно отличать бан от «мягкого 404». Если сервер начал отдавать 200 на всё — это может быть WAF-страница, а не находка. Фильтруйте по размеру и словам (`-fs`, `-fw`), а не только по коду. Если после серии запросов все ответы стали одинаковыми — остановитесь, проверьте руками, при необходимости смените источник и снизьте темп.

## Разобранный пример: SPA и краулинг

Одностраничные приложения (React/Vue/Next) отдают один и тот же `index.html` на все пути, поэтому перебор каталогов бесполезен: всё вернёт 200. Работать нужно иначе — через JS.

```bash
# 1. собрать все JS-бандлы
katana -u https://spa.target.local -jc -d 3 -silent | grep -E '\.js' | sort -u > js.txt

# 2. извлечь эндпоинты из бандлов
while read u; do curl -s "$u"; done < js.txt \
  | grep -oE '"/api/[a-zA-Z0-9_/{}.-]+"' | sort -u

# 3. проверить найденные эндпоинты
for e in $(cat endpoints.txt); do
  curl -so /dev/null -w "%{http_code} $e\n" "https://spa.target.local$e"
done
```

Типичная находка — скрытый `/api/internal/users` или debug-эндпоинт, которого нет в UI. Именно ради таких поверхностей и нужен краулинг JS, а не перебор каталогов.

## Итоговая стратегия

Разведка — это итеративный процесс, а не один запуск. Соберите поверхность, определите стек, найдите контент, прогоните nuclei, затем вернитесь к тому, что осталось непонятным: неизвестный поддомен, эндпоинт без документации, нестандартный параметр. Каждую находку подтверждайте вручную. Отрицательные результаты записывайте — это экономит время вам и коллегам. И помните: разведка заканчивается не тогда, когда «кончились идеи», а тогда, когда все дешёвые ветки закрыты доказательствами.

## Квиз

```quiz
- question: "Какой инструмент превращает сырой список поддоменов в список живых URL с кодом ответа и title?"
  options:
    - "nuclei"
    - "katana"
    - "httpx"
    - "wfuzz"
  answer: 2
  explanation: "httpx — массовая HTTP-проба: статус, title, технологии, редиректы."
- question: "Что ищут на этапе nuclei до ручного анализа?"
  options:
    - "Скрытые каталоги перебором словаря"
    - "Известные CVE, дефолтные креды и открытые конфиги по шаблонам"
    - "Cookie текущей сессии"
    - "Скорость ответа сервера"
  answer: 1
  explanation: "nuclei — шаблонный сканер известных багов и мисконфигов, самый дешёвый «низковисящий фрукт»."
- question: "Почему ffuf без -mc/-fs даёт много мусора?"
  options:
    - "Потому что не следует редиректам"
    - "Потому что SPA может отдавать 200 на любой путь"
    - "Потому что не умеет работать с cookie"
    - "Потому что не поддерживает JSON"
  answer: 1
  explanation: "Многие приложения возвращают 200 для любого пути; матчеры/фильтры нужны, чтобы отсеять шум."
```

## Где пригодится

- **CTF (Web):** быстро найти скрытый эндпоинт/параметр, который не виден в ссылках.
- **Bug bounty:** стандартный пайплайн subfinder → httpx → katana → nuclei → ffuf даёт карту программы за минуты.
- **Пентест:** приоритизация целей и доказательства находок для отчёта.
- **Работа (AppSec/DevSecOps):** регулярные сканы в CI и мониторинг изменений поверхности атаки.
