---
id: osint-favicon
title: "Favicon-хэшинг и технологический фингерпринт"
category: osint
parent: osint-infra-network
difficulty: easy
order: 1
tags: [favicon, fingerprint, wappalyzer, tech, mmh3]
prerequisites: [osint-infrastructure]
useful_for:
  - "Поиск origin за CDN"
  - "Картирование однотипных серверов"
estimated_minutes: 50
summary: "Как хэшировать favicon (mmh3/MD5), искать по нему в Shodan/FOFA/Censys, определять технологии через Wappalyzer и whatweb, использовать фингерпринты для корреляции."
---

Favicon — маленькая иконка сайта, но её хэш уникален для продукта или компании. Он остаётся тем же на всех серверах одной организации, даже за CDN и на разных доменах. Поэтому favicon-хэшинг — один из самых надёжных способов найти **origin-серверы** (настоящие IP за Cloudflare) и **связанные хосты**, о существовании которых вы не знали.

## Что такое favicon-хэш

Shodan и FOFA вычисляют отпечаток иконки `/favicon.ico` по алгоритму **mmh3** от base64-содержимого файла. Одинаковая иконка → одинаковый хэш → все серверы с ней находятся одним запросом. Это «отпечаток» инфраструктуры, устойчивый к смене IP и домена.

Важно: движки используют именно `mmh3(base64(content))`, а не MD5/SHA — MD5 годится лишь для ручного сравнения двух иконок между собой.

```bash
# локально посчитать mmh3-хэш favicon (как его видят Shodan/FOFA)
pip install mmh3 requests
python3 - <<'PY'
import mmh3, requests, base64, hashlib
url = "https://example.com/favicon.ico"
r = requests.get(url, timeout=10)
print("status :", r.status_code, "bytes:", len(r.content))
print("mmh3   :", mmh3.hash(base64.encodebytes(r.content)))   # для Shodan/FOFA
print("mmh3(no-b64):", mmh3.hash(r.content))                  # для FOFA icon_hash
print("md5    :", hashlib.md5(r.content).hexdigest())          # для сравнения иконок
PY
```

Обратите внимание: **FOFA** использует `mmh3.hash(content)` без base64, а **Shodan** — `mmh3(base64(content))`. Поэтому для одного файла эти два хэша **различаются**; не путайте их между собой.

## Поиск по хэшу в движках

Полученное значение подставляйте напрямую:

- **Shodan**: `http.favicon.hash:<значение>`
- **FOFA**: `icon_hash="<значение>"`
- **Censys**: поиск по `services.http.response.favicon.md5` (или через сторонние базы)
- **ZoomEye**: `iconhash:"<значение>"`

```bash
# Shodan CLI
shodan search 'http.favicon.hash:-123456789' --fields ip_str,port,hostnames

# FOFA API
curl -s "https://fofa.info/api/v1/search/all?key=$FOFA_KEY&qbase64=$(echo -n 'icon_hash=\"-123456789\"' | base64)"
```

## Поиск origin за CDN

Классический сценарий обхода Cloudflare/WAF:

1. Сайт за Cloudflare; прямой IP скрыт.
2. Считайте favicon-хэш (см. скрипт выше).
3. Ищите хэш в Shodan/FOFA.
4. Среди результатов — IP **вне** диапазонов Cloudflare. Проверьте, отдаёт ли он тот же сайт:
   ```bash
   curl -sI http://<ip>/ -H 'Host: example.com' | head -5
   curl -sk https://<ip>/ -H 'Host: example.com' | head -c 300
   ```
5. Если заголовки/тело совпадают — origin найден.

Дополнительные признаки origin: нестандартные порты (8080/8443), прямой TLS-сертификат с именем `example.com` (а не `*.cloudflare`), отсутствие `cf-ray`/`server: cloudflare` в ответе.

## Технологический фингерпринт

Помимо favicon, технологии выдают заголовки, cookies, характерные пути и HTML-маркеры:

```bash
# whatweb: агрессивный режим, набор плагинов
whatweb -a 3 https://example.com
whatweb -a 3 -v https://example.com | grep -iE 'wordpress|nginx|php|react'

# wappalyzer (CLI, если установлен)
wappalyzer https://example.com

# заголовки и cookie
curl -sI https://example.com
curl -s https://example.com | grep -ioE 'wp-content|/static/|/_next/|react|vue|angular'

# TLS-сертификат: issuer, SAN (часто выдаёт весь список хостов)
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -issuer -subject -ext subjectAltName
```

Характерные маркеры:

| Признак | Технология |
|---|---|
| `Set-Cookie: PHPSESSID` | PHP |
| `Set-Cookie: JSESSIONID` | Java (JSP/Servlet) |
| `Set-Cookie: laravel_session` | PHP Laravel |
| `X-Powered-By: Express` | Node.js Express |
| `Server: gunicorn` | Python (WSGI) |
| `/wp-content/`, `/wp-json/` | WordPress |
| `/_next/`, `__NEXT_DATA__` | Next.js |
| `/_nuxt/`, `__NUXT__` | Nuxt (Vue) |
| `X-AspNet-Version` | ASP.NET |

## Корреляция по фингерпринтам

Один и тот же продукт (например, Grafana, Jenkins, GitLab) на сотнях хостов имеет общий favicon и заголовки. Это позволяет:

- находить **все** инстансы продукта у организации (включая забытые dev/staging);
- искать **устаревшие версии** (`Server: nginx/1.14`, `X-Jenkins: 2.204`) — кандидаты на CVE;
- обнаруживать **dev/staging** по нестандартным портам, `title` («Dev», «Test») и self-signed сертификатам;
- связывать хосты по **общему сертификату** (`SAN`-список, один `issuer`), **общему favicon** и **общему уникальному заголовку**.

Комбинируйте сразу несколько сигналов: favicon + `Server` + TLS-сертификат + cookie. Совпадение нескольких признаков даёт высокую уверенность, что хосты принадлежат одной организации.

## Разбор типового кейса

Задача: найти origin `shop.example.com` за CDN.

```bash
# 1. Скачать иконку и посчитать хэши
python3 - <<'PY'
import mmh3, requests, base64
c = requests.get("https://shop.example.com/favicon.ico", timeout=10).content
print("shodan:", mmh3.hash(base64.encodebytes(c)))
print("fofa  :", mmh3.hash(c))
PY
# 2. Найти все хосты с этим favicon
shodan search 'http.favicon.hash:<shodan-hash>' --fields ip_str,port,hostnames
# 3. Отфильтровать IP вне Cloudflare и проверить Host-заголовком
for ip in 1.2.3.4 5.6.7.8; do
  echo "== $ip"; curl -skI "https://$ip/" -H 'Host: shop.example.com' | head -3
done
```

## Частые ошибки

- **Считать обычный MD5** — движки используют mmh3; MD5 не совпадёт с поисковым запросом.
- **Путать Shodan- и FOFA-хэш** — base64/без base64 дают разные значения.
- **Забыть про редирект favicon** — иконка может отдаваться с `/favicon.ico?v=2` или с CDN; тогда хэш будет от другого файла.
- **Один признак как истина** — `Server` легко подделать; сверяйте несколько сигналов.
- **Игнорировать дефолтный favicon** — пустой/дефолтный favicon даёт тысячи ложных совпадений; проверяйте содержимое иконки.
- **Не проверять дату** — устаревшие записи Shodan могут указывать на уже несуществующие хосты.

## Массовый favicon-хэшинг

Для многих хостов хэши считаются пакетно:

```bash
# скачать favicon и посчитать хэш для списка хостов
for h in $(cat hosts.txt); do
  c=$(curl -s -m 5 "https://$h/favicon.ico" | base64 | tr -d '\n')
  [ -n "$c" ] && echo "$h $(python3 -c "import mmh3,sys;print(mmh3.hash(sys.stdin.read()))" <<< "$c")"
done
```

Затем группируйте хосты по одинаковому хэшу — это «кластеры» одного продукта/организации.

## Отпечатки помимо favicon

Дополнительные устойчивые отпечатки:

- **TLS/JARM**: отпечаток стека TLS (Cobalt Strike, Metasploit имеют узнаваемые JARM).
- **HTTP-заголовки**: порядок и набор заголовков (server fingerprint).
- **Robots.txt/sitemap**: характерные для конкретного ПО.
- **Метатеги и пути**: `/wp-content/`, `/_next/`, `/assets/`.

```bash
# JARM через httpx
echo example.com | httpx -jarm -silent
```

## Практический конвейер фингерпринта

```text
1. Собрать хосты (subfinder/amass)
2. Проверить живость (httpx)
3. Снять favicon-хэш + JARM + заголовки
4. Сгруппировать по отпечаткам
5. Найти «одиночек» и устаревшие версии
6. Обогатить (CVE по версии)
```

## Практика: массовый favicon-хэшинг и кластеризация

Считаем хэши для списка хостов и группируем их по совпадению:

```bash
pip install mmh3 requests
cat > favhash.py <<'PY'
import mmh3, base64, sys, requests
for h in sys.stdin.read().split():
    try:
        c = requests.get(f"https://{h}/favicon.ico", timeout=5).content
        print(h, mmh3.hash(base64.encodebytes(c)), mmh3.hash(c))
    except Exception as e:
        print(h, "ERR", e, file=sys.stderr)
PY
cat hosts.txt | python3 favhash.py | tee favhashes.txt
# кластеризация по Shodan-хэшу (колонка 2)
awk '{print $2}' favhashes.txt | sort | uniq -c | sort -rn | head
```

Пайплайн на инструментах ProjectDiscovery:

```bash
subfinder -d example.com -silent | httpx -silent -favicon -jarm | tee fp.jsonl
cat fp.jsonl | jq -r '[.host,.favicon,.jarm]|@tsv' | sort -k2
```

Хосты с одинаковым favicon-хэшем образуют «кластер» одного продукта или организации — даже если домены и IP разные.

## Практика: поиск по хэшу в движках

```bash
# Shodan
shodan search 'http.favicon.hash:-305179312' --fields ip_str,port,hostnames,org
# FOFA (icon_hash без base64)
curl -s "https://fofa.info/api/v1/search/all?key=$FOFA_KEY&qbase64=$(printf 'icon_hash="-305179312"' | base64 -w0)&fields=host,ip,port" | jq -r '.results[]|@tsv'
# ZoomEye
curl -s "https://api.zoomeye.org/web/search?query=iconhash:-305179312" -H "API-KEY: $ZE_KEY" | jq '.matches[].ip'
# Censys
censys search 'services.http.response.favicon.md5: <md5hex>'
```

## Дополнительные отпечатки помимо favicon

- **JARM** — 30-символьный хэш TLS-стека; Cobalt Strike и Metasploit имеют узнаваемые значения.
- **TLS fingerprint (JA3/JA4)** — отпечаток по параметрам рукопожатия.
- **HTTP/2 fingerprint** — наборы настроек, характерные для конкретных прокси.
- **Robots.txt и sitemap** — характерные для продукта пути.
- **Точный матч файла** — размер и контрольная сумма самой иконки.

```bash
echo example.com | httpx -jarm -favicon -silent
nmap -p443 --script ssl-enum-ciphers example.com
```

## Справочник: соответствие движков и алгоритмов

| Движок | Поле запроса | Алгоритм |
|---|---|---|
| Shodan | `http.favicon.hash:` | mmh3(base64) |
| FOFA | `icon_hash=` | mmh3(raw) |
| ZoomEye | `iconhash:` | mmh3 |
| Censys | `favicon.md5` | MD5 |

## Что дальше / решение

Кластеры по favicon — вход для поиска устаревших версий (`Server:`), подбора CVE по версии и обнаружения origin за CDN. Всегда сверяйте дату записи в индексе: устаревшие результаты Shodan часто указывают на уже несуществующие хосты. Для собственной инфраструктуры favicon-хэшинг — быстрый способ найти забытые dev-стенды, которые торчат наружу с той же иконкой.

## Разбор: кластеризация инфраструктуры по отпечаткам

Собрав favicon-хэши, JARM и данные сертификатов для набора хостов, вы получаете несколько независимых осей для группировки. Сгруппируйте хосты по favicon-хэшу — это «продуктовые» кластеры. Затем внутри кластера разбейте их по JARM: одинаковый TLS-стек усиливает уверенность, что это один и тот же сервер под разными именами. Добавьте SAN сертификатов: если у нескольких IP в SAN перечислены одни и те же имена, они почти наверняка принадлежат одной организации. Одиночки, выпадающие из кластера, — самые интересные: это могут быть забытые dev/staging-стенды, тестовые инсталляции с ослабленной защитой или устаревшие версии продукта. Обогатите каждую находку версией ПО из заголовка `Server` и `X-Powered-By` и сопоставьте с известными CVE. На выходе — не список разрозненных хостов, а карта инфраструктуры, где видно, какие сервисы развёрнуты где, какие версии устарели и какие хосты выпадают из общего паттерна. Именно эта карта и служит основой для расстановки приоритетов при тестировании.

## Квиз

```quiz
- question: "Какой алгоритм используют Shodan/FOFA для favicon-хэша?"
  options:
    - "MD5"
    - "mmh3 от base64-содержимого"
    - "SHA-256"
    - "CRC32"
  answer: 1
- question: "Почему favicon-хэш помогает найти origin за CDN?"
  options:
    - "Он содержит IP"
    - "Иконка одинакова на origin и в CDN, и хэш находится в поиске по другим IP"
    - "Он расшифровывает трафик"
    - "Он показывает DNS"
  answer: 1
- question: "Какой заголовок выдаёт язык/платформу сервера?"
  options:
    - "Content-Length"
    - "X-Powered-By"
    - "Date"
    - "ETag"
  answer: 1
- question: "Что означает `Set-Cookie: JSESSIONID`?"
  options:
    - "PHP"
    - "Java (JSP/Servlet)"
    - "Python Flask"
    - "Node.js"
  answer: 1
- question: "Почему нельзя опираться только на заголовок `Server`?"
  options:
    - "Он всегда пуст"
    - "Его легко подделать или изменить"
    - "Он не существует"
    - "Он показывает только ОС"
  answer: 1
```

## Где пригодится

- **CTF:** найти сервер по favicon или определить стек приложения.
- **Bug bounty:** origin discovery за WAF и поиск однотипных уязвимых хостов.
- **Пентест:** фингерпринт технологий для подбора векторов атаки.
- **Blue team:** инвентаризация собственных сервисов по отпечаткам и поиск «забытых» стендов.
