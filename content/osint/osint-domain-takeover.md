---
id: osint-domain-takeover
title: "Dangling CNAME и захват поддоменов (subdomain takeover)"
category: osint
parent: osint-dns-security
difficulty: hard
order: 2
tags: [osint, dns, cname, takeover, subdomain, cloud, bugbounty]
prerequisites: [osint-dnssec-caa]
useful_for:
  - "Bug bounty и пентест"
  - "CTF категория OSINT"
  - "Мониторинг поверхности атаки"
estimated_minutes: 30
summary: "Как находить висящие CNAME на удалённые облачные ресурсы и определять захват поддоменов: список уязвимых сервисов, проверка и подтверждение."
---
Subdomain takeover (захват поддомена) — одна из самых «вкусных» находок в bug bounty. Суть: поддомен `blog.example.com` указывает CNAME на ресурс внешнего сервиса (S3-бакет, GitHub Pages, Heroku), который владелец **удалил**, но DNS-запись осталась. Атакующий регистрирует тот же ресурс на своём аккаунте и получает контроль над `blog.example.com` — легитимным поддоменом компании. Для OSINT это комбинация пассивного перечисления поддоменов и проверки их «висячести».

## Теория: как возникает уязвимость

Схема:
1. Компания создаёт `blog.example.com` → CNAME на `myblog.herokuapp.com`.
2. Проект закрывают, приложение на Heroku удаляют.
3. **DNS-запись остаётся** (её забыли удалить).
4. Теперь `blog.example.com` → несуществующий ресурс.
5. Атакующий регистрирует `myblog` на Heroku (никто не занял) и получает `blog.example.com`.

Условия уязвимости:
- CNAME указывает на сервис, где имя ресурса **занимается по принципу «кто первый»** (S3, GitHub Pages, Heroku, Azure, Shopify).
- Ресурс удалён, но DNS-запись жива.
- Сервис не проверяет «владение» доменом.

Не все сервисы уязвимы: те, что требуют верификации домена (например, современный Netlify/Cloudflare Pages), защищены.

## Поиск висящих CNAME

Шаг 1 — собрать поддомены (из CT-логов, subfinder, amass). Шаг 2 — получить их CNAME:

```bash
for h in $(cat subdomains.txt); do
  cname=$(dig +short CNAME "$h")
  [ -n "$cname" ] && echo "$h -> $cname"
done
```

Вывод:

```
blog.example.com -> myblog.herokuapp.com
shop.example.com -> example-shop.s3.amazonaws.com
docs.example.com -> example.github.io
old.example.com  -> example.azurewebsites.net
```

Шаг 3 — определить, «жив» ли целевой ресурс:

```bash
for h in $(cat subdomains.txt); do
  cname=$(dig +short CNAME "$h" | head -1)
  [ -z "$cname" ] && continue
  # NXDOMAIN на самом CNAME-хосте = кандидат
  if ! dig +short "$cname" | grep -q .; then
    echo "CANDIDATE: $h -> $cname (NXDOMAIN)"
  fi
done
```

`NXDOMAIN` на целевом хосте — сильный признак висящего указателя.

## Проверка по HTTP

Часто CNAME резолвится, но отдаёт «сервис-специфичную» страницу ошибки, которая выдаёт незанятость:

```bash
curl -sI "https://blog.example.com" | head -1
curl -s "https://blog.example.com" | grep -iE 'no such app|404|there is no|not found|deprecated'
```

Характерные признаки по сервисам:

| Сервис | Признак незанятости |
|--------|---------------------|
| Heroku | `No such app` |
| GitHub Pages | `404 There isn't a GitHub Pages site here` |
| AWS S3 | `NoSuchBucket` |
| Azure | `Error 404 - Web app not found` |
| Shopify | `Sorry, this shop is currently unavailable` |
| Fastly | `Fastly error: unknown domain` |
| Zendesk | `Help Center Closed` |

## Список уязвимых сервисов (примеры)

Инструмент `can-i-take-over-xyz` (на GitHub) ведёт актуальный список. Классические кандидаты:

- AWS S3 (`s3.amazonaws.com`)
- GitHub Pages (`github.io`)
- Heroku (`herokuapp.com`)
- Azure (`azurewebsites.net`, `cloudapp.azure.com`)
- Shopify (`myshopify.com`)
- Fastly, Pantheon, Tumblr, WordPress.com, Zendesk, Desk, Bitbucket, Surge.sh, Unbounce, Cargo.

Проверять список нужно регулярно — статусы меняются.

## Автоматизация

Инструменты: `subjack`, `subover`, `tko-subs`, `nuclei` (шаблоны takeover), `dnsReaper`.

`subjack`:

```bash
subjack -w subdomains.txt -t 100 -timeout 30 -o takeover.txt -ssl -c fingerprints.json
```

`nuclei` с шаблонами takeover:

```bash
nuclei -l subdomains.txt -t http/takeovers/ -silent -o takeovers.txt
```

`dnsReaper` (Python):

```bash
dnsreaper --filename subdomains.txt --out takeover.json
```

## Разобранный пример: подтверждение takeover

Дано: `docs.example.com` → `example.github.io`, и GitHub отдаёт 404 «Pages site not found».

Шаг 1 — подтверждаем висячесть:

```bash
curl -s https://docs.example.com | head -3
# 404
# There isn't a GitHub Pages site here.
```

Шаг 2 — проверяем, что имя свободно (в рамках авторизации!):

```bash
# создать репозиторий example.github.io на тестовом аккаунте — имя доступно
```

Шаг 3 — после регистрации контент `docs.example.com` отдаётся с нашего репозитория → захват подтверждён.

**Важно:** фактический захват — это активное действие, требующее явной авторизации. В OSINT-фазе мы только **находим и подтверждаем кандидатов**, не захватывая.

## Таблица: оценка кандидата

| Наблюдение | Вывод |
|-----------|-------|
| CNAME на известный сервис | кандидат |
| Целевой хост NXDOMAIN | вероятный кандидат |
| Сервис отдаёт «not found» | сильный кандидат |
| Имя ресурса свободно | уязвимо |
| Сервис требует верификации домена | не уязвим |
| CNAME на внутренний хост | не takeover |

## Ошибки и подводные камни

- **Путать NXDOMAIN с takeover.** Иногда CNAME просто указывает на внутреннее имя, которое не должно резолвиться публично.
- **Игнорировать верификацию сервиса.** Современные платформы требуют подтверждения домена — они не уязвимы.
- **Захватывать без авторизации.** Регистрация ресурса = активная атака; только в рамках scope.
- **Считать HTTP 404 признаком.** Нужен именно «сервисный» текст ошибки, а не общий 404.
- **Забывать про wildcard.** `*.example.com` может маскировать реальные записи.
- **Не перепроверять список сервисов.** Статусы уязвимости меняются со временем.

## Что дальше / решение

Dangling CNAME — мост от разведки к эксплуатации. Дальше: **картирование поверхности атаки** (`osint-attack-surface`) для систематизации, **favicon/CDN** (ветка инфраструктуры) для корреляции, и **верификация** (`osint-verification`) для подтверждения кандидатов. Итог: вы находите поддомены с висящими указателями и документируете их как кандидатов на захват — не выполняя сам захват без разрешения.

## Полный конвейер поиска takeover

Собираем все шаги в один скрипт — от перечисления поддоменов до отчёта.

```bash
#!/usr/bin/env bash
# takeover-hunt.sh — конвейер поиска висящих CNAME
DOMAIN="$1"
mkdir -p takeover && cd takeover || exit

# 1. поддомены
subfinder -d "$DOMAIN" -all -silent | sort -u > subs.txt
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' \
  | sed 's/\*\.//g' | sort -u >> subs.txt
sort -u subs.txt -o subs.txt

# 2. CNAME
while read -r h; do
  c=$(dig +short CNAME "$h" | head -1)
  [ -n "$c" ] && echo "$h $c" >> cnames.txt
done < subs.txt

# 3. проверка живости целевого хоста
while read -r h c; do
  if ! dig +short "$c" | grep -q .; then
    echo "NXDOMAIN: $h -> $c" >> candidates.txt
  fi
done < cnames.txt

echo "Кандидаты:"; cat candidates.txt 2>/dev/null || echo "нет"
```

Дополняем HTTP-проверкой признаков сервисов:

```bash
while read -r line; do
  h=$(echo "$line" | awk '{print $1}')
  body=$(curl -s -m 8 "https://$h" 2>/dev/null)
  echo "$body" | grep -qiE 'no such app|isn.t a github pages|nosuchbucket|web app not found|currently unavailable' \
    && echo "TAKEOVER: $h"
done < subs.txt
```

## Проверка конкретных сервисов

Разные сервисы — разные признаки и способы проверки:

| Сервис | CNAME-паттерн | Признак свободности |
|--------|---------------|---------------------|
| S3 | `*.s3.amazonaws.com` | `NoSuchBucket` |
| GitHub Pages | `*.github.io` | 404 «Pages site not found» |
| Heroku | `*.herokuapp.com` | `No such app` |
| Azure | `*.azurewebsites.net` | «Web app not found» |
| Netlify | `*.netlify.app` | требует верификацию (не уязв.) |
| Vercel | `*.vercel.app` | требует верификацию |
| Shopify | `*.myshopify.com` | «shop unavailable» |
| Fastly | CNAME на `fastly.net` | «unknown domain» |

Проверяем ресурс напрямую:

```bash
curl -sI "https://myblog.herokuapp.com" | head -1
aws s3 ls s3://example-shop 2>&1 | grep -i 'NoSuchBucket'
```

## Отчётность по takeover

В отчёте указывайте:
- **поддомен** и **CNAME-цель**;
- **сервис** и признак свободности (скриншот/ответ);
- **потенциальное влияние** (фишинг, cookie-кража, репутация);
- **рекомендацию** (удалить DNS-запись или занять ресурс).

Не выполняйте захват без разрешения — достаточно доказательства «ресурс свободен».

## Влияние и цепочки атак

Захват поддомена — не просто «чужой сайт». Возможные последствия:
- **Фишинг** на доверенном домене (высокий клик-рейт).
- **Кража cookie** родительского домена (если cookie без `Domain`-ограничений).
- **Обход CSP** — доверенный origin.
- **OAuth redirect** — если поддомен в белом списке.
- **Утечка токенов** через `document.domain`.
- **Репутационный ущерб**.

Оценка влияния в отчёте: какой сервис, какие cookie/токены доступны, есть ли SSO-привязка.

## Защита и профилактика

Для blue team:
- **Инвентаризация DNS** — регулярная сверка записей с активами.
- **Мониторинг** — `notify`/SecurityTrails на изменения CNAME.
- **Удаление забытых записей** при выводе сервиса.
- **Верификация домена** в облачных платформах (закрывает класс).
- **CAA** ограничивает выпуск сертификатов на захваченный поддомен.

```bash
# еженедельный diff CNAME
dig +short CNAME blog.example.com > /var/lib/dns/cname.new
diff /var/lib/dns/cname.old /var/lib/dns/cname.new && echo "без изменений"
```

## Квиз

```quiz
- question: "Что такое dangling CNAME?"
  options:
    - "CNAME на внутренний хост"
    - "DNS-запись на удалённый ресурс внешнего сервиса, которую забыли убрать"
    - "Тип сертификата"
    - "Запись MX"
  answer: 1
- question: "Какое условие делает поддомен уязвимым к takeover?"
  options:
    - "Наличие DNSSEC"
    - "Сервис позволяет занять имя ресурса «кто первый», а ресурс удалён"
    - "Наличие CAA"
    - "Открытый порт 80"
  answer: 1
- question: "Что означает `No such app` на поддомене?"
  options:
    - "Сайт работает"
    - "Heroku-приложение удалено — признак висячего CNAME"
    - "Ошибка сертификата"
    - "DNS не настроен"
  answer: 1
- question: "Какое действие в OSINT-фазе НЕЛЬЗЯ выполнять без авторизации?"
  options:
    - "Собирать поддомены"
    - "Фактически регистрировать ресурс (захватывать поддомен)"
    - "Проверять CNAME"
    - "Читать CT-логи"
  answer: 1
- question: "Какой инструмент проверяет takeover по списку поддоменов?"
  options:
    - "dig"
    - "subjack / nuclei takeover-шаблоны"
    - "openssl"
    - "exiftool"
  answer: 1
```

## Где пригодится

- **Bug bounty:** subdomain takeover — высокооплачиваемая находка.
- **CTF (OSINT):** висячий CNAME ведёт к контрольному ресурсу с флагом.
- **Мониторинг:** регулярный скан поддоменов на висячие указатели.
- **Пентест:** расширение периметра за счёт облачных «сирот».
- **Blue team:** инвентаризация DNS и удаление забытых записей.
