---
id: osint-tracking-ids
title: "Tracking ID и аналитика: Google Analytics, GTM и пиксели"
category: osint
parent: osint-web-surface
difficulty: medium
order: 3
tags: [osint, tracking, analytics, ga, gtm, adsense, pixel, pivot]
prerequisites: [osint-tech-fingerprint]
useful_for:
  - "CTF категория OSINT"
  - "Bug bounty и пентест"
  - "Атрибуция и поиск аффилированных доменов"
estimated_minutes: 30
summary: "Как tracking-идентификаторы (Google Analytics, GTM, AdSense, пиксели соцсетей) связывают домены одного владельца и как их искать и использовать для pivot."
---
Tracking-идентификаторы — это уникальные номера, которые вставляются в код сайта для аналитики и рекламы: Google Analytics (`UA-XXXXXXX-Y`, `G-XXXXXXX`), Google Tag Manager (`GTM-XXXXXXX`), AdSense (`pub-XXXXXXXXXXXXXXXX`), Facebook Pixel, Yandex.Metrica и другие. Для OSINT они — золото: **один и тот же ID часто стоит на десятках доменов одного владельца**, что позволяет связать разрозненные активы в единую инфраструктуру. Это техника «pivot по аналитике»: нашли ID на одном домене — нашли все остальные.

## Теория: почему ID связывают

Когда компания заводит аккаунт Google Analytics, она получает **один** ID (property) и вставляет его на все свои сайты, чтобы видеть сводную статистику. То же с GTM-контейнером: один контейнер на все домены, чтобы управлять тегами централизованно. Поэтому ID — это фактически «отпечаток владельца», переживающий смену дизайна, хостинга и даже домена.

Важные свойства:
- **ID привязан к аккаунту**, а не к сайту.
- **ID переживает редизайн**: старый GA-код иногда остаётся в углу страницы годами.
- **ID виден в исходнике** — он в JS-коде, в `gtag`, в `analytics.js`.
- **ID можно найти в архивах** (Wayback) даже если снят с живого сайта.

## Где искать ID

Откройте исходный код страницы:

```bash
curl -s https://example.com | grep -oiE '(UA-[0-9]{4,}-[0-9]+|G-[A-Z0-9]{8,}|GTM-[A-Z0-9]{4,}|pub-[0-9]{10,})' | sort -u
```

Вывод:

```
G-8F2K9LQ3ZM
GTM-5XW2K9
UA-1234567-3
pub-9876543210987654
```

Дополнительно ищите в JS-бандлах и в отдельных скриптах:

```bash
curl -s https://example.com | grep -oiE 'https?://[^"'\'' ]*(googletagmanager|google-analytics|connect.facebook|mc\.yandex)[^"'\'' ]*'
```

Маркеры разных систем:

| Сервис | Паттерн ID | Где в коде |
|--------|-----------|-----------|
| Universal Analytics | `UA-XXXXXXX-Y` | `analytics.js` |
| GA4 | `G-XXXXXXXXXX` | `gtag('config', ...)` |
| Tag Manager | `GTM-XXXXXX` | `gtm.js?id=` |
| AdSense | `pub-XXXXXXXXXXXX` | `adsbygoogle` |
| Facebook Pixel | 15-16 цифр | `fbq('init', ...)` |
| Yandex.Metrica | 8 цифр | `ym(XXXXXX, ...)` |
| Hotjar | 6-7 цифр | `hjid:` |
| Matomo | числовой `idsite` | `matomo.js` |

## Pivot: от ID к другим доменам

Найдя ID, ищем все домены, где он встречается. Способы:

**1. BuiltWith / PublicWWW / NerdyData.** Это поисковые системы по коду страниц. Запрос:

```
builtwith.com/analytics/G-8F2K9LQ3ZM
publicwww.com/websites/"GTM-5XW2K9"
```

PublicWWW и NerdyData индексируют HTML и JS, поэтому находят ID в исходниках напрямую. Пример запроса в PublicWWW:

```
"UA-1234567-3"
```

Результат — список доменов, где строка встречается. Это и есть «соседи» владельца.

**2. Google-дорки.** Иногда ID утекает в текст:

```
"G-8F2K9LQ3ZM" -site:example.com
"pub-9876543210987654"
```

**3. СпyOnWeb и SimilarWeb.** Показывают «похожие» сайты по инфраструктуре, но менее точно.

**4. Архивы.** Если ID сняли с живого сайта, он мог остаться в снимках Wayback:

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com&output=text&fl=timestamp,original&filter=urlkey:.*" | head
```

Затем загружаем старый снимок и грепаем ID.

## Разобранный пример: связать два «разных» домена

Дано: `shop.example.com` и `blog-example.net`. Выглядят как разные компании.

Шаг 1 — ID на первом домене:

```bash
curl -s https://shop.example.com | grep -oiE 'G-[A-Z0-9]{8,}|GTM-[A-Z0-9]{4,}'
# G-8F2K9LQ3ZM
# GTM-5XW2K9
```

Шаг 2 — ищем тот же GTM на втором домене:

```bash
curl -s https://blog-example.net | grep -oiE 'GTM-[A-Z0-9]{4,}'
# GTM-5XW2K9
```

Совпадение `GTM-5XW2K9` — сильное доказательство общего владельца. Шаг 3 — pivot в PublicWWW по `GTM-5XW2K9`, получаем ещё 4 домена. Итог: пять активов одной организации, которые формально «не связаны».

## Yandex.Metrica и региональная аналитика

В рунете популярна Yandex.Metrica. Её ID (`ym(12345678, "..." )`) ищется так:

```bash
curl -s https://example.ru | grep -oiE 'ym\([0-9]{6,}' 
```

У Metrica есть публичный «Вебвизор» по ID — иногда можно посмотреть статистику чужого сайта, если владелец не закрыл доступ. Это отдельный мощный вектор: `metrika.yandex.ru/stat/?id=12345678`.

## Пиксели соцсетей

Facebook Pixel, LinkedIn Insight Tag, TikTok Pixel, VK Pixel — все содержат числовой ID и связывают домены с одним рекламным кабинетом. Пример:

```bash
curl -s https://example.com | grep -oiE "fbq\('init',\s*'[0-9]{10,}'"
# fbq('init', '123456789012345')
```

Тот же пиксель на другом домене — общий рекламодатель. Это особенно ценно в расследованиях: рекламные кабинеты регистрируются на юридические лица.

## Таблица: что даёт каждый ID

| ID | Что связывает | Инструмент поиска |
|----|---------------|-------------------|
| `UA-`/`G-` | все сайты одного GA-аккаунта | PublicWWW, BuiltWith |
| `GTM-` | все сайты одного контейнера | PublicWWW, NerdyData |
| `pub-` (AdSense) | все сайты одного издателя | BuiltWith, PublicWWW |
| Facebook Pixel | домены одного рекламного кабинета | PublicWWW |
| `ym()` (Metrica) | сайты одного аккаунта Яндекс | Yandex-поиск |
| Hotjar `hjid` | сайты одного аккаунта Hotjar | PublicWWW |

## Ошибки и подводные камни

- **Путать чужой ID с владельческим.** Некоторые ставят GA-код подрядчика/агентства — тогда ID связывает не владельцев, а подрядчиков.
- **Считать совпадение одного ID доказательством.** Для атрибуции нужно 2+ совпадающих ID или ID + другие сигналы (общий сертификат, общий IP, общие контакты).
- **Игнорировать дату.** ID мог быть снят годы назад; в архиве он есть, в живом коде нет.
- **Забывать про сторонние скрипты.** ID может быть не в HTML, а в подключаемом `analytics.js` со своего CDN.
- **Искать только в HTML.** SPA отдают код через JS-бандлы — грепайте `*.js`.
- **Не проверять региональные системы.** В СНГ часто только Metrica и VK Pixel, GA отсутствует.

## Что дальше / решение

Tracking-идентификаторы — это pivot в инфраструктуру владельца. Дальше: **TLS-фингерпринт** (`osint-tls-fingerprint`) для корреляции хостов по стеку, **favicon-хэшинг** (см. ветку инфраструктуры) для той же задачи, и **картирование поверхности атаки** (`osint-attack-surface`), куда вы складываете все найденные «соседние» домены. Итог: из одной строки `GTM-XXXX` вы разворачиваете карту всех активов владельца, не коснувшись цели агрессивно.

## Автоматизация: сканер tracking ID

По списку доменов собираем все ID и группируем по совпадению — так автоматически находятся «кластеры» владельцев.

```bash
#!/usr/bin/env bash
# track-scan.sh — собрать tracking ID со списка доменов
OUT=ids.tsv
: > "$OUT"
while read -r h; do
  [ -z "$h" ] && continue
  ids=$(curl -sL -m 10 "https://$h" 2>/dev/null \
        | grep -oiE '(UA-[0-9]{4,}-[0-9]+|G-[A-Z0-9]{8,}|GTM-[A-Z0-9]{4,}|pub-[0-9]{10,})' \
        | sort -u | paste -sd, -)
  [ -n "$ids" ] && printf '%s\t%s\n' "$h" "$ids" >> "$OUT"
done < hosts.txt
column -t -s $'\t' "$OUT"
```

Затем находим ID, встречающиеся на нескольких доменах:

```bash
# разворачиваем "домен,ID1,ID2" в строки "ID домен"
awk -F'\t' '{n=split($2,a,","); for(i=1;i<=n;i++) print a[i]"\t"$1}' ids.tsv \
  | sort | awk -F'\t' '{c[$1]=c[$1]" "$2} END{for(k in c) if(split(c[k],x," ")>1) print k" ->"c[k]}'
# GTM-5XW2K9 -> shop.example.com blog-example.net ...
```

Так вы автоматически находите связанные домены.

## Проверка ID через публичные базы

Поиск по ID в открытых базах:

```bash
# PublicWWW (по подписке/API), NerdyData, BuiltWith
curl -s "https://builtwith.com/relationships/example.com" | grep -iE 'analytics|tracking'
```

Совет: даже без платных API, Google-дорк `"GTM-XXXXXXX"` часто находит страницы с тем же контейнером.

## Другие идентификаторы для pivot

Помимо аналитики, есть ещё «технические отпечатки», связывающие домены:
- **`ads.txt`** — `pub-` ID (AdSense/рекламные сети).
- **`app-ads.txt`** — мобильные рекламные ID.
- **Favicon-хэш** (см. `osint-favicon`) — MMH3-хэш иконки.
- **ASN/IP** — общий хостинг.
- **Сертификат CA** — общий выпуск.

Комбинация двух-трёх отпечатков — уверенная атрибуция владельца.

## Юридическая заметка

Tracking ID публично видны в коде — их сбор легален. Но связывание ID с конкретным человеком/организацией — это уже атрибуция, требующая осторожности и подтверждений. Не публикуйте выводы о «владении» без достаточных доказательств.

## Tracking ID в мобильных приложениях

Мобильные приложения тоже содержат SDK аналитики с теми же ID. Это расширяет pivot на APK/IPA:
- **Google Analytics for Firebase** — `google_app_id`, `gcm_defaultSenderId`.
- **Facebook SDK** — App ID.
- **Adjust/AppsFlyer** — dev key.

Распаковываем APK и грепаем:

```bash
apktool d app.apk -o app_src
grep -rniE 'google_app_id|fb_app|adjust|appsflyer|AIza[0-9A-Za-z_-]{35}' app_src | head
```

Совпадение Firebase-проекта (`google_app_id`) между приложением и сайтом (`G-XXXX`) — сильная связь. Firebase-проект (`projectId`) также раскрывает облачные ресурсы (см. `osint-cloud-recon`).

## Сводная таблица pivot-стратегии

| Найден ID | Куда pivot |
|-----------|-----------|
| `G-`/`UA-` | PublicWWW, BuiltWith → другие сайты |
| `GTM-` | контейнер → теги → вендоры |
| `pub-` | AdSense → издатель → другие сайты |
| Firebase `projectId` | облако, API-ключи |
| Facebook App ID | рекламный кабинет, другие домены |
| `ym()` | Яндекс-сервисы, рунет |

Комбинируя 2-3 ID, вы строите уверенную карту активов владельца.

## Квиз

```quiz
- question: "Почему tracking ID хорошо связывает домены одного владельца?"
  options:
    - "Он случайно повторяется"
    - "Один GA/GTM-аккаунт обычно обслуживает все сайты компании"
    - "Его видно только в DNS"
    - "Он меняется при каждом заходе"
  answer: 1
- question: "Какая поисковая система индексирует исходный код страниц и находит ID?"
  options:
    - "Shodan"
    - "PublicWWW"
    - "Censys"
    - "crt.sh"
  answer: 1
- question: "Что означает префикс `pub-` в идентификаторе?"
  options:
    - "Universal Analytics"
    - "Google AdSense"
    - "Tag Manager"
    - "Facebook Pixel"
  answer: 1
- question: "Какой ID популярен в рунете вместо Google Analytics?"
  options:
    - "Hotjar"
    - "Yandex.Metrica (`ym(...)`)"
    - "Matomo"
    - "Cloudflare"
  answer: 1
- question: "Сколько совпадающих ID достаточно, чтобы уверенно утверждать общий контроль доменов?"
  options:
    - "Достаточно одного"
    - "Лучше два и более независимых сигнала"
    - "Нужно не менее десяти"
    - "ID вообще не показатель"
  answer: 1
```

## Где пригодится

- **CTF (OSINT):** найти «второй» сайт цели по общему tracking ID.
- **Bug bounty:** расширить scope, обнаружив аффилированные домены в рамках программы.
- **Расследования:** связать сайты одного владельца (дис-инфо, мошеннические сети).
- **Пентест:** выявить тень-инфраструктуру компании.
- **Атрибуция:** рекламные кабинеты регистрируются на юрлица — ценный pivot.
