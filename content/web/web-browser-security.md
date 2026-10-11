---
id: web-browser-security
title: "Модель безопасности браузера: site isolation, CORB/ORB, COOP/COEP"
category: web
parent: web-browser-core
difficulty: medium
order: 1
tags: [browser-security, site-isolation, corb, orb, coop, coep, same-origin]
prerequisites: [web-same-origin-cors]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 40
summary: "Как устроена изоляция сайтов в браузере и какие механизмы защищают данные между origin, сайтами и процессами."
---

Модель безопасности браузера — фундамент, на котором держатся все клиентские атаки. Same-Origin Policy, Site Isolation, CORB/ORB, COOP/COEP — это механизмы, которые определяют, что один сайт может и не может делать с данными другого. Понимание этих механизмов отличает специалиста, который «знает payload'ы», от того, кто понимает, **почему** атака работает или не работает. Этот урок — про современную модель безопасности браузера.

## Same-Origin Policy (SOP)

SOP — базовое правило: скрипт с одного origin не может читать данные другого. Origin определяется тройкой **схема + хост + порт**. `https://a.com` и `https://a.com:443` — один origin; `http://a.com` и `https://a.com` — разные; `https://sub.a.com` и `https://a.com` — разные.

SOP запрещает чтение (например, `fetch` к чужому origin без CORS), но **разрешает** некоторые действия: отправку запросов (но не чтение ответа), включение скриптов/картинок/стилей, навигацию. Именно из этого «разрешения отправлять, но не читать» рождаются CSRF, JSONP, XS-Leaks.

## Site Isolation

Классическая модель помещала страницы разных сайтов в один процесс, что позволяло атаки типа Spectre и утечки через side-channels. **Site Isolation** (Chrome с 2018) помещает каждый сайт в отдельный процесс, изолируя память. Это резко усложнило Spectre-атаки и некоторые утечки. Проверять Site Isolation можно через `chrome://process-internals` или специальные тесты.

## CORB и ORB

CORB (Cross-Origin Read Blocking) и его преемник **ORB** (Opaque Response Blocking) защищают от утечки данных через «неправильно типизированные» ответы. Идея: если cross-origin ресурс имеет тип, который не должен исполняться (JSON, HTML), браузер блокирует его содержимое от попадания в скрипт-контекст. Это закрывает часть XSSI-атак.

```bash
# Content-Type имеет значение для CORB/ORB
curl -sI https://api.victim.com/data | grep -i content-type
# application/json + nosniff -> ORB блокирует включение как скрипт
# text/html -> блокируется как скрипт
# text/javascript -> исполняется (потенциальный XSSI)
```

## COOP и COEP

**COOP** (`Cross-Origin-Opener-Policy`) изолирует browsing context: с `same-origin` окно не может получить ссылку на `window.opener` чужого origin. Это защита от tabnabbing и некоторых утечек. **COEP** (`Cross-Origin-Embedder-Policy`) требует, чтобы все встраиваемые ресурсы явно разрешали встраивание (`CORP`), что вместе с COOP включает мощные API (`SharedArrayBuffer`).

```bash
# проверяем заголовки
curl -sI https://t/ | grep -iE 'cross-origin-opener-policy|cross-origin-embedder-policy|cross-origin-resource-policy'
```

| Заголовок | Значение | Эффект |
|-----------|----------|--------|
| `COOP: same-origin` | изоляция opener | нет доступа к opener чужого origin |
| `COEP: require-corp` | требуются CORP | включает crossOriginIsolated |
| `CORP: same-origin` | ресурс только для своего origin | защита от утечки |
| `CORP: cross-origin` | ресурс встраиваем | нужен для COEP |

## Изоляция и `document.domain`

`document.domain` позволяет ослабить SOP между поддоменами одного родителя. Однако это deprecated и ломает изоляцию (site isolation), поэтому современные браузеры ограничивают его. Проверяйте, не использует ли приложение `document.domain` — это признак устаревшей модели и потенциальной слабости.

```bash
curl -s https://t/ | grep -o 'document.domain' 
```

## Разобранный пример: почему XSSI не работает

```bash
# 1. пробуем включить JSON как скрипт
$ curl -sI https://api.victim.com/user | grep -iE 'content-type|x-content-type'
content-type: application/json
x-content-type-options: nosniff
# ORB блокирует -> скрипт не исполнится

# 2. ищем эндпоинт без защиты
$ curl -sI 'https://api.victim.com/user?callback=x' | grep -i content-type
content-type: text/javascript
# JSONP -> исполняется -> XSSI возможен
```

## Разобранный пример: COOP против tabnabbing

```bash
# 1. проверяем COOP
$ curl -sI https://t/ | grep -i cross-origin-opener-policy
cross-origin-opener-policy: same-origin
# -> window.opener недоступен из другого origin
# 2. без COOP
$ curl -sI https://t2/ | grep -i cross-origin-opener-policy
(нет)
# -> reverse tabnabbing возможен
```

## Что проверять в реальном тесте

При аудите смотрите на заголовки и их согласованность. Отсутствие COOP/COEP — не всегда уязвимость, но открывает класс атак. Наличие `document.domain` — устаревшая модель. Отсутствие `nosniff` при JSON — риск XSSI. Разные origin на поддоменах — границы для cookie и CORS. И помните: SOP — это про чтение; действия (CSRF) и утечки (XS-Leaks) живут в её «щелях».

## Крайние случаи и подводные камни

- **Origin — тройка.** Схема и порт так же важны, как хост.
- **Порт по умолчанию.** `https://a.com:443` = `https://a.com`, но `http://a.com:80` ≠ `https://a.com`.
- **`document.domain`** ослабляет SOP — избегайте.
- **CORB/ORB** защищают от XSSI, но не от JSONP с `text/javascript`.
- **COOP/COEP** нужны для изоляции и мощных API.
- **Site Isolation** ломает часть Spectre, но не все side-channels.
- **Private Network Access** — новый механизм, ограничивающий запросы к локальной сети.

## Что делать дальше / решение

1. **Проверьте заголовки** — COOP, COEP, CORP, nosniff.
2. **Определите границы origin** — поддомены, порты, схемы.
3. **Ищите ослабления SOP** — `document.domain`, CORS, postMessage.
4. **Оцените CORB/ORB** — какие ответы можно включить как скрипт.
5. **Стройте атаки в «щелях»** — CSRF, XS-Leaks, JSONP.
6. **Учитывайте Site Isolation** — что стало невозможно.
7. **Тупик** — переходите к конкретным клиентским классам.

## Справочная таблица

| Механизм | Что защищает | Обходится |
|----------|--------------|-----------|
| SOP | чтение чужого origin | CORS/JSONP/XSSI |
| Site Isolation | Spectre, утечки памяти | side-channels |
| CORB/ORB | XSSI через типизированные ответы | JSONP text/javascript |
| COOP | opener, tabnabbing | — |
| COEP/CORP | встраивание ресурсов | — |
| `document.domain` | ослабляет SOP | устаревшее |
| PNA | запросы к локальной сети | SSRF-подобные |

## Глубже: Private Network Access (PNA)

PNA — относительно новый механизм, ограничивающий доступ публичных сайтов к локальной сети. Идея: страница из интернета не должна без разрешения обращаться к `127.0.0.1`, приватным диапазонам и `.local`. Браузер отправляет preflight-запрос с заголовком `Access-Control-Request-Private-Network: true`, и сервер должен ответить `Access-Control-Allow-Private-Network: true`. Это защита от атак, где вредоносная страница сканирует локальную сеть жертвы (SSRF из браузера).

```bash
# проверяем, поддерживает ли приложение PNA-заголовки (для локальных ресурсов)
curl -sI https://t/local-api -H 'Access-Control-Request-Private-Network: true' | grep -i private-network
```

Понимание PNA важно при тестировании DNS rebinding и браузерных SSRF: некоторые векторы, работавшие раньше, теперь блокируются.

## Глубже: как использовать модель в тестировании

Модель браузера — это карта того, что возможно и невозможно. Начните с определения origin-границ: какие поддомены, порты и схемы существуют, где проходят границы cookie и CORS. Затем проверьте заголовки изоляции (COOP/COEP/CORP) и их отсутствие. Далее ищите **ослабления SOP**: CORS с отражением origin, postMessage без проверки, `document.domain`, JSONP с `text/javascript`. Каждое ослабление — канал чтения чужого origin. Наконец, проверьте «щели»: CSRF (действия без чтения), XS-Leaks (утечка состояния через различимое поведение), кликджекинг (действия через UI).

```bash
# карта origin и заголовков
for h in https://t https://api.t https://static.t; do
  echo "== $h"; curl -sI "$h" | grep -iE 'access-control|content-type|x-content-type|cross-origin'
done
```

Такой системный проход показывает, где модель ослаблена, и направляет атаку в нужное место.

## Глубже: почему это важно для отчёта

Понимание модели браузера делает отчёты точными. Вместо «нашли XSS» вы пишете «XSS на поддомене, cookie основного домена недоступны из-за скоупа, но через postMessage можно…» — это показывает глубину анализа и реальный импакт. Вместо «есть CORS» — «ACAO отражает origin, ACAC: true, что позволяет читать приватный API с сессией жертвы». Заказчик ценит не набор багов, а понимание их последствий в контексте браузерной модели.

## Итог

Модель безопасности браузера — это SOP, Site Isolation, CORB/ORB, COOP/COEP/CORP и PNA. SOP запрещает чтение, но разрешает действия — отсюда CSRF и XS-Leaks. CORB/ORB блокируют XSSI, но не JSONP с `text/javascript`. COOP/COEP изолируют контексты и включают мощные API. Понимание каждого механизма позволяет точно определить, работает атака или нет, и правильно оценить импакт. Проверяйте заголовки, границы origin и ослабления SOP — это и есть системный клиентский аудит.

## Частые ошибки при аудите клиентской модели

Первая — считать все поддомены «одним origin». Нет: `a.com`, `api.a.com` и `static.a.com` — разные origin, и cookie/CORS-границы между ними важны. Вторая — игнорировать порт и схему: `https://a.com` и `http://a.com:8080` — разные origin. Третья — не проверять заголовки изоляции, хотя их отсутствие открывает целый класс атак (tabnabbing, утечки). Четвёртая — путать SOP и CORS: CORS не «ослабляет» SOP для всех, а лишь разрешает конкретные кросс-доменные чтения при явном согласии сервера. Пятая — забывать про «щели» SOP: CSRF и XS-Leaks не требуют чтения ответа и потому работают даже при строгом SOP. Шестая — не учитывать новые механизмы (PNA, CHIPS для cookie, partitioned storage), которые меняют ландшафт атак.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Чем Origin отличается от Site?"
  options:
    - "Origin = схема+хост+порт; Site = схема+eTLD+1"
    - "Это одно и то же"
    - "Site = IP"
    - "Origin = cookie"
  answer: 0
  explanation: "Site группирует поддомены одного регистрируемого домена."
- question: "Что делает `Cross-Origin-Opener-Policy: same-origin`?"
  options:
    - "Изолирует `window.opener` от чужих документов"
    - "Шифрует cookies"
    - "Отключает TLS"
    - "Включает CORS"
  answer: 0
  explanation: "COOP ломает reverse-tabnabbing и часть XS-Leaks."
- question: "Зачем CORB/ORB?"
  options:
    - "Блокируют чтение кросс-ориджин «чувствительных» ресурсов через теги"
    - "Ускоряют сайт"
    - "Меняют DNS"
    - "Ставят cookie"
  answer: 0
  explanation: "Они мешают утечке HTML/JSON через `<img>`/`<script>`."
- question: "Что включает cross-origin isolation?"
  options:
    - "COOP + COEP"
    - "CORS + CORP"
    - "TLS + HSTS"
    - "DNS + CDN"
  answer: 0
  explanation: "Только их комбинация даёт `crossOriginIsolated === true`."
- question: "Что делает `Cross-Origin-Resource-Policy: same-origin`?"
  options:
    - "Запрещает встраивание ресурса с других origin"
    - "Разрешает всем"
    - "Шифрует ресурс"
    - "Отключает кэш"
  answer: 0
  explanation: "CORP ограничивает, кто может встраивать ответ."
```

## Где пригодится

- **CTF (Web):** задачи на browser-side изоляцию и «почему не читается».
- **Bug bounty:** аудит отсутствующих security-заголовков как цепочка к утечкам.
- **Пентест:** понимание границ доверия при клиентских атаках.
- **Работа (AppSec/Dev):** внедрение COOP/COEP/CORP и корректной cookie-политики.
