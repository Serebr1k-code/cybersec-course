---
id: web-architecture
title: "Архитектура веб-приложений: клиент, сервер, БД, прокси"
category: web
parent: web-http-basics
difficulty: beginner
order: 1
tags: [architecture, frontend, backend, api, reverse-proxy, database]
prerequisites: [web-http-basics]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Из чего состоит современное веб-приложение, где живут данные и где возникает большинство уязвимостей."
---

Прежде чем что-то ломать, надо понимать карту местности. Веб-приложение — это не «один сайт», а цепочка компонентов: браузер → CDN/WAF → reverse-proxy → application-сервер → база данных → внешние сервисы. Почти каждая уязвимость из этого дерева живёт на границе двух компонентов, поэтому важно понимать, какой слой за что отвечает.

## Теория: слои веб-приложения

**Клиентская часть (frontend).** Всё, что исполняется в браузере: HTML, CSS, JavaScript. Здесь рождаются XSS, DOM-based уязвимости, проблемы с CORS, утечки токенов в `localStorage`. Важно: frontend не доверяет backend, но и backend не должен доверять frontend. Всё, что пришло от клиента, — потенциально враждебно.

**Reverse-proxy / балансировщик.** nginx, Apache, HAProxy, Traefik, Cloudflare. Отвечает за TLS, кэш, маршрутизацию, лимиты, статику. Именно здесь настраивают правила WAF и `X-Forwarded-*` заголовки. Ошибки конфигурации прокси → path traversal, SSRF, host header injection.

**Application-сервер (backend).** PHP-FPM, Node/Express, Python/Django/Flask/FastAPI, Java/Spring, Go. Здесь выполняется бизнес-логика: аутентификация, авторизация, работа с БД. 90% «интересных» багов — здесь: SQLi, SSTI, десериализация, command injection, IDOR.

**База данных.** MySQL/PostgreSQL/MSSQL/MongoDB/Redis. Хранит пользователей, заказы, сессии. Прямые атаки на БД идут через инъекции из backend-слоя.

**Внешние сервисы.** S3, очереди (RabbitMQ/Kafka), микросервисы, платёжные шлюзы, SMTP. Связь с ними — источник SSRF и утечек токенов/ключей.

**Кэш / сессии.** Redis/Memcached часто хранят сессии и токены. Открытый Redis (порт 6379) без пароля — мгновенный доступ к сессиям.

Типовая схема в виде текста:

```
Browser
  └─(HTTPS)─> CDN/WAF (Cloudflare)
        └─> Reverse proxy (nginx)  ── static files
              └─> App server (node/php/python) ──> Database (PostgreSQL)
                    └─> External services (S3, mail, payment)
```

## Инструменты: как увидеть архитектуру цели

**Wappalyzer / BuiltWith / `whatweb`** — определяют технологии. В CLI:

```bash
whatweb -a 3 https://target.example
```

Ответ покажет CMS, фреймворк, версии библиотек, веб-сервер, язык.

**Заголовки ответа** выдают многое:

```bash
curl -s -I https://target.example
```

`Server: nginx/1.25.3`, `X-Powered-By: Express`, `Set-Cookie: PHPSESSID=...` (значит PHP), `X-Powered-By: Next.js` и т.п.

**Анализ JS-бандлов.** Современные SPA грузят один большой JS-файл, в котором зашиты все API-пути. Скачиваем и ищем эндпоинты:

```bash
curl -s https://target.example/ | grep -oE '/assets/[^"]+\.js' | sort -u
curl -s https://target.example/assets/index-abc123.js -o app.js
grep -oE '"/api/[a-zA-Z0-9_/{}.-]+"' app.js | sort -u
grep -oE 'https?://[a-zA-Z0-9./_-]+' app.js | sort -u
```

Так вы находите скрытые `/api/admin/...`, `/api/internal/...` ручки, которые не видны в UI.

**`robots.txt`, `sitemap.xml`, `.well-known/`** — легальные карты сайта:

```bash
curl -s https://target.example/robots.txt
curl -s https://target.example/sitemap.xml
```

`Disallow:` в robots часто прямо перечисляет админки и приватные разделы — это подсказка, куда смотреть.

## Разобранный пример: рекон структуры типового SPA

Цель — `https://app.example` (React SPA + backend API).

Шаг 1. Определяем стек:

```bash
whatweb -a 3 https://app.example | tr ',' '\n'
```

Видим `React`, `Next.js`, `nginx`.

Шаг 2. Забираем HTML и ищем бандлы:

```bash
curl -s https://app.example/ | grep -oE 'src="[^"]+\.js"' 
# -> src="/static/js/main.7f3a9c.js"
```

Шаг 3. Качаем бандл и вытаскиваем API-пути и ключи:

```bash
curl -s https://app.example/static/js/main.7f3a9c.js -o main.js
grep -oE '/api/v[0-9]+/[a-zA-Z0-9_/{}.-]+' main.js | sort -u
grep -oE '(api[_-]?key|token|secret)["\']?\s*[:=]\s*["\'][^"\']+' main.js -i | head
```

Шаг 4. Проверяем каждый найденный эндпоинт на существование и метод:

```bash
for p in /api/v1/users /api/v1/admin /api/v1/orders; do
  echo -n "$p -> "; curl -s -o /dev/null -w '%{http_code}\n' "https://app.example$p"
done
```

Так за 5 минут вы получаете карту приложения: какие сервисы, какие API, какие ключи засветились на клиенте. Дальше эти ручки становятся целью для IDOR/инъекций.

## Типичные ошибки новичков

- **Смотреть только главную страницу.** Реальная функциональность живёт в подпутях (`/admin`, `/api`, `/debug`, `/actuator`). Их надо фаззить (следующий урок).
- **Забыть про API.** Многие тестируют UI, а баг — в API, которое UI не вызывает. Всегда вытаскивайте эндпоинты из JS.
- **Верить, что «на фронте спрятано — значит недоступно».** Скрытые поля, `localStorage`, отключённые кнопки — всё это управляется клиентом и тривиально обходится.
- **Путать слои.** Если вы нашли nginx 1.25.3, это не значит, что уязвимо приложение. Различайте: серверная CVE vs логика приложения.
- **Не проверять технологию через несколько источников.** Wappalyzer может ошибаться; сверяйте заголовки, cookie-имена и структуру JS.
- **Игнорировать микросервисы.** Один фронтенд может ходить в 10 бэкендов на разных поддоменах — каждый со своей атакуемой поверхностью.

## Reference-таблица: слои, технологии, типичные уязвимости

| Слой | Типичные технологии | Класс уязвимостей |
|------|---------------------|-------------------|
| Frontend | React/Vue/Angular, Webpack/Vite | XSS, DOM-XSS, prototype pollution, утечки в `localStorage` |
| CDN/WAF | Cloudflare, Akamai, Fastly | cache poisoning/deception, WAF bypass |
| Reverse-proxy | nginx, Apache, HAProxy, Traefik | path traversal, alias misconfig, host header |
| App server | Node/Express, PHP-FPM, Django, Spring, Go | SQLi, SSTI, deser, cmd-injection, IDOR, SSRF |
| DB | PostgreSQL, MySQL, MSSQL, MongoDB, Redis | injection, auth bypass, UDF RCE |
| Cache/session | Redis, Memcached | no-auth access, session forgery |
| External | S3, Kafka, SMTP, payment | SSRF, key leakage, webhook abuse |
| Auth | OAuth2/OIDC/SAML/JWT | redirect_uri, alg confusion, XSW |

Знание стека сразу подсказывает, какие CVE и классы проверять: `X-Powered-By: Express` → Node-специфика; `PHPSESSID` → PHP-обёртки/type juggling; `Server: nginx` → alias traversal и proxy-мисконфиги.

## Полный разбор: рекон через заголовки, JS, robots (с выводом)

```bash
# 1. технологии и версии
whatweb -a 3 https://app.example | tr ',' '\n' | grep -iE 'nginx|express|react|php|cloudflare'
# nginx[1.25.3], Express, React, Cloudflare

# 2. заголовки (индикаторы стека и защиты)
curl -s -I https://app.example | grep -iE 'server|x-powered-by|set-cookie|cross-origin|content-security'
# server: nginx
# x-powered-by: Express
# set-cookie: connect.sid=...; HttpOnly; SameSite=Lax
# (нет CSP/COOP -> поверхность для XSS/XS-Leaks)

# 3. robots.txt и sitemap (карта скрытых разделов)
curl -s https://app.example/robots.txt
# Disallow: /admin
# Disallow: /internal
# Disallow: /api/v2

# 4. JS-бандл -> API-эндпоинты и ключи
curl -s https://app.example/ | grep -oE 'src="[^"]+\.js"' | head
curl -s https://app.example/static/js/main.abc.js -o main.js
grep -oE '/api/v[0-9]+/[a-zA-Z0-9_/{}.-]+' main.js | sort -u
# /api/v1/users
# /api/v1/admin/settings
# /api/v1/orders/{id}
grep -oE '(api[_-]?key|secret|token)["\x27]?\s*[:=]\s*["\x27][^"\x27]+' -i main.js | head
# api_key: "sk_live_51H..."   -> засвеченный ключ

# 5. проверка найденных эндпоинтов
for p in /api/v1/users /api/v1/admin/settings; do
  echo -n "$p -> "; curl -s -o /dev/null -w '%{http_code}\n' "https://app.example$p"
done
# /api/v1/users -> 401
# /api/v1/admin/settings -> 200   -> интересно
```

За 5 минут получаем: стек, защитные заголовки, скрытые разделы и список API с потенциально засвеченным ключом. Дальше — IDOR/инъекции по этим ручкам.

## Микросервисы, API-gateway и surface

Современные приложения — не монолит, а граф сервисов:

- **API-gateway** (Kong, APISIX, AWS API Gateway) — единая точка входа; маршрутизация, auth, rate-limit. Мисконфиги маршрутов дают доступ к внутренним сервисам.
- **Внутренние сервисы** (`*.svc.cluster.local`, `/internal/`, gRPC) — часто без auth, доверяют сети; SSRF/SSRF-chain сюда ведёт.
- **Отдельные поддомены** (`api.`, `admin.`, `internal.`, `staging.`) — каждый со своей поверхностью; собирайте через subfinder/httpx.
- **Service discovery** (`/actuator`, `/health`, `/metrics`, `/swagger`, `/v2/api-docs`) — раскрывают карту сервисов.
- **Message queues/webhooks** — вход для инъекций и SSRF.

Правило: одна UI-страница может обращаться к десяткам бэкендов. Картируйте их через сетевую панель браузера и JS-бандлы, а не только через видимые ссылки.

## Что делать дальше / решение

1. **Определить стек** (`whatweb`, заголовки, cookie-имена).
2. **Снять защитные заголовки** (CSP/COOP/CORS/HSTS) — понять поверхность.
3. **Вытащить карту** из `robots.txt`, `sitemap.xml`, JS-бандлов, `/actuator`, `/swagger`.
4. **Перечислить поддомены/сервисы** (subfinder → httpx).
5. **Проверить каждый эндпоинт** на существование/метод/авторизацию.
6. **Перейти к фаззингу** скрытых путей (см. `web-tools-fuzz`) и ручному анализу в Burp.

## Модель доверия между слоями

Главная причина большинства веб-уязвимостей — **разрыв в модели доверия** на границе компонентов. Каждый слой должен валидировать вход, но на практике это делают «где-то в одном месте».

- **Браузер → backend:** клиентская валидация (JS) — не защита; атакующий обходит её напрямую. Backend обязан валидировать всё заново.
- **Прокси → приложение:** приложение доверяет `X-Forwarded-*`, `Host`, внутренним IP. Если прокси не перезаписывает эти заголовки, клиент может их подделать (host header, SSRF, cache poisoning).
- **Приложение → БД:** конкатенация строк в запросе → инъекция; параметризация — обязательна.
- **Сервис → сервис:** микросервисы часто доверяют друг другу без auth («внутренняя сеть безопасна»). SSRF или скомпрометированный сервис получает доступ ко всему.
- **Frontend → внешние домены:** доверие любому `Origin`/`redirect_uri`/`jku` ломает CORS/OAuth/JWT.

Практический вывод для тестировщика: ищите места, где один слой **предполагает**, что другой уже проверил вход. Именно там рождаются обходы — двойное декодирование, разные парсеры у прокси и приложения, доверие заголовкам. Спрашивайте на каждом стыке: «а что, если этот заголовок/поле подделать?» — и это укажет следующий вектор.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Где чаще всего находится бизнес-логика и уязвимости уровня приложения?"
  options:
    - "В CDN"
    - "В application-сервере (backend)"
    - "В CSS"
    - "В DNS"
  answer: 1
  explanation: "Backend исполняет логику и общается с БД."
- question: "Зачем атакующему анализировать JS-бандлы SPA?"
  options:
    - "Чтобы украсить сайт"
    - "Чтобы найти скрытые API-эндпоинты и зашитые ключи"
    - "Чтобы ускорить загрузку"
    - "Чтобы получить TLS-сертификат"
  answer: 1
  explanation: "Бандл содержит все маршруты API и часто — токены/ключи."
- question: "Что означает заголовок `X-Powered-By: Express`?"
  options:
    - "Сайт использует сервер Express (Node.js)"
    - "Сайт за Cloudflare"
    - "База данных — Express"
    - "Это ошибка конфигурации CORS"
  answer: 0
  explanation: "Это индикатор технологии backend."
- question: "Какой компонент чаще всего отвечает за WAF и терминацию TLS?"
  options:
    - "База данных"
    - "Reverse-proxy / CDN"
    - "application-сервер"
    - "браузер"
  answer: 1
  explanation: "nginx/Cloudflare/HAProxy на входе."
- question: "Что из перечисленного НЕ является слоем типового веб-приложения?"
  options:
    - "Frontend (браузер)"
    - "Reverse-proxy"
    - "Application-сервер"
    - "Компилятор C++"
  answer: 3
  explanation: "Компилятор C++ — не часть веб-архитектуры."
```

## Где пригодится

- **CTF (Web):** понимание слоёв позволяет быстро понять, куда «бить» — в прокси, в приложение или в БД; часто флаг лежит в скрытом API, найденном в JS.
- **Bug bounty:** карта технологий и эндпоинтов — первый шаг любого отчёта; скрытые API часто оказываются самым дорогим багом.
- **Пентест:** определение архитектуры задаёт стратегию (внешний/внутренний периметр, точки входа).
- **Работа (AppSec/архитектор):** ревью архитектуры и threat modeling опираются на понимание этих слоёв и их границ доверия.
