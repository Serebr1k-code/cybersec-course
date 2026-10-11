---
id: web-xs-leaks
title: "XS-Leaks: кросс-сайтовые утечки через браузер"
category: web
parent: web-browser-advanced
difficulty: medium
order: 1
tags: [xs-leaks, side-channel, browser, cors, timing, cache]
prerequisites: [web-same-origin-cors, web-cache-poisoning]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как, не читая ответ чужого домена, узнать его содержимое по косвенным признакам: кэш, тайминги, ошибки, фреймы."
---

Same-Origin Policy не даёт читать ответы чужих сайтов — но она **не делает сайты невидимыми**. Браузер сам «рассказывает» о них через косвенные сигналы: попал ли ресурс в кэш, сколько заняла загрузка, какой размер фрейма, сработала ли навигация. **XS-Leaks (Cross-Site Leaks)** — это класс атак, извлекающих состояние/данные жертвы через такие оракулы. Это современная замена классическим «SOP-обходам» и активно исследуется (xsleaks.dev).

## Теория: оракулы и «вопрос-ответ»

Идея: задаём странице жертвы вопрос, ответ на который влияет на **наблюдаемый** нами сигнал. Если сигнал меняется — мы узнаём ответ, хотя ответ не читаем.

Основные оракулы:

| Оракул | Что наблюдает | Пример вопроса |
|--------|---------------|----------------|
| **Cache** | попал ли ресурс в кэш (время/`load`) | «залогинен ли пользователь?» (страница `/me` кэшируется только для залогиненных) |
| **Timing** | время ответа | «существует ли пользователь?» |
| **Error/Frame count** | сколько фреймов/ошибок | «есть ли на странице iframe с X?» |
| **Navigation** | куда произошёл редирект | «содержит ли страница строку?» |
| **Size/scroll** | размер/скролл фрейма | «есть ли скроллбар?» |
| **Connection pool** | порядок/скорость соединений | «занят ли сокет?» |
| **COSI** | размер ответа по `Content-Length` | «сколько данных?» |

Ключ — найти **вопрос, где ответ жертвы меняет сигнал**, и наблюдаемый канал.

## Теория: cache probing — самый практичный оракул

Сценарий: страница `/account` отдаётся только аутентифицированному пользователю и при этом кэшируется (CDN/proxy). Атакующий на `evil.com`:

1. Заставляет жертву загрузить `https://target/account` (например, через `<img>` или `fetch`-no-cors).
2. Затем сам грузит `https://target/account` и измеряет время / проверяет `X-Cache`.
3. Если ресурс в кэше (быстро/HIT) — жертва аутентифицирована; если MISS — нет.

Так узнаётся состояние логина и даже части данных (через cache busting по параметрам). Связано с **cache deception** (`web-cache-deception`).

## Теория: frame counting и error events

- **frame counting:** если на целевой странице число фреймов зависит от состояния (например, «друзья» показывают iframe), атакующий вставляет страницу в свой iframe и считает `frames.length` (для same-origin-вложенных). Ограничено SOP, но работает в связке с переходами.
- **error events:** загрузка `<img src="https://target/secret.png">` — если ресурс существует и виден, `onload`; если 403/404 — `onerror`. Так проверяют существование/доступность.
- **`onload`/`onerror` на `<script>`/`<link>`** — определяют, отдаётся ли ресурс.

## Теория: COOP/COEP и защита

Современные защиты:
- **`Cross-Origin-Opener-Policy` (COOP)** изолирует `window.opener` — ломает ряд XS-Leaks (например, `window.open` + доступ к `window.length`).
- **`Cross-Origin-Embedder-Policy` (COEP)** запрещает загрузку кросс-ориджин ресурсов без CORP.
- **`Cross-Origin-Resource-Policy` (CORP)** ограничивает встраивание ресурсов.
- **`SameSite` cookies** мешают автоматическому включению cookie в кросс-сайтовых запросах.
- **`Cache-Control: no-store`** и `Vary` снимают cache-оракулы.

Отсутствие этих заголовков — признак потенциальных XS-Leaks.

## Инструменты и команды

Проверить защитные заголовки:

```bash
curl -s -I https://target.local/ | grep -iE 'cross-origin|cache-control|vary|same-site|content-length'
```

Измерить тайминг загрузки (в DevTools Performance или JS):

```js
// на своей странице (в рамках теста)
const t0 = performance.now();
const img = new Image();
img.src = 'https://target.local/account';
img.onload = img.onerror = () => console.log('ms:', performance.now() - t0);
```

Наблюдать кэш-статус:

```bash
curl -s -i https://target.local/account | grep -iE 'x-cache|cf-cache-status|age'
```

Каталог известных XS-Leaks и их проверок — **xsleaks.dev** (референс).

## Разобранный пример: cache-probe определение логина

Шаг 1. Убеждаемся, что `/account` кэшируется для залогиненных (нет `no-store`), а для анонимов отдаёт редирект/логин:

```bash
curl -s -I https://target.local/account -b 'session=victim' | grep -iE 'cache-control|x-cache'
curl -s -I https://target.local/account | grep -iE 'cache-control|x-cache|location'
```

Шаг 2. На `evil.com` грузим ресурс в контексте жертвы и замеряем, а затем повторяем сами — сравниваем `X-Cache`/время.

Шаг 3. Если после визита жертвы ресурс «HIT» (или быстрее), делаем вывод: жертва аутентифицирована. Это утечка состояния (и потенциально данных). В отчёте: канал (cache), заголовки, измерения.

## Разобранный пример: error-based existence check

Проверяем, существует ли приватный ресурс (например, `https://target/private/report-123.pdf`):

```html
<img src="https://target/private/report-123.pdf" onload="log('exists')" onerror="log('missing')">
```

`onload` → ресурс отдаётся (существует/доступен); `onerror` → нет. Так перебираются ID (см. `web-idor-uuid`).

## Частые ошибки

- **Ждать «чтения» ответа.** XS-Leaks — это косвенный сигнал, а не прямая утечка.
- **Игнорировать защитные заголовки.** COOP/COEP/CORP/SameSite/`no-store` ломают многие оракулы.
- **Не калибровать тайминг.** Сеть шумная; нужны замеры и статистика.
- **Забывать про cache buster.** При probing используйте уникальные параметры, чтобы не задеть реальных пользователей.
- **Путать с CORS.** CORS — это про чтение с разрешения; XS-Leaks — про косвенные сигналы без разрешения.

## Полный разбор: cache probing с измерениями (с выводом)

End-to-end проверка, залогинена ли жертва, через кэш-оракул.

Шаг 1. Убеждаемся, что приватная страница кэшируема (нет `no-store`) и различается для анонима/юзера:

```bash
# от анонима
curl -s -I https://target.local/account | grep -iE 'location|cache-control|x-cache|age|vary'
# HTTP/1.1 302 Found
# location: /login
# cache-control: public, max-age=60

# от залогиненного (эмулируем своей сессией)
curl -s -I https://target.local/account -b 'session=me' | grep -iE 'cache-control|x-cache|age|vary'
# HTTP/1.1 200 OK
# cache-control: public, max-age=60
# -> страница для юзера кэшируется публично: cache-оракул возможен
```

Шаг 2. Логика атаки на `evil.com`:

```html
<!-- 1) заставить жертву загрузить приватную страницу (кэшировать её) -->
<img src="https://target.local/account" style="display:none">
<script>
// 2) подождать и самим запросить ресурс, измерив время / проверив заголовок
setTimeout(async () => {
  const t0 = performance.now();
  await fetch('https://target.local/account', {mode:'no-cors'});   // заполнит/прочитает кэш
  // для измерения времени удобнее <img>/<script> с onload
}, 3000);
</script>
```

На практике время загрузки кэш-HIT резко меньше MISS:

```
MISS (жертва не залогинена): 240 ms
HIT  (жертва залогинена):     12 ms
```

Шаг 3. Делаем вывод: если после визита жертвы ресурс «HIT»/быстрый — жертва аутентифицирована. Это утечка состояния. Для утечки *данных* комбинируйте с cache-busting по ID и наблюдайте, какие ресурсы кэшируются.

## Reference-таблица: оракулы и их проверки

| Оракул | Как проверять | Пример вопроса |
|--------|---------------|----------------|
| Cache | `X-Cache`/`Age`/время, `no-cors` fetch | залогинен ли |
| Timing | `performance.now()` вокруг `<img>` | существует ли юзер |
| Error/onload | `<img onload/onerror>` | доступен ли ресурс |
| Frame count | `frames.length`/`window.length` | сколько виджетов |
| Navigation | `window.open` + redirect | есть ли редирект на X |
| Size (COSI) | `Content-Length` / `onload` | размер ответа |
| Connection pool | тайминг при забитых сокетах | занятость пула |
| Scroll/visual | scroll-to-text, `:target` | есть ли текст |
| Media | `<video>`/`<audio>` `onerror` | тип контента |

## COSI, connection pool, scroll-to-text и другие современные оракулы

- **COSI (Cross-Origin Size Inference):** по `Content-Length` (иногда виден через кэш/`Range`) и времени оценивают размер ответа — можно вытянуть, содержит ли страница конкретную строку.
- **Connection pool:** забивая пул соединений (6 на origin в HTTP/1.1), по времени узнают, занят ли сокет — сложно, но описано.
- **Scroll-to-text (`#:~:text=`):** если страница жертвы содержит текст из фрагмента, браузер скроллит к нему; косвенно детектируется.
- **`:target`/`:visited` (историческое):** CSS-селекторы состояния — сейчас ограничены, но проверяйте старые движки.
- **`window.length` (frame count):** количество фреймов выдаёт структуру страницы.
- **Error messages:** загрузка `<script>`/`<link>` на целевой origin с `onerror`/`onload` раскрывает доступность.

Современный референс всех техник — `xsleaks.dev`.

## Защита: полный набор заголовков

| Заголовок | Значение | Что закрывает |
|-----------|----------|---------------|
| `Cross-Origin-Opener-Policy: same-origin` | изоляция opener | window-opener оракулы |
| `Cross-Origin-Embedder-Policy: require-corp` | запрет кросс-ресурсов без CORP | COSI/встраивание |
| `Cross-Origin-Resource-Policy: same-origin` | запрет встраивания | onload/onerror оракулы |
| `Cache-Control: no-store, private` | не кэшировать | cache probing |
| `Vary: Cookie, Origin` | разделять кэш | cache confusion |
| `SameSite=Lax/Strict` | не слать cookie кросс-сайт | login CSRF, часть оракулов |
| `Content-Security-Policy` | ограничить источники | загрузка ваших ресурсов |
| `Permissions-Policy` | отключить API | часть каналов |

Проверка одним запросом:

```bash
curl -s -I https://target.local/ | grep -iE 'cross-origin|cache-control|vary|same-site|permissions-policy'
```

## Что делать дальше / решение

1. **Инвентаризировать защитные заголовки** — отсутствие COOP/COEP/CORP/`no-store` = потенциал.
2. **Найти приватную кэшируемую страницу** (`/account`, `/me`, `/settings`).
3. **Построить cache-оракул** (HIT/MISS или время) на своём аккаунте.
4. **Проверить error-based** (`<img onload/onerror>`) для перечисления ресурсов/ID.
5. **Проверить frame count и navigation** оракулы.
6. **Оформить PoC** с измерениями и заголовками; отметить класс XS-Leak.

## Практические ограничения и шум

XS-Leaks чувствительны к условиям:

- **Сетевой шум:** тайминговые оракулы требуют многих замеров и статистики; на мобильной сети разброс огромен.
- **Прогрев кэша:** перед probing всегда «прогревайте» (заполняйте) кэш и используйте cache buster, чтобы не спутать свой запрос с чужим.
- **Разделяемое состояние:** кэш CDN общий — легко задеть других; тестируйте на своём ресурсе и в рамках scope.
- **Изоляция браузера:** современные браузеры (partitioning, COOP/COEP, `SameSite`) ломают многие каналы; проверяйте в актуальном Chromium/Firefox.
- **Кросс-браузерность:** оракул, работающий в одном движке, может не работать в другом — фиксируйте версию.

Практический подход: сначала определите, есть ли **стабильная разница сигнала** (HIT/MISS, onload/onerror, значимый разрыв времени). Если сигнал шумит — усильте его (повторы, больший ресурс, `Range`-запросы) и только потом стройте PoC.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Что такое XS-Leaks?"
  options:
    - "Прямое чтение ответа чужого домена"
    - "Извлечение данных о состоянии/контенте чужого сайта по косвенным сигналам"
    - "SQL-инъекция"
    - "Отравление DNS"
  answer: 1
  explanation: "Используются оракулы (кэш, тайминг, ошибки), а не прямое чтение."
- question: "Какой оракул самый практичный для проверки логина?"
  options:
    - "Cache probing"
    - "`document.cookie`"
    - "SQL"
    - "`eval`"
  answer: 0
  explanation: "Закэшированность приватной страницы выдаёт состояние жертвы."
- question: "Что делает `Cross-Origin-Opener-Policy`?"
  options:
    - "Изолирует `window.opener` между документами"
    - "Шифрует cookies"
    - "Включает CORS"
    - "Меняет DNS"
  answer: 0
  explanation: "COOP ломает часть XS-Leaks, связанных с `window.open`/opener."
- question: "Как `onload`/`onerror` помогают в XS-Leaks?"
  options:
    - "Показывают, отдаётся ли ресурс (существует/доступен)"
    - "Читают ответ"
    - "Меняют cookie"
    - "Отключают CSP"
  answer: 0
  explanation: "Успех/ошибка загрузки — оракул существования/доступа."
- question: "Какой заголовок снимает cache-оракул для приватных страниц?"
  options:
    - "`Cache-Control: no-store`"
    - "`Content-Type`"
    - "`Server`"
    - "`X-Powered-By`"
  answer: 0
  explanation: "`no-store` (и `private`) не дают кэшу сохранить приватный ответ."
```

## Где пригодится

- **CTF (Web):** задачи на browser-side утечки и «SOP bypass» — часто XS-Leaks.
- **Bug bounty:** cache-probing и error-based утечки — современный класс, растёт спрос.
- **Пентест:** аудит защитных заголовков (COOP/COEP/CORP/SameSite) и кэш-политик.
- **Работа (AppSec/Dev):** включение изоляции контекста и `no-store` для приватного.
