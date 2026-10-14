---
id: web-cms-fingerprint
title: "CMS/plugin fingerprinting: определение движка, версии и расширений"
category: web
parent: web-cms-enterprise
difficulty: medium
order: 4
tags: [cms, fingerprint, whatweb, wpscan, droopescan, version-mapping, recon]
prerequisites: [web-cms-platforms]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Системный подход к определению CMS и её версий: паспортные пути, генераторы, сканеры и таблица сопоставления сигнатур движкам."
---

## Вопрос, с которого всё начинается

Ты на новой цели. Сайт выглядит как блог, но написан ли он на WordPress, Drupal или на самописном фреймворке? От ответа зависит весь дальнейший план. Ошибка на этом шаге стоит часов работы: будешь гонять `wpscan` по Drupal-у и удивляться пустому выводу. Сегодня — система, которая отвечает на вопрос «что там внутри» за минуту.

## Наш пример: незнакомый сайт

Цель — `https://unknown.target.example`. Никаких подсказок, только URL. Начинаем с универсального сканера.

## Шаг 1: whatweb — первый заход

```
$ whatweb -a 3 https://unknown.target.example
https://unknown.target.example [200 OK] Country[US], HTTPServer[nginx/1.24.0],
  MetaGenerator[WordPress 6.4.2], X-Powered-By[PHP/8.2.1], WordPress
```

`whatweb` (агрессивность `-a 3` — больше проверок) уже ответил: **WordPress 6.4.2**, nginx 1.24.0, PHP 8.2.1. Три факта за один запрос. Если бы это был Drupal, мы бы увидели `Drupal` и `X-Generator`; если Joomla — `Joomla`.

## Шаг 2: паспортные пути — когда whatweb молчит

Сканеры ошибаются или их блокирует WAF. Тогда идём по «паспортным» путям вручную — у каждого движка они свои:

```
$ for p in /wp-json/ /CHANGELOG.txt /administrator/ /magento_version; do
    echo -n "$p -> "; curl -s -o /dev/null -w '%{http_code}\n' "https://unknown.target.example$p"
  done
/wp-json/ -> 200
/CHANGELOG.txt -> 404
/administrator/ -> 404
/magento_version -> 404
```

`/wp-json/` вернул 200 — подтверждение WordPress. Дополнительно `/readme.html` часто хранит версию:

```
$ curl -s https://unknown.target.example/readme.html | grep -io 'version [0-9.]*' | head -1
Version 6.4.2
```

## Шаг 3: перечисление расширений

Знать CMS мало — нужны **плагины и темы** и их версии. Для WordPress это `wpscan`:

```
$ wpscan --url https://unknown.target.example --enumerate vp,vt,u --no-banner
[+] WordPress version 6.4.2
[+] Plugin: woocommerce (version 8.2.0)
[+] Plugin: elementor (version 3.18.0) — outdated
[+] Theme: astra (version 4.5.0)
[+] User(s): admin, shopmanager
```

Здесь `vp` = vulnerable plugins, `vt` = vulnerable themes, `u` = users. Мы получили список плагинов с версиями и пользователей. Это карта поверхности атаки.

Для других движков:

| CMS | Инструмент |
|---|---|
| WordPress | `wpscan` |
| Drupal | `droopescan scan drupal` |
| Joomla | `joomscan -u` |
| Magento | `magescan` |
| Универсальный | `cmseek` |

## Шаг 4: генераторы и заголовки

Помимо сканеров, версию выдают «мелочи»:

- мета-тег `<meta name="generator" content="WordPress 6.4.2">`;
- заголовок `X-Generator` (Drupal);
- заголовок `X-Powered-By` (PHP/фреймворк);
- cookie: `wordpress_*`, `PHPSESSID`, `JSESSIONID` — подсказывают стек.

Проверим cookie и заголовки разом:

```
$ curl -sI https://unknown.target.example | grep -iE 'server|x-powered|set-cookie|x-generator'
server: nginx/1.24.0
x-powered-by: PHP/8.2.1
set-cookie: wordpress_test_cookie=WP+Cookie+check
```

Cookie `wordpress_test_cookie` — ещё одно подтверждение.

## Шаг 5: сопоставление версии с уязвимостями

Финальный шаг фингерпринта — не просто «узнать», а **сопоставить с базой**. Держи в голове три источника:

1. **WPScan DB** — по ядру/плагинам/темам WordPress;
2. **CVE/NVD** — по точной версии любого движка;
3. **nuclei** — шаблоны, названные по CVE-id (`CVE-2024-XXXX.yaml`).

Запускаем целевой скан:

```
$ nuclei -u https://unknown.target.example -tags wordpress -silent
[CVE-2023-XXXX] [http] [high] https://unknown.target.example/wp-content/plugins/elementor/...
```

Итог: мы превратили «незнакомый сайт» в конкретный список «версия → известная уязвимость → PoC».

## Что мы теперь знаем

- `whatweb -a 3` даёт движок и версию в первом же запросе.
- «Паспортные» пути (`/wp-json/`, `/CHANGELOG.txt`, `/administrator/`, `/magento_version`) подтверждают движок вручную.
- Расширения и пользователей перечисляют `wpscan`/`droopescan`/`joomscan`/`magescan`/`cmseek`.
- Версию выдают мета-теги, заголовки и cookies.
- Фингерпринт завершается сопоставлением версии с базой уязвимостей (WPScan DB / CVE / nuclei).

## Шаг 6: ручной фингерпринт без инструментов

Иногда под рукой только `curl`. Этого достаточно. Начни с заголовков — они бесплатны и информативны:

```
$ curl -sI https://unknown.target.example
HTTP/2 200
server: nginx/1.24.0
x-powered-by: PHP/8.2.1
set-cookie: wordpress_test_cookie=WP+Cookie+check; path=/
```

`wordpress_test_cookie` — почти подпись WordPress. Дальше — три запроса по «паспортным» путям:

```
$ curl -s -o /dev/null -w '%{http_code} /wp-json/\n'   https://unknown.target.example/wp-json/
200 /wp-json/
$ curl -s -o /dev/null -w '%{http_code} /administrator/\n' https://unknown.target.example/administrator/
404 /administrator/
$ curl -s -o /dev/null -w '%{http_code} /CHANGELOG.txt\n' https://unknown.target.example/CHANGELOG.txt
404 /CHANGELOG.txt
```

200 на `/wp-json/` при 404 на остальных — это WordPress. Версию добираем из `readme.html` или из статики темы.

## Шаг 7: чек-лист фингерпринта и частые ошибки

Полный чек-лист, который стоит прогонять на каждой новой цели:

1. `whatweb -a 3` — стек и версии в один заход.
2. Заголовки (`curl -sI`) — сервер, `X-Powered-By`, cookies.
3. «Паспортные» пути — подтверждение движка.
4. `robots.txt` и `sitemap.xml` — скрытые разделы, админки, API.
5. Сканер движка (`wpscan`/`droopescan`/`joomscan`/`magescan`).
6. `nuclei` по тегу движка — известные CVE.

Частые ошибки: доверять одному признаку; игнорировать CDN-маскировку; не проверять `robots.txt`; забывать про версии **расширений** (не только ядра). И главная — **делать вывод «безопасно» без полного активного скана**. Отсутствие находки в ручном осмотре не значит, что уязвимостей нет: современный хост может нести свежую CVE, о которой ты не знаешь. Фингерпринт — это начало работы, а не её конец.

## Шаг 8: закрепление и переход к эксплуатации

Фингерпринт — это не самоцель, а **вход в эксплуатацию**. Правильная последовательность: определить движок и версию → составить список расширений с версиями → сопоставить с базой уязвимостей → выбрать безопасную проверку → подтвердить → эксплуатировать. Пропуск любого шага ведёт к ошибкам: эксплуатируешь не ту версию, бьёшь по несуществующему пути, делаешь вывод «не уязвимо» без оснований.

И главное правило, которое повторяется в каждом уроке ветки: **отсутствие ручной находки ≠ безопасность**. Полноценный вывод о состоянии цели делается только после завершённого активного скана (`whatweb` + сканер движка + `nuclei`). Пока скан не завершён, любое «тут чисто» — преждевременно.

## Шаг 9: автоматизация и повторяемость

Фингерпринт выигрывает от автоматизации: на десятках целей ручной обход не масштабируется. Собери простой конвейер: список целей → `httpx` (живые хосты и заголовки) → `whatweb` (стек) → тематический сканер (по движку) → `nuclei` (CVE). Результаты складывай в таблицу «хост / движок / версия / расширения / кандидаты CVE».

Повторяемость важна и для отчёта: один и тот же конвейер на разных целях даёт сравнимые данные, а значит — приоритизацию. Где уязвимость выше и импакт больше, туда и уходят усилия.

## Практика: фингерпринт без единого сканера

Сканеры шумят и блокируются WAF. Поэтому навык «определить CMS глазами» обязателен. Начнём с заголовков и пассивных признаков:

```
$ curl -sI https://site.target.example | grep -iE 'server|x-powered|set-cookie|link'
Server: nginx
X-Powered-By: PHP/8.1.2
Set-Cookie: wp-settings-1=...; path=/
Link: <https://site.target.example/wp-json/>; rel="https://api.w.org/"
```

Три признака сразу выдают WordPress: cookie `wp-settings-*`, заголовок `Link` с `wp-json`, и `X-Powered-By: PHP`. Ни одного запроса к «специальному» пути — только корень.

Дальше уточняем через уникальные пути, но аккуратно, по одному:

```
$ for p in /wp-login.php /administrator/ /user/login /admin/login ; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "https://site.target.example$p")
    echo "$code  $p"
  done
200  /wp-login.php
404  /administrator/
404  /user/login
404  /admin/login
```

`200` на `/wp-login.php` подтверждает WordPress, а не просто PHP. Такой метод надёжнее, чем «определение по favicon», и легко документируется.

## Практика: версия из статики, а не из заголовков

Заголовки врут и урезаются прокси. Версия надёжнее лежит в статике. Для WordPress:

```
$ curl -s https://site.target.example/ | grep -oE 'ver=[0-9.]+' | sort -u
ver=6.4.2
ver=1.7
```

Первый — версия ядра (в query у `/wp-includes/`), второй — версия jQuery. Для Drupal версия есть в `CHANGELOG.txt` или в `core/lib/Drupal.php`; для Joomla — в `administrator/manifests/files/joomla.xml` (`<version>4.2.6</version>`). Каждый движок прячет версию в «паспортном» файле, и знание этих файлов — половина навыка фингерпринта.

## Таблица: паспортные пути по движкам

| Движок | Файл/путь с версией | Доп. признак |
|---|---|---|
| WordPress | `/wp-includes/js/wp-embed.min.js?ver=` | `Link: wp-json` |
| Drupal | `/CHANGELOG.txt`, `/core/CHANGELOG.txt` | `X-Generator` |
| Joomla | `/administrator/manifests/files/joomla.xml` | `/components/com_` |
| Magento | `/magento_version`, cookie `X-Magento-*` | `/static/version.../` |
| TYPO3 | `/typo3/`, `?type=...` | `Set-Cookie: be_typo_user` |
| Ghost | `/ghost/api/content/` | `<meta name="generator" content="Ghost">` |
| Craft | `/admin/login`, `X-Powered-By: Craft CMS` | cookie `CraftSessionId` |

Держи эту таблицу под рукой: по ней ты за минуту определишь движок на незнакомом сайте и не будешь наугад лить `wp-login.php` в Drupal.

## Как не ошибиться: ложные признаки

Ложные срабатывания — главная ловушка фингерпринта. Сайт может отдавать `X-Powered-By: PHP` и при этом быть на Laravel, а не на WordPress. `X-Generator` иногда выставляют руками. Поэтому правило: **минимум три независимых признака**, прежде чем делать вывод. Хороший набор — cookie + заголовок + уникальный путь. Если все три совпали, ошибка почти исключена. И обязательно сохраняй каждый признак в отчёт с точной командой и выводом: «`Set-Cookie: wp-settings-1` — признак WordPress» весит куда больше, чем «похоже на WordPress».

## Квиз

Проверь себя.

```quiz
- question: "Какой флаг whatweb включает больше проверок?"
  options:
    - "-a 3"
    - "-v"
    - "-q"
    - "-o"
  answer: 0
  explanation: "Агрессивность 3 — больше запросов и эвристик."
- question: "Какой путь подтверждает WordPress?"
  options:
    - "/CHANGELOG.txt"
    - "/wp-json/"
    - "/magento_version"
    - "/administrator/"
  answer: 1
  explanation: "REST-API есть только у WordPress."
- question: "Что означает флаг wpscan --enumerate vp?"
  options:
    - "Все посты"
    - "Уязвимые плагины"
    - "Версии PHP"
    - "Пользователи"
  answer: 1
  explanation: "vp = vulnerable plugins."
- question: "Почему нельзя грепать библиотеку nuclei по слову 'wordpress'?"
  options:
    - "Файлы названы по CVE-id, а не по продукту"
    - "Так медленнее"
    - "nuclei не поддерживает теги"
    - "Это запрещено"
  answer: 0
  explanation: "Нужно использовать -tags или точный CVE-id."
- question: "Что даёт cookie wordpress_test_cookie?"
  options:
    - "Пароль админа"
    - "Подтверждение стека WordPress"
    - "Доступ к БД"
    - "RCE"
  answer: 1
  explanation: "Это отпечаток движка."
```

## Куда дальше

Дальше мы углубимся в отдельные движки (WordPress-плагины, Drupal, Joomla) и в связку «версия → CVE → PoC». А пока запомни: **фингерпринт — это первый обязательный шаг любой веб-атаки; без него ты стреляешь вслепую.**

## Где пригодится

- Bug bounty: быстрый триаж новых целей в скоупе.
- Пентест: инвентаризация CMS-парка клиента.
- CTF: определение движка для выбора эксплойта.
