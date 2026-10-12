---
id: web-tool-wfuzz-burp-intruder
title: "wfuzz и Burp Intruder: полный практический справочник"
category: web
parent: web-tools-fuzz
difficulty: medium
order: 3
tags: [wfuzz, burp, intruder, fuzzing, payloads, brute, tooling]
prerequisites: [web-tooling, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 40
summary: "wfuzz (payloads, encoders, iterators, фильтры) и Burp Intruder (sniper/battering ram/pitchfork/cluster bomb) с рецептами."
---

## Задача

`ffuf` и `gobuster` хороши, когда позиция подстановки одна. Но бывают задачи сложнее: перебрать **пару** логин-пароль, где нужны **два** словаря одновременно; или подставить payload, **закодированный** в base64; или разметить несколько позиций и гонять их разными наборами значений.

Здесь нужны **wfuzz** (мощный движок payload/encoders/iterators в консоли) и **Burp Intruder** (то же самое, но в GUI с ручной разметкой позиций).

## Данные, с которыми работаем

Форма логина `https://shop.acme-lab.test/login` (метод POST, поля `user` и `pass`) и словари `users.txt`, `pass.txt`. Плюс эндпоинт `https://shop.acme-lab.test/api/order?id=` для перебора ID.

## Пробуем в лоб

Обычный перебор одним словарём:

```bash
$ wfuzz -w users.txt -u https://shop.acme-lab.test/login -d 'user=FUZZ&pass=x' --hc 200
```

Все ответы — `200` со страницей ошибки, потому что пароль всегда неверный. Проблема в том, что `ffuf`/`wfuzz` с одним словарём перебирают **одну** позицию. Нужны две сразу.

## Приём 1: два словаря — `-z` и ключевые слова

В wfuzz каждый источник payload задаётся флагом `-z` (тип, параметры, необязательный encoder) и получает **своё** ключевое слово: `FUZZ`, `FUZ2Z`, `FUZ3Z`. Сначала — перебор всех комбинаций (по умолчанию `product`):

```bash
$ wfuzz -z file,users.txt:FUZZ -z file,pass.txt:FUZ2Z \
       -d 'user=FUZZ&pass=FUZ2Z' -u https://shop.acme-lab.test/login --hc 200
=====================================================================
ID    Response   Lines   Word   Chars   Payload
=====================================================================
00042: 302     0 L     1 W    0 Ch     "admin - hunter2"
```

Строка `302` (редирект после успешного входа) выделилась: `admin:hunter2`. Пара найдена.

> **Термин.** `--hc` — *hide code*: скрыть ответы с этим HTTP-кодом. Здесь мы спрятали все `200` (страницы «неверный пароль»), чтобы увидеть единственный `302`.

## Приём 2: `zip` вместо `product`

`product` — это **все** комбинации (медленно). Если у тебя уже есть список пар «логин:пароль» и надо идти по ним параллельно, используй iterator `zip`:

```bash
$ wfuzz -z file,users.txt:FUZZ -z file,pass.txt:FUZ2Z,zip \
       -d 'user=FUZZ&pass=FUZ2Z' -u https://shop.acme-lab.test/login --hc 200
```

`zip` берёт по одной строке из каждого набора (1-я с 1-й, 2-я со 2-й), а `product` — декартово произведение. Ещё есть `chain` (последовательно) — посмотреть все: `wfuzz -e iterators`.

## Приём 3: encoders

Третий параметр `-z` — encoder, применённый к payload. Полезно для обхода фильтров:

```bash
$ wfuzz -z file,payloads.txt,base64 -u 'https://shop.acme-lab.test/api?data=FUZZ' --hc 400
$ wfuzz -z file,payloads.txt,urlencode -u 'https://shop.acme-lab.test/search?q=FUZZ' --hc 404
```

Доступные: `urlencode`, `double urlencode`, `base64`, `md5`, `sha1`, `hexlify`, `html_escape`, `uri_hex`, `none`. Посмотреть: `wfuzz -e encoders`.

## Приём 4: фильтры wfuzz

Фильтры — самая выразительная часть. Можно скрывать/показывать по коду, строкам, словам, размеру и regex:

```bash
# скрыть 404 и показать только ответы, где встречается слово admin
$ wfuzz -w raft.txt -u https://shop.acme-lab.test/FUZZ --hc 404 --ss admin

# выражение: код 200, меньше 8 строк, больше 100 слов
$ wfuzz -w raft.txt -u https://shop.acme-lab.test/FUZZ --filter 'c=200,l<8,w>100'
```

`--hc/--hl/--hw/--hh` — *hide* по коду/строкам/словам/размеру; `--sc/--sl/--sw/--sh` — *show*; `--ss/--hs` — по regex; `--filter 'выражение'` — комбинированная логика.

## Приём 5: Burp Intruder — четыре типа атак

Intruder работает в GUI: ты **размечаешь позиции** (`§...§`), выбираешь тип атаки и наборы payload. Типов ровно четыре:

| Тип | Как работает | Когда |
|-----|--------------|-------|
| **Sniper** | Один набор; значение идёт по одной позиции за раз | Перебор одного параметра |
| **Battering ram** | Один набор; одно значение во **все** позиции | Одно значение везде |
| **Pitchfork** | Несколько наборов; идут **параллельно** (1-й с 1-м) | Пары логин:пароль, id:token |
| **Cluster bomb** | Несколько наборов; **все комбинации** | Логин×пароль целиком |

Примеры разметки: `?id=§1§` (Sniper по одному параметру); `user=§a§&pass=§b§` (Pitchfork — пары; Cluster bomb — все комбинации). Наборы payload задаются типами Simple list, Runtime file, Numbers, Brute forcer и др. **Payload processing** добавляет префикс/суффикс, кодирование (URL/base64/hash), match-replace.

> **Важно про CSRF.** Форма с токеном в Intruder не сработает «в лоб»: токен надо извлекать из ответа (**Grep — Extract**) и подставлять в следующий запрос, иначе сервер отвергнет все попытки.

## Полный прогон от начала до конца

1. `wfuzz -w users.txt -u .../login -d 'user=FUZZ&pass=x' --hc 200` → одним словарём не выходит.
2. `wfuzz -z file,users.txt:FUZZ -z file,pass.txt:FUZ2Z -d 'user=FUZZ&pass=FUZ2Z' ... --hc 200` → пара `admin:hunter2`.
3. `wfuzz -z file,payloads.txt,base64 ... --hc 400` → закодированный payload прошёл.
4. `wfuzz ... --filter 'c=200,w>100'` → сузили вывод до интересных ответов.
5. В Intruder: Sniper по `?id=§1§` → находим чужие объекты (IDOR).

## Если не сработало

- **Вывод утонул.** Забыл `--hc 404` (или `--hc 200` для логина) — без фильтра wfuzz печатает всё.
- **Пара не находится.** Спутал `zip` и `product`: `zip` — параллельно, `product` — все комбинации.
- **Два словаря конфликтуют.** Второе ключевое слово должно отличаться: `FUZZ` и `FUZ2Z`.
- **Intruder «всё красное».** Нет Grep-Match — добавь маркер успеха (`Welcome`, `302`).
- **Pitchfork теряет данные.** Наборы разной длины: итерация идёт до конца меньшего.
- **Слишком шумно.** Снизь потоки `-t 20` и добавь задержку `-s 0.2`; проверь `--dry-run` заранее.

## Шпаргалка: wfuzz

| Флаг | Что делает |
|------|-----------|
| `-z file,LIST[:KEY][,ENCODER]` | источник payload (файл/список/диапазон + encoder) |
| `-w LIST` | алиас `-z file,LIST` |
| `-u URL` / `-X` / `-d` / `-H` / `-b` | цель / метод / тело / заголовок / cookie |
| `--hc/--hl/--hw/--hh` | скрыть по коду/строкам/словам/размеру |
| `--sc/--sl/--sw/--sh` | показать только эти значения |
| `--ss/--hs REGEX` | показать/скрыть по regex |
| `--filter 'c=200,l<8'` | выражение фильтрации |
| `-t N` / `-s N` | потоки / задержка |
| `-o json -f out.json` | JSON-вывод |
| `-e payloads\|encoders\|iterators` | список возможностей |

**Burp Intruder:** Sniper (по одной позиции) · Battering ram (одно значение везде) · Pitchfork (пары параллельно) · Cluster bomb (все комбинации). Плюс Grep-Match/Extract и payload processing.

## Что мы теперь знаем

- `wfuzz` подставляет payload в несколько позиций (`FUZZ`, `FUZ2Z`) из разных `-z`-источников.
- Iterator `product` = все комбинации, `zip` = параллельные пары.
- Encoder — третий параметр `-z` (base64, urlencode и др.).
- Фильтры wfuzz (`--hc`, `--ss`, `--filter`) решают проблему шума.
- Intruder — те же идеи в GUI: четыре типа атак + обработка payload.

## На что смотреть дальше

- **Онлайн-брутфорс — EV-минус.** Малый словарь: дефолты и топ-100, не `rockyou`.
- **CSRF-токен ломает Intruder.** Используй Grep-Extract или макросы сессии.
- **`--dry-run` в wfuzz.** Показывает, какие запросы уйдут, до массовой отправки.
- **Intruder → ffuf.** Сложный запрос удобнее разметить в Burp, потом «Copy as curl» и гонять в CLI.
- **Скорость.** Для простых задач ffuf быстрее; wfuzz/Intruder — для хитрых payload.

## Квиз

Проверь себя.

```quiz
- question: "Какой тип атаки Burp Intruder использует все комбинации нескольких payload-sets?"
  options:
    - "Sniper"
    - "Battering ram"
    - "Pitchfork"
    - "Cluster bomb"
  answer: 3
  explanation: "Cluster bomb перебирает декартово произведение всех наборов."
- question: "Чем iterator zip отличается от product в wfuzz?"
  options:
    - "Ничем"
    - "zip идёт параллельно по одной строке из каждого набора, product — все комбинации"
    - "product быстрее"
    - "zip работает только с одним словарём"
  answer: 1
  explanation: "zip — пары (1-я с 1-й), product — декартово произведение."
- question: "Где в wfuzz задаётся кодирование payload?"
  options:
    - "Флагом --hc"
    - "Третьим параметром -z (например, base64)"
    - "Флагом -t"
    - "В теле запроса"
  answer: 1
  explanation: "-z file,list,base64 применяет encoder к каждому значению."
- question: "Что делает фильтр --hc 200 в wfuzz?"
  options:
    - "Показывает только 200"
    - "Скрывает ответы с кодом 200"
    - "Ускоряет скан"
    - "Меняет метод"
  answer: 1
  explanation: "hc = hide code: прячет ответы с этим кодом, чтобы видеть отклонения."
- question: "Почему Burp Intruder может провалить форму с CSRF-токеном?"
  options:
    - "Intruder не умеет POST"
    - "Токен одноразовый — его надо извлекать (Grep-Extract) и подставлять"
    - "Токен шифрует ответ"
    - "Intruder игнорирует cookie"
  answer: 1
  explanation: "Без извлечения и подстановки свежего токена запросы отклоняются."
```

## Куда дальше

Дальше (`web-tools-offense`) мы соберём наступательный арсенал: Burp/ZAP, `jwt_tool`, `ysoserial`/`phpggc` и инструменты инъекций. А пока главное запомни: когда позиций несколько или нужен encoder — бери `wfuzz` (CLI) или Burp Intruder (GUI), а простые задачи оставляй `ffuf`.

## Где пригодится

- **CTF (Web):** перебор пар логин:пароль и закодированных payload.
- **Bug bounty:** обход фильтров через encoders; массовая проверка параметров.
- **Пентест:** аккуратный контролируемый перебор с фильтрацией шума.
- **Работа (AppSec):** проверка устойчивости логина к перебору и кодированию.
