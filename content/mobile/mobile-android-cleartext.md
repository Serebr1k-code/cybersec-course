---
id: mobile-android-cleartext
title: 'cleartextTraffic и сетевые флаги Android'
category: mobile
parent: mobile-android-transport
difficulty: easy
order: 4
tags: [android, cleartext, network-security-config, http, flags]
prerequisites: [mobile-network-security-config]
useful_for:
  - 'Пентест мобильных приложений'
  - 'Bug report Android'
  - 'CTF Mobile'
estimated_minutes: 38
summary: 'Что реально означает cleartextTrafficPermitted, где он остаётся включённым и как доказать утечку открытого трафика.'
lab:
  kind: shell
  title: 'Практика: найди cleartext-адрес'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, strings.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`strings.txt` — строки из APK.'
    - 'Ищи базовый URL без шифрования.'
    - 'Рядом с ним — флаг `nto{...}`.'
---

## Вопрос, с которого всё начинается

Приложение шлёт данные на сервер по `http://` — без шифрования. В декомпилированном манифесте
стоит `android:usesCleartextTraffic="true"`, а в Network Security Config — домены-исключения. Почему
это опасно и как это доказать, разберём на конкретном приложении.

## Наш пример: http в коде

Ищем адреса серверов в декомпилированном коде:

```bash
$ grep -rn 'http://' out/sources | grep -v 'schemas.android' | head
out/sources/com/example/bank/Api.java:14: String BASE = "http://api.example.com/v1";
```

`BASE` начинается с `http://` — открытый текст. Любой, кто в той же сети (кафе, отель, оператор),
может прочитать запросы и ответы.

## Шаг 1: что такое cleartext

**Cleartext** — данные, идущие без шифрования, то есть HTTP, а не HTTPS. Начиная с Android 9 (API
28) открытый текст по умолчанию запрещён: приложение, которое хочет `http://`, должно явно
разрешить это флагом или конфигом. Разрешение — сигнал, что разработчик сознательно оставил дыру
(или не заметил).

## Шаг 2: где включается разрешение

Три места:

```xml
<!-- AndroidManifest.xml -->
<application android:usesCleartextTraffic="true"/>
```

```xml
<!-- res/xml/network_security_config.xml -->
<base-config cleartextTrafficPermitted="true"/>
```

Либо точечно — для конкретных доменов:

```xml
<domain-config cleartextTrafficPermitted="true">
  <domain includeSubdomains="true">legacy.example.com</domain>
</domain-config>
```

Последний вариант часто оставляют для «старого» сервера, забывая, что туда уходят токены.

## Шаг 3: как доказать утечку

Достаточно встать между приложением и сервером. В тестовой сети — `tcpdump` и фильтр по порту 80:

```bash
$ tcpdump -i any -A 'tcp port 80' | grep -i 'authorization\|password'
Authorization: Bearer eyJhbGciOi...
```

Если видите токен или пароль в открытом виде — уязвимость доказана. Это не теория: такие находки
регулярно закрывают как high.

## Шаг 4: почему это не только про конфиденциальность

Открытый текст можно не только читать, но и **менять**: подставить свой ответ, изменить сумму
перевода, вернуть чужой баланс. Атака «человек посередине» без всякого сертификата. Поэтому
cleartext — это и целостность тоже.

## Шаг 5: как чинить

- Всегда `https://`, никаких исключений.
- Убрать `usesCleartextTraffic` и `cleartextTrafficPermitted`.
- Включить HSTS на сервере.
- Проверять сертификаты (см. ветку `mobile-ssl-pinning`).

## Шаг 6: чек-лист аудита

- Грепнуть `http://` по декомпилированному коду.
- Посмотреть `usesCleartextTraffic` и `network_security_config.xml`.
- Прогнать трафик и поискать токены/пароли в открытом виде.
- Проверить, есть ли domain-config-исключения.

## Что мы теперь знаем

- Cleartext — трафик без шифрования (HTTP).
- С Android 9 он запрещён по умолчанию, но включается флагом или конфигом.
- Открытый текст можно читать и подменять.
- Доказательство — токен/пароль, видимый в дампе.
- Лечение — только HTTPS и удаление исключений.

## Квиз

Проверь себя.

```quiz
- question: Что означает cleartext?
  options:
    - Данные без шифрования
    - Сжатые данные
    - Кэш
    - Бинарный формат
  answer: 0
  explanation: Cleartext — открытый, нешифрованный трафик.
- question: С какой версии Android cleartext запрещён по умолчанию?
  options:
    - Android 4
    - Android 6
    - Android 9
    - Android 13
  answer: 2
  explanation: С API 28 (Android 9) открытый текст запрещён по умолчанию.
- question: Как доказать утечку cleartext?
  options:
    - Показать токен/пароль в дампе трафика
    - Переустановить приложение
    - Сменить язык
    - Включить Wi-Fi
  answer: 0
  explanation: Видимый в открытом виде секрет — доказательство.
- question: Чем опасен cleartext кроме чтения?
  options:
    - Подменой ответов и запросов
    - Разрядом батареи
    - Медленным стартом
    - Потерей SIM
  answer: 0
  explanation: Открытый текст можно модифицировать по пути.
```

## Куда дальше

Мы закончили с транспортом. Дальше — работа с самим API: JWT, GraphQL, версионирование и обход
лимитов. А пока запомни: любой `http://` в приложении — это находка.

## Где пригодится

- Пентест мобильных приложений.
- Bug bounty Android.
- CTF Mobile.
