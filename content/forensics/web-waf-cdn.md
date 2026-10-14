---
id: web-waf-cdn
title: 'WAF и CDN: что видно в защите и кэше'
category: forensics
parent: forensics-web-infra
difficulty: medium
order: 2
tags: [forensics, web, waf, cdn, cloudflare, logs]
prerequisites: [forensics-web-forensics]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как использовать логи WAF и CDN в расследовании: блокировки, реальные IP за прокси и восстановление запросов из кэша.'
lab:
  kind: shell
  title: 'Практика: WAF и CDN'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Перед сайтом стоит **WAF/CDN** (Cloudflare/Akamai/AWS). Он не только защищает, но и
**логирует** всё: запросы, блокировки, реальные IP. Разберём.

## Наш пример: Cloudflare

## Шаг 1: логи WAF

WAF логирует решения: пропущено/заблокировано/челлендж.

```
$ grep BLOCK waf.log | head
203.0.113.5  GET /?id=1' OR '1'='1  BLOCK  SQLi
```

Здесь видно атаку (SQLi) и её источник.

## Шаг 2: реальный IP за прокси

CDN прячет настоящий IP клиента. В логах есть заголовки:

```
$ grep -i 'cf-connecting-ip\|x-forwarded-for' access.log | head
```

`CF-Connecting-IP` — настоящий адрес. Без него ты видишь только IP CDN.

## Шаг 3: кэш как источник

CDN кэширует ответы. В кэше могут остаться:

- версии страниц (в т.ч. удалённые);
- ответы API;
- статические файлы.

```
$ curl -s http://cdn/old-page | head
```

Проверь `Cache-Control`/`Age` — если страница из кэша, она «заморожена».

## Шаг 4: восстановление запросов

Логи WAF/CDN показывают полный URL и заголовки:

```
$ jq '.ClientRequestURI, .ClientIP' cdn_log.json | head
```

Это позволяет восстановить, что именно отправлял атакующий (payload).

## Шаг 5: что искать

- блокировки по типам атак (SQLi/XSS/RCE);
- реальные IP за прокси;
- запросы, прошедшие WAF (bypass);
- изменения конфигурации WAF;
- страницы из кэша.

## Что мы теперь знаем

- WAF/CDN логирует запросы и решения.
- Реальный IP — в `CF-Connecting-IP`/`X-Forwarded-For`.
- Кэш хранит версии страниц.
- Логи дают полный payload.
- Ищем блокировки, bypass, смену правил.

## Если не сработало

- Логи не экспортируются? Включи Logpush/журналирование.
- Нужны тела? Смотри логи бэкенда.
- Прокси без логов? Анализируй сеть.

## Квиз

Проверь себя.

```quiz
- question: Что делает WAF?
  options:
    - 'ускоряет'
    - 'фильтрует запросы и логирует решения'
    - 'шифрует диск'
    - 'сканирует порты'
  answer: 1
  explanation: 'WAF блокирует атаки и ведёт логи.'
- question: Где реальный IP клиента за CDN?
  options:
    - 'в имени'
    - 'в заголовке CF-Connecting-IP/X-Forwarded-For'
    - 'в cookie'
    - 'в обои'
  answer: 1
  explanation: 'Прокси-заголовки несут настоящий адрес клиента.'
- question: Чем полезен кэш CDN для форензики?
  options:
    - 'ничем'
    - 'хранит версии страниц, в т.ч. удалённые'
    - 'шифрует'
    - 'сеть'
  answer: 1
  explanation: 'Кэш может сохранить контент, убранный с сервера.'
- question: Что искать в логах WAF?
  options:
    - 'обои'
    - 'блокировки атак и прошедшие bypass запросы'
    - 'музыку'
    - 'шрифты'
  answer: 1
  explanation: 'Блокировки показывают атаки; пропуски — обход.'
```
