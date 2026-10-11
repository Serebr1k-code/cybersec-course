---
id: web-ssrf-advanced
title: "SSRF: протоколы, DNS и serverless"
category: web
parent: web-ssrf
difficulty: easy
order: 2
tags: [ssrf, gopher, dns, serverless, roadmap]
prerequisites: [web-ssrf]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 8
summary: "Продвинутый уровень SSRF: контрабанда протоколов (gopher/dict), DNS rebinding и serverless."
---

Вершина ветви — SSRF, который выходит за пределы HTTP: внутренние сервисы, DNS и serverless-окружения.

## Что покрывает эта ступень

Ступень объединяет `web-ssrf-protocol-smuggling` (gopher/dict и контрабанда в Redis/внутренние сервисы), `web-dns-rebinding` (обход проверок через перепривязку DNS) и `web-serverless` (специфика SSRF в serverless).

## Почему такой порядок

Эти техники расширяют SSRF за пределы HTTP и обходят allow-list проверки. Требуют понимания сетей и внутренних протоколов.

## Что вы будете уметь

Вы умеете использовать gopher/dict для атаки внутренних сервисов, обходить allow-list через DNS rebinding и учитывать специфику serverless.

## Как проходить ступень

Начните с protocol smuggling (gopher в Redis даёт RCE), затем DNS rebinding, затем serverless.

## Квиз

```quiz
- question: "Чем занимается продвинутый уровень SSRF?"
  options:
    - "Не-HTTP протоколами, DNS rebinding и serverless"
    - "Только XSS"
    - "Только CSRF"
    - "Только SQLi"
  answer: 0
  explanation: "Ступень расширяет SSRF за пределы обычного HTTP-запроса."
- question: "Зачем в SSRF использовать gopher?"
  options:
    - "Он позволяет слать произвольные байты во внутренние сервисы"
    - "Он ускоряет запросы"
    - "Он шифрует трафик"
    - "Он скрывает IP"
  answer: 0
  explanation: "gopher:// передаёт сырые TCP-данные, что даёт доступ к Redis/Memcached и др."
- question: "Что делает DNS rebinding?"
  options:
    - "Меняет IP за доменом после проверки, обходя allow-list"
    - "Шифрует DNS-запросы"
    - "Отключает DNSSEC"
    - "Ускоряет разрешение имён"
  answer: 0
  explanation: "DNS rebinding возвращает проверенный IP при валидации и внутренний IP при запросе."
```

## Где пригодится

- **CTF:** закрепление темы в задачах категории Web.
- **Bug bounty:** приоритизация находок и построение отчётов.
- **Пентест:** планирование этапов тестирования веб-приложения.
- **Работа:** понимание, какие классы багов критичны для защиты продукта.
