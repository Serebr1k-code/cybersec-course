---
id: web-xss-bypass-advanced
title: "XSS: обход защит и продвинутые векторы"
category: web
parent: web-xss
difficulty: easy
order: 2
tags: [csp, mutation, prototype, roadmap]
prerequisites: [web-xss]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 8
summary: "Продвинутый уровень XSS: обход CSP, prototype pollution, mXSS и CSTI."
---

Когда разметка и DOM понятны, начинается борьба с защитами: CSP, санитайзерами и клиентскими шаблонизаторами.

## Что покрывает эта ступень

Ступень объединяет `web-csp-bypass` (обход Content-Security-Policy), `web-prototype-pollution` (prototype pollution), `web-mxss` (mutation XSS) и `web-client-side-template-injection` (CSTI).

## Почему такой порядок

Все четыре темы — про обход защит и «нестандартные» векторы исполнения скрипта. Это вершина XSS-ветви.

## Что вы будете уметь

Вы умеете обходить CSP, эксплуатировать prototype pollution до XSS, находить mXSS в санитайзерах и CSTI в клиентских шаблонах.

## Как проходить ступень

Начните с CSP bypass, затем prototype pollution, затем mXSS и CSTI.

## Квиз

```quiz
- question: "Чему посвящена продвинутая ступень XSS?"
  options:
    - "Обходу CSP и продвинутым векторам (pollution, mXSS, CSTI)"
    - "Только открытым редиректам"
    - "Только SQLi"
    - "Только десериализации"
  answer: 0
  explanation: "Ступень про обход защит и нестандартные векторы исполнения."
- question: "Что такое mXSS?"
  options:
    - "XSS, возникающий при повторном парсинге после санитайзера"
    - "XSS только в мобильных браузерах"
    - "XSS через SMTP"
    - "XSS без JavaScript"
  answer: 0
  explanation: "Mutation XSS появляется из-за расхождения парсинга санитайзера и браузера."
- question: "Как prototype pollution может привести к XSS?"
  options:
    - "Через изменение свойств, влияющих на клиентскую логику"
    - "Напрямую выполняя shell"
    - "Через переполнение буфера"
    - "Через TLS-ошибку"
  answer: 0
  explanation: "Загрязнение прототипа меняет поведение клиентского кода вплоть до XSS."
```

## Где пригодится

- **CTF:** закрепление темы в задачах категории Web.
- **Bug bounty:** приоритизация находок и построение отчётов.
- **Пентест:** планирование этапов тестирования веб-приложения.
- **Работа:** понимание, какие классы багов критичны для защиты продукта.
