---
id: web-xss-client-side
title: "XSS: клиентские поверхности и инъекции разметки"
category: web
parent: web-xss
difficulty: easy
order: 1
tags: [xss, dom, css, roadmap]
prerequisites: [web-xss]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 8
summary: "Клиентский уровень XSS-ветви: open redirect/CRLF, DOM clobbering, dangling markup и CSS-инъекции."
---

Ветвь XSS не ограничивается тегом script. Значительная часть атак живёт в разметке, DOM и стилях. Здесь — про клиентские поверхности.

## Что покрывает эта ступень

Ступень объединяет `web-open-redirect-crlf` (открытые редиректы и CRLF), `web-dom-clobbering` (DOM clobbering), `web-dangling-markup` (dangling markup) и `web-css-injection` (CSS-инъекции).

## Почему такой порядок

Эти техники не всегда дают alert(1), но позволяют красть данные, ломать логику DOM и утекать информацию. Изучать их вместе логично — это клиентский слой без обхода CSP.

## Что вы будете уметь

Вы умеете использовать открытые редиректы и CRLF, ломать DOM через clobbering, применять dangling markup и CSS-инъекции для утечек.

## Как проходить ступень

Начните с open redirect/CRLF (часто самостоятельный баг), затем dom clobbering, dangling markup и CSS.

## Квиз

```quiz
- question: "Что объединяет клиентский уровень XSS-ветви?"
  options:
    - "Инъекции в разметку, DOM и стили"
    - "Только серверные инъекции"
    - "Только шифрование"
    - "Только мобильные API"
  answer: 0
  explanation: "Ступень про клиентские поверхности: redirect/CRLF, DOM, разметка, CSS."
- question: "Что такое DOM clobbering?"
  options:
    - "Переопределение DOM-переменных HTML-элементами"
    - "Удаление всех обработчиков"
    - "Сжатие DOM"
    - "Шифрование localStorage"
  answer: 0
  explanation: "DOM clobbering подменяет глобальные переменные через id/name элементов."
- question: "Зачем нужен dangling markup?"
  options:
    - "Для утечки данных через незакрытую разметку"
    - "Для обхода TLS"
    - "Для чтения файлов сервера"
    - "Для подбора пароля"
  answer: 0
  explanation: "Dangling markup заставляет браузер утащить последующий контент в атрибут/URL."
```

## Где пригодится

- **CTF:** закрепление темы в задачах категории Web.
- **Bug bounty:** приоритизация находок и построение отчётов.
- **Пентест:** планирование этапов тестирования веб-приложения.
- **Работа:** понимание, какие классы багов критичны для защиты продукта.
