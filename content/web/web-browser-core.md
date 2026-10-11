---
id: web-browser-core
title: "Браузер: модель безопасности и клиентские поверхности"
category: web
parent: web-same-origin-cors
difficulty: medium
order: 1
tags: [browser, cors, jsonp, postmessage, roadmap]
prerequisites: [web-same-origin-cors]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 8
summary: "Базовый уровень браузерной безопасности: модель безопасности, JSONP/XSSI, CORS и postMessage."
---

Браузер — это среда исполнения со своей моделью безопасности. Эта ступень — про её основы и типовые ошибки конфигурации.

## Что покрывает эта ступень

Ступень объединяет `web-browser-security` (модель безопасности браузера), `web-jsonp-xssi` (JSONP и XSSI), `web-cors-deep` (CORS) и `web-postmessage-tabnabbing` (postMessage и tabnabbing).

## Почему такой порядок

Все четыре темы — про доверие между источниками (origin) и про то, как это доверие настраивают неправильно. Это фундамент ветви.

## Что вы будете уметь

Вы умеете оценивать same-origin policy, находить ошибки CORS, утечки через JSONP/XSSI и небезопасный postMessage.

## Как проходить ступень

Начните с модели безопасности браузера, затем CORS (самая частая ошибка), затем JSONP/XSSI и postMessage.

## Квиз

```quiz
- question: "Что объединяет базовый уровень браузерной ветви?"
  options:
    - "Модель безопасности, JSONP/XSSI, CORS и postMessage"
    - "Только SQLi"
    - "Только SSTI"
    - "Только десериализация"
  answer: 0
  explanation: "Ступень про same-origin policy и доверие между источниками."
- question: "Что такое same-origin policy?"
  options:
    - "Ограничение доступа скриптов к другому origin"
    - "Правило кэширования"
    - "Алгоритм шифрования"
    - "Формат cookie"
  answer: 0
  explanation: "SOP запрещает странице читать данные другого origin без разрешения."
- question: "Чем опасна ошибка в CORS-конфигурации?"
  options:
    - "Любой сайт сможет читать ответы API"
    - "Сервер перестанет отвечать"
    - "Потеряются cookie"
    - "Отключится HTTPS"
  answer: 0
  explanation: "Слабая CORS-политика (например, отражение Origin с credentials) открывает чтение данных API."
```

## Где пригодится

- **CTF:** закрепление темы в задачах категории Web.
- **Bug bounty:** приоритизация находок и построение отчётов.
- **Пентест:** планирование этапов тестирования веб-приложения.
- **Работа:** понимание, какие классы багов критичны для защиты продукта.
