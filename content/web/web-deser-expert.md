---
id: web-deser-expert
title: "Десериализация: экспертные цепочки и ViewState"
category: web
parent: web-deserialization
difficulty: expert
order: 2
tags: [java, viewstate, gadget, deserialization, roadmap]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 8
summary: "Экспертный уровень: Java gadget-цепочки, .NET ViewState и трюки PHP."
---

Самые сложные и самые разрушительные цепочки — в Java и .NET. Здесь — про них и про продвинутые трюки PHP.

## Что покрывает эта ступень

Ступень объединяет `web-java-deser-chains` (ysoserial и Java gadget chains), `web-viewstate` (.NET ViewState) и `web-php-tricks` (продвинутые PHP-приёмы).

## Почему такой порядок

Это вершина ветви: длинные цепочки гаджетов, подпись ViewState и языковые особенности. Требует уверенного владения предыдущей ступенью.

## Что вы будете уметь

Вы умеете строить Java gadget-цепочки (ysoserial), атаковать ViewState и применять продвинутые PHP-приёмы десериализации.

## Как проходить ступень

Java-цепочки — ядро; затем ViewState (нужно понимать подпись), затем PHP-трюки.

## Квиз

```quiz
- question: "Какие технологии на экспертном уровне?"
  options:
    - "Java-цепочки, .NET ViewState и трюки PHP"
    - "Только Python pickle"
    - "Только Node.js"
    - "Только Ruby Marshal"
  answer: 0
  explanation: "Экспертный уровень — Java, .NET ViewState и продвинутый PHP."
- question: "Что нужно, чтобы атаковать ViewState?"
  options:
    - "Знать/подобрать ключ подписи или найти его отсутствие"
    - "Только браузер"
    - "Только DNS"
    - "Только cookie сессии"
  answer: 0
  explanation: "ViewState защищён MAC-подписью — нужен ключ либо его отсутствие/утечка."
- question: "Что генерирует ysoserial?"
  options:
    - "Сериализованные Java-полезные нагрузки для gadget-цепочек"
    - "Python-pickle блобы"
    - "PHP-сессии"
    - "TLS-сертификаты"
  answer: 0
  explanation: "ysoserial создаёт Java-сериализованные payload'ы для известных gadget-цепочек."
```

## Где пригодится

- **CTF:** закрепление темы в задачах категории Web.
- **Bug bounty:** приоритизация находок и построение отчётов.
- **Пентест:** планирование этапов тестирования веб-приложения.
- **Работа:** понимание, какие классы багов критичны для защиты продукта.
