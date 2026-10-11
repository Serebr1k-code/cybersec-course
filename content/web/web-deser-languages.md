---
id: web-deser-languages
title: "Десериализация: по языкам"
category: web
parent: web-deserialization
difficulty: hard
order: 1
tags: [deserialization, python, node, ruby, php, roadmap]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 8
summary: "Средний уровень: десериализация в Python, Node.js, Ruby и PHP."
---

Десериализация опасна по-разному в каждом языке. Эта ступень — про четыре самых распространённых стека, кроме Java.

## Что покрывает эта ступень

Ступень объединяет `web-python-deser` (pickle и др.), `web-node-deser` (node-serialize и др.), `web-ruby-deser` (Marshal/YAML) и `web-php-deser-chains` (PHP Object Injection и цепочки).

## Почему такой порядок

Каждый язык имеет свои форматы и gadget-цепочки. Изучать их вместе логично — это «языковой» уровень, после которого идёт экспертный (Java/ViewState).

## Что вы будете уметь

Вы умеете распознавать сериализованные блобы этих языков и строить рабочие gadget-цепочки для RCE.

## Как проходить ступень

Начните с Python (pickle) и PHP — самый частый веб-стек, затем Node и Ruby.

## Квиз

```quiz
- question: "Какие языки покрывает ступень?"
  options:
    - "Python, Node.js, Ruby и PHP"
    - "Только Java"
    - "Только Go"
    - "Только Rust"
  answer: 0
  explanation: "Ступень про четыре распространённых не-Java стека."
- question: "Как распознать Python pickle в запросе?"
  options:
    - "По base64/байтам, начинающимся с gASV/8004"
    - "По префиксу rO0AB"
    - "По тегу __VIEWSTATE"
    - "По строке O:4:"
  answer: 0
  explanation: "Pickle-блобы часто начинаются с gASV… (base64) или ."
- question: "Что такое PHP Object Injection?"
  options:
    - "Подстановка сериализованного PHP-объекта для вызова магических методов"
    - "Инъекция SQL через PHP"
    - "Переполнение стека в PHP"
    - "Шифрование сессии PHP"
  answer: 0
  explanation: "PHP Object Injection использует unserialize и magic-методы для gadget-цепочки."
```

## Где пригодится

- **CTF:** закрепление темы в задачах категории Web.
- **Bug bounty:** приоритизация находок и построение отчётов.
- **Пентест:** планирование этапов тестирования веб-приложения.
- **Работа:** понимание, какие классы багов критичны для защиты продукта.
