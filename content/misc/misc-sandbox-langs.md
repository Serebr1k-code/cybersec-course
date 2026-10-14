---
id: misc-sandbox-langs
title: "Модуль: языковые песочницы"
category: misc
parent: misc-sandbox-runtimes-hub
difficulty: hard
order: 4
tags: [misc, sandbox, python, node, lua, ruby]
prerequisites: [misc-sandbox]
useful_for:
  - "CTF misc/infra"
  - "Bug bounty"
  - "Пентест"
estimated_minutes: 15
summary: "Первый этап побега из песочниц: Python, Node.js, Lua и Ruby."
---

Этот модуль — промежуточный этап ветки «Sandbox escape и изоляция». Он собирает несколько последовательных уроков в единый учебный шаг и объясняет, зачем и в каком порядке их проходить. Начните с первого урока и двигайтесь по списку.

## Что покрывает модуль

1. **Python sandbox escape: аудит-хуки и ctypes** (`misc-python-sandbox`) — Python sandbox escape: аудит-хуки и ctypes.
2. **Node.js sandbox escape: vm, require и конструктор** (`misc-nodejs-sandbox`) — Node.js sandbox escape: vm, require и конструктор.
3. **Lua sandbox escape: getfenv, debug и loadstring** (`misc-lua-sandbox`) — Lua sandbox escape: getfenv, debug и loadstring.
4. **Ruby sandbox escape и десериализация Marshal** (`misc-ruby-sandbox`) — Ruby sandbox escape и десериализация Marshal.

## Почему такой порядок

Разбираем языковые песочницы по популярности языка: Python, затем Node.js, Lua и Ruby. Общий приём — дотянуться до системных примитивов через уже загруженные объекты, поэтому уроки идут вместе.

## Чему вы научитесь

- обходить аудит-хуки Python через ctypes;
- выбираться из vm-контекста Node.js;
- использовать getfenv/debug в Lua;
- эксплуатировать Marshal-десериализацию в Ruby.

## Квиз

```quiz
- question: "Что чаще всего ограничивают в Python-песочнице?"
  options:
    - "Опасные встроенные функции и импорты"
    - "Скорость интерпретатора"
    - "Размер файла"
    - "Кодировку"
  answer: 0
  explanation: "Фильтруют open/exec/import."
- question: "Через что можно выйти из Node.js vm-контекста?"
  options:
    - "Через конструктор Function и require"
    - "Через favicon"
    - "Через AXFR"
    - "Через OCR"
  answer: 0
  explanation: "Конструктор даёт доступ к реальному scope."
- question: "Что эксплуатируют в Ruby-песочнице?"
  options:
    - "Десериализацию Marshal"
    - "Спектрограмму"
    - "QR-код"
    - "DNS-зону"
  answer: 0
  explanation: "Marshal.load может вызвать опасный код."
```

## Где пригодится

- **CTF:** задачи соответствующей категории, где нужен этот этап навыка.
- **Bug bounty:** разведка и эксплуатация в рамках легальной программы.
- **Пентест:** на этапах recon/enumeration/exploitation.
- **Работа:** в задачах SOC/IR и при оценке защищённости.
