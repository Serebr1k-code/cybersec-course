---
id: misc-web3-econ
title: 'Модуль: экономика Web3, MEV и Bitcoin'
category: misc
parent: misc-web3-advanced
difficulty: expert
order: 9
tags: [web3, mev, defi, bitcoin, script, ctf, roadmap]
prerequisites: [misc-flash-loan]
useful_for:
  - 'CTF Web3'
  - 'Bug bounty Web3'
  - 'Понимать MEV и Bitcoin'
estimated_minutes: 16
summary: 'Экономика и разведка в Web3: продвинутый MEV (sandwich/backrun/JIT), Bitcoin Script и Ordinals, методология Web3-CTF.'
---

Последний этап Web3-ветки — про то, где код встречается с рынком и с чужой цепочкой. Здесь баг — не обязательно ошибка в контракте: иногда это отсутствие защиты от чужой транзакции (MEV) или неверное чтение биткоин-скрипта.

## Что покрывает модуль

1. **Продвинутый MEV** — sandwich, backrun, JIT-ликвидность и их защита.
2. **Bitcoin Script** — стек-машина, SegWit, Taproot и Ordinals.
3. **Методология Web3-CTF** — разведка контракта, форк сети, написание эксплойта.

## Почему такой порядок

Сначала MEV — потому что это атаки без ошибок в коде жертвы. Потом Bitcoin — другая модель исполнения, где тоже есть свои баги. И в конце — общая методология, которая связывает всё воедино.

## Квиз

Проверь себя.

```quiz
- question: Что такое sandwich-атака?
  options:
    - Кража ключей
    - Обрамление чужой сделки своими buy/sell
    - Разрыв сети
    - Двойная трата
  answer: 1
  explanation: Атакующий извлекает прибыль из проскальзывания.
- question: Чем Bitcoin Script отличается от EVM?
  options:
    - Ничем
    - Стековая, не-Turing-полная машина
    - Он на Solidity
    - Он быстрее
  answer: 1
  explanation: Script намеренно ограничен.
- question: Где хранятся Ordinals-инскрипции?
  options:
    - В заголовке блока
    - В witness-данных транзакции
    - В mempool
    - В адресе
  answer: 1
  explanation: Данные кладут в witness.
```

## Куда дальше

Дальше — другие платформы (Cairo, Move, Cosmos, Solana) и низкоуровневый Solidity. А пока запомни: в Web3 атака не всегда требует бага в контракте.

## Где пригодится

- CTF Web3 экономических задач.
- Bug bounty Web3 и MEV-анализ.
- Blockchain-форензика Bitcoin.
