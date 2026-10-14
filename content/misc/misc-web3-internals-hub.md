---
id: misc-web3-internals-hub
title: "Модуль: Внутренности EVM и ZK"
category: misc
parent: misc-web3-advanced
difficulty: medium
order: 1
tags: [misc, module, roadmap]
prerequisites: [misc-web3-advanced]
useful_for:
- CTF Web3.
- Аудит смарт-контрактов.
- Bug bounty в Web3.
estimated_minutes: 10
summary: "Opcodes/gas/storage evm, solidity-байткод и proxy-паттерны, атаки на zk-схемы"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Внутренности EVM и ZK»: opcodes/gas/storage EVM, Solidity-байткод и proxy-паттерны, атаки на ZK-схемы.

- **misc-evm-internals** — Внутренности EVM: opcodes, gas, storage layout.
- **misc-web3-evm-deep** — Модуль: Solidity, байткод и proxy-паттерны.
- **misc-zk-circuits** — ZK-схемы (Circom, Groth16): атаки на доказательства.

## Почему такой порядок

Чтобы атаковать контракты, нужно понимать, как EVM исполняет байткод.

## Что вы сможете после этапа

- Читать байткод EVM.
- Искать ошибки в ZK-схемах.

## Квиз

Проверь себя.

```quiz
- question: Что такое storage layout в EVM?
  options:
    - "Раскладка переменных по слотам"
    - "Формат JSON"
    - "Тип транзакции"
    - "Стандарт токена"
  answer: 0
  explanation: Переменные контракта лежат в слотах storage.
- question: Зачем нужен proxy-паттерн?
  options:
    - "Обновляемость логики контракта"
    - "Ускорение газа"
    - "Шифрование"
    - "Сжатие"
  answer: 0
  explanation: Proxy делегирует вызовы к реализации.
- question: Где чаще ошибаются ZK-схемы?
  options:
    - "В неполных ограничениях (under-constrained)"
    - "В DNS"
    - "В шрифтах"
    - "В TLS"
  answer: 0
  explanation: Слабые constraints позволяют подделать доказательство.
```

## Где пригодится

- CTF Web3.
- Аудит смарт-контрактов.
- Bug bounty в Web3.
