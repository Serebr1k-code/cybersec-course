---
id: misc-web3-ecosystem-hub
title: "Модуль: Экосистема Web3: экономика, платформы, Solana"
category: misc
parent: misc-web3-advanced
difficulty: medium
order: 3
tags: [misc, module, roadmap]
prerequisites: [misc-web3-advanced]
useful_for:
- CTF Web3.
- Аудит Solana-программ.
- Анализ MEV.
estimated_minutes: 10
summary: "Экономику web3 и mev, не-evm платформы и специфику solana/anchor"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «Экосистема Web3: экономика, платформы, Solana»: экономику Web3 и MEV, не-EVM платформы и специфику Solana/Anchor.

- **misc-web3-econ** — Модуль: экономика Web3, MEV и Bitcoin.
- **misc-web3-platforms** — Модуль: Web3-платформы за пределами EVM.
- **misc-solana-ctf** — Solana и Anchor: PDA, account confusion, CPI.

## Почему такой порядок

За пределами EVM живут другие модели исполнения; их изучают после базовых атак.

## Что вы сможете после этапа

- Понимать MEV и экономику протоколов.
- Разбирать Solana-специфику (PDA, CPI).

## Квиз

Проверь себя.

```quiz
- question: Что такое MEV?
  options:
    - "Прибыль от упорядочивания транзакций"
    - "Формат токена"
    - "Тип подписи"
    - "Стандарт кошелька"
  answer: 0
  explanation: MEV извлекают, влияя на порядок транзакций.
- question: Что такое PDA в Solana?
  options:
    - "Program-Derived Address"
    - "Тип токена"
    - "Формат JSON"
    - "Стандарт NFT"
  answer: 0
  explanation: PDA — адрес, выведенный программой без приватного ключа.
- question: Чем Solana отличается от EVM?
  options:
    - "Моделью аккаунтов и CPI вместо delegatecall"
    - "Языком разметки"
    - "Отсутствием транзакций"
    - "Использованием SQL"
  answer: 0
  explanation: Solana использует аккаунт-модель и cross-program invocation.
```

## Где пригодится

- CTF Web3.
- Аудит Solana-программ.
- Анализ MEV.
