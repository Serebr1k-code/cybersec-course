---
id: misc-web3-defi-hub
title: "Модуль: DeFi-атаки: оракулы, flash loan, подписи"
category: misc
parent: misc-web3-advanced
difficulty: medium
order: 2
tags: [misc, module, roadmap]
prerequisites: [misc-web3-advanced]
useful_for:
- CTF Web3.
- Аудит DeFi-протоколов.
- Bug bounty.
estimated_minutes: 10
summary: "Манипуляции оракулами цен, flash loan и replay-атаки на подписи"
---

## Что покрывает этот этап

Этот модуль собирает уроки по теме «DeFi-атаки: оракулы, flash loan, подписи»: манипуляции оракулами цен, flash loan и replay-атаки на подписи.

- **misc-oracle-manipulation** — Оракулы цен и их атаки.
- **misc-flash-loan** — Flash loan и манипуляции оракулами.
- **misc-signature-replay** — Подписи, permit и replay в Web3.

## Почему такой порядок

Финансовая логика DeFi — главный источник потерь, поэтому разбираем её отдельным этапом.

## Что вы сможете после этапа

- Оценивать зависимость протокола от оракула.
- Искать replay и permit-злоупотребления.

## Квиз

Проверь себя.

```quiz
- question: Чем опасен спотовый оракул?
  options:
    - "Ценой можно манипулировать в одной транзакции"
    - "Он медленный"
    - "Он шифрует данные"
    - "Он хранит ключи"
  answer: 0
  explanation: Спот-цену можно сдвинуть flash loan'ом.
- question: Что даёт flash loan атакующему?
  options:
    - "Большой капитал без залога в одной транзакции"
    - "Постоянный доступ"
    - "Шифрование"
    - "Резервную копию"
  answer: 0
  explanation: Flash loan выдаёт средства и требует вернуть их в той же транзакции.
- question: Что такое replay подписи?
  options:
    - "Повторное использование валидной подписи"
    - "Восстановление приватного ключа"
    - "Смена сети"
    - "Сжатие данных"
  answer: 0
  explanation: Без nonce/chainId подпись можно переиспользовать.
```

## Где пригодится

- CTF Web3.
- Аудит DeFi-протоколов.
- Bug bounty.
