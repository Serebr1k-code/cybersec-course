---
id: misc-web3-evm-deep
title: 'Модуль: Solidity, байткод и proxy-паттерны'
category: misc
parent: misc-web3-internals-hub
difficulty: expert
order: 2
tags: [web3, evm, yul, proxy, erc, roadmap]
prerequisites: [misc-evm-internals]
useful_for:
  - 'CTF Web3'
  - 'Аудит Solidity'
  - 'Понимать upgradeable-контракты'
estimated_minutes: 16
summary: 'Низкоуровневый Solidity: Yul и байткод, upgradeable-прокси (UUPS/diamond), нестандарты ERC и их типичные баги.'
---

Ветка про Solidity уходит на уровень ниже: от «написал контракт» к тому, как он превращается в байткод и как его можно обновлять, не теряя состояние. Эти три урока — про места, где формально корректный код ломается из-за низкоуровневых деталей.

## Что покрывает модуль

1. **Yul и assembly** — память, storage, dirty bits и типичные ошибки ручной сборки.
2. **Upgradeable-прокси** — delegatecall, storage collision, UUPS и diamond.
3. **Нестандарты ERC** — fee-on-transfer, callback-хуки, permit и их следствия.

## Почему такой порядок

Сначала байткод — без него непонятно, почему прокси вообще работает. Потом прокси — самая частая причина критических инцидентов в DeFi. И затем ERC-тонкости: они ломают интеграции, а не сам контракт.

## Чему вы научитесь

- Читать Yul и находить незамаскированные dirty bits.
- Объяснять, как delegatecall разделяет storage и почему это опасно.
- Распознавать fee-on-transfer и reentrancy через callback.
- Писать эксплойт против незащищённого прокси.

## Квиз

Проверь себя.

```quiz
- question: Что делает delegatecall?
  options:
    - Копирует код
    - Исполняет чужой код в контексте вызывающего storage
    - Создаёт контракт
    - Переводит ETH
  answer: 1
  explanation: Код чужой, состояние своё.
- question: Что такое storage collision в прокси?
  options:
    - Ошибка компиляции
    - Совпадение слотов переменных прокси и реализации
    - Потеря газа
    - Ошибка сети
  answer: 1
  explanation: Слоты читаются в контексте прокси.
- question: Чем опасен fee-on-transfer токен для протокола?
  options:
    - Он медленный
    - Протокол получает меньше, чем ожидает
    - Он не ERC-20
    - Он не торгуется
  answer: 1
  explanation: Комиссия списывается при переводе.
```

## Куда дальше

Дальше — экономика: MEV, оракулы и Bitcoin Script. А пока запомни: в Web3 критические баги живут на уровне байткода и storage, а не в синтаксисе Solidity.

## Где пригодится

- Аудит Solidity с assembly и прокси.
- CTF Web3 низкоуровневых задач.
- Понимание upgradeable-протоколов.
