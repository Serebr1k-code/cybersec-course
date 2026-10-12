---
id: misc-blockchain-tools
title: "Инструменты Web3-CTF: Foundry, cast, Etherscan"
category: misc
parent: misc-blockchain
difficulty: medium
order: 2
tags: [foundry, forge, anvil, cast, etherscan, rpc, ctf]
prerequisites: [misc-blockchain-solidity]
useful_for:
  - "CTF Blockchain категория"
  - "Аудит смарт-контрактов"
  - "Разбор транзакций"
estimated_minutes: 30
summary: "Окружение Foundry, forge/anvil/cast, форк mainnet, чтение байткода и storage, отладка транзакций и воспроизведение реальных эксплойтов."
---

## Вопрос, с которого всё начинается

У тебя есть адрес контракта и RPC, но исходников нет. Или есть готовый PoC, который надо проверить локально. Или нужно разобрать, как именно прошёл реальный эксплойт. В Web3-CTF половину задачи решают **инструменты**: поднять локальную цепочку, форкнуть mainnet, прочитать storage, написать тест-эксплойт. В этом уроке — полный рабочий цикл с Foundry.

## Наш пример: адрес контракта без исходников

Дано: `0xTARGET`, исходников нет. Задача — понять, что контракт делает, и найти уязвимость. Ставим Foundry (набор инструментов для разработки и тестирования контрактов):

```bash
$ curl -L https://foundry.paradigm.xyz | bash
$ foundryup
$ forge --version
forge 0.2.0
```

Компоненты, которые нам понадобятся:

| Бинарь | Назначение |
|--------|-----------|
| `forge` | сборка, тесты, скрипты деплоя |
| `anvil` | локальная EVM-нода (RPC) |
| `cast` | RPC-вызовы, чтение storage, кодирование |
| `chisel` | REPL для Solidity |

## Поднимаем ноду и форкаем mainnet

`anvil` — локальная нода. Она печатает готовые аккаунты с балансами и приватными ключами:

```bash
$ anvil
Listening on 127.0.0.1:8545
Available Accounts
(0) 0xf39F...2266 (10000.000000000000000000 ETH)
Private Keys
(0) 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

Чтобы работать с реальным контрактом, форкаем сеть на нужный блок:

```bash
$ anvil --fork-url $RPC --fork-block-number 17000000
```

`--fork-block-number` важен: для разбора эксплойта нужен блок **до** атаки, иначе состояние уже изменено и воспроизвести его не выйдет.

## cast: читаем состояние контракта

`cast` — CLI к блокчейну. Проверяем баланс и читаем слоты (про раскладку storage — в предыдущем уроке). Удобно, что `cast` работает и с локальной нодой `anvil`, и с публичным RPC — достаточно менять `--rpc-url`:

```bash
$ cast balance 0xTARGET --rpc-url http://127.0.0.1:8545
1234567890000000000
$ cast storage 0xTARGET 0 --rpc-url http://127.0.0.1:8545
0x0000000000000000000000000000000000000000000000000000000000000000
```

Вызываем view-функцию (только чтение, без транзакции) — `cast call`:

```bash
$ cast call 0xTARGET "balanceOf(address)(uint256)" 0xUSER --rpc-url $RPC
```

## Восстанавливаем интерфейс по селекторам

Исходников нет — начинаем с **селекторов**: первых 4 байт calldata, которыми кодируется имя функции. Достаём байткод и ищем в нём `PUSH4`-константы (опкод `0x63` — это `PUSH4`):

```bash
$ cast code 0xTARGET --rpc-url $RPC > code.hex
$ python3 -c "import re;h=open('code.hex').read();print(set(re.findall(r'63([0-9a-f]{8})',h)))"
{'a9059cbb', '70a08231', 'd0e30db0'}
$ cast 4byte 0xa9059cbb
transfer(address,uint256)
$ cast 4byte 0x70a08231
balanceOf(address)
```

`cast 4byte` ищет селектор в публичной базе `4byte.directory`. Так по байткоду восстанавливают список функций. Дальше — декомпиляторы (`heimdall`, `panoramix`) или ручной реверс.

## forge test: пишем PoC-эксплойт

Создаём проект и пишем тест:

```bash
$ forge init myctf && cd myctf
```

```solidity
// test/Exploit.t.sol
pragma solidity ^0.8.20;
import "forge-std/Test.sol";

contract Target {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 b = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: b}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}

contract ExploitTest is Test {
    function testExploit() public {
        vm.createSelectFork(vm.envString("RPC"), 17_000_000);
        vm.deal(address(this), 1 ether);      // даём себе эфир
        Target t = Target(0xTARGET);
        t.deposit{value: 1 ether}();
        assertEq(address(t).balance, 1 ether);
    }
}
```

Запускаем с максимальной трассировкой:

```bash
$ forge test -vvvv --match-test testExploit
[PASS] testExploit() (gas: 87001)
```

`-vvvv` печатает пошаговую трассировку: вызовы, газ, возвраты, события. Это лучший отладчик в Web3 — по нему видно, на каком шаге и куда утекает баланс. `vm.deal` не забудь: у тестового адреса по умолчанию нет эфира.

## Воспроизводим чужую транзакцию

Ключевой приём разбора реальных инцидентов — `cast run`: он проигрывает транзакцию локально и печатает трассировку.

```bash
$ cast run 0xTXHASH --rpc-url $ARCHIVE_RPC
```

Workflow: находим на Etherscan адрес атакованного контракта и хэш атаки → `cast run <hash>` → читаем исходники или декомпилируем → находим в трассировке точку утечки → форкаем на блок до атаки и пишем свой эксплойт. Важно: публичные RPC часто не дают **архивных** данных (историческое состояние), и `cast run` падает с «missing trie node». Для этого нужен архивный RPC (Alchemy/Infura/QuickNode) или локальный `anvil` с загруженным состоянием.

## Отладка: почему тест не срабатывает

Начинающих останавливают несколько типовых ошибок. Если `forge test` не компилируется — проверь `pragma` и remappings. Если тест «проходит», но баланс не меняется — вероятно, ты не дал контракту эфир (`vm.deal`) или не вызвал нужный метод. Если `cast call` возвращает мусор — неверная подпись функции или отсутствует ABI: без правильного кодирования ты получишь случайные байты. Если `cast run` не находит транзакцию — скорее всего, RPC не архивный (нужна нода, где историческое состояние доступно). И всегда проверяй, на каком блоке ты форкаешь: состояние меняется каждые ~12 секунд, и «до» или «после» атаки — принципиально. Для быстрых экспериментов с Solidity есть `chisel` — REPL, где можно вводить выражения и сразу видеть результат, не поднимая проект.

## Полный цикл: от адреса к эксплойту

Соберём весь путь в одну последовательность команд — именно так решается задача «дан адрес, исходников нет»:

```bash
# 1. вытащить байткод и найти селекторы
$ cast code 0xTARGET --rpc-url $RPC > code.hex
$ python3 -c "import re;h=open('code.hex').read();print(set(re.findall(r'63([0-9a-f]{8})',h)))"
# 2. сопоставить селекторы с сигнатурами
$ for s in a9059cbb 70a08231 d0e30db0; do cast 4byte $s; done
# 3. прочитать storage — ищем owner / implementation
$ for i in 0 1 2; do cast storage 0xTARGET $i --rpc-url $RPC; done
# 4. воспроизвести на форке и увидеть трассировку
$ forge test --fork-url $RPC --fork-block-number N -vvvv
```

Трассировка покажет, где именно происходит запись в storage — и если там есть подменяемый `delegatecall` или публичный `init`, ты уже знаешь, как строить эксплойт. Реверс байткода + форк + трассировка складываются в готовый PoC без исходников.

## Что мы теперь знаем

- Foundry: `forge` (тесты), `anvil` (нода), `cast` (RPC-запросы), `chisel` (REPL).
- `cast storage` читает слоты; `cast call` — view, `cast send` — транзакция.
- Интерфейс без исходников восстанавливают по **селекторам** (`cast code` + `cast 4byte`).
- `forge test -vvvv` даёт пошаговую трассировку эксплойта.
- `cast run TXHASH` воспроизводит чужую транзакцию; форкать надо на блок **до** атаки.
- Архивные RPC нужны для исторического состояния.

## Квиз

Проверь себя.

```quiz
- question: "Какой бинарь Foundry поднимает локальную EVM-ноду?"
  options:
    - "anvil"
    - "forge"
    - "cast"
    - "chisel"
  answer: 0
  explanation: "anvil — локальный RPC-узел с готовыми аккаунтами."
- question: "Что делает cast storage ADDR 0?"
  options:
    - "Читает слот 0 storage контракта"
    - "Очищает storage"
    - "Отправляет транзакцию"
    - "Компилирует контракт"
  answer: 0
  explanation: "Это прямой доступ к 256-битному слоту."
- question: "Как воспроизвести чужую транзакцию локально?"
  options:
    - "cast run TXHASH --rpc-url ..."
    - "forge build"
    - "anvil --version"
    - "cast 4byte 0x..."
  answer: 0
  explanation: "cast run проигрывает транзакцию и печатает трассировку."
- question: "Почему форкать mainnet для разбора эксплойта нужно на блок ДО атаки?"
  options:
    - "После атаки состояние уже изменено, эксплойт не воспроизведётся"
    - "Иначе не хватит газа"
    - "Иначе anvil не запустится"
    - "Это не имеет значения"
  answer: 0
  explanation: "Нужно исходное состояние уязвимого контракта."
- question: "Чем cast call отличается от cast send?"
  options:
    - "call — read-only view, send изменяет состояние и тратит газ"
    - "call работает только с ERC-20"
    - "send не требует приватного ключа"
    - "Ничем"
  answer: 0
  explanation: "call не создаёт транзакцию; send создаёт."
```

## Куда дальше

В следующем уроке `misc-blockchain-reentrancy` мы напишем полноценный атакующий контракт с повторным входом и прогоним его через `forge test -vvvv`. А пока главное: Foundry превращает разбор контракта в воспроизводимый тест — эксплойт, фикс и проверка фикса живут в одном файле. Возьми любую публичную CTF-задачу с контрактом и разверни её через `anvil`.

## Где пригодится

- **CTF:** все Blockchain-задачи проходят через Foundry.
- **Аудит:** тесты инвариантов, форки mainnet.
- **Разбор инцидентов:** `cast run` воспроизводит реальные эксплойты.
- **Работа:** разработка и отладка контрактов, CI.
