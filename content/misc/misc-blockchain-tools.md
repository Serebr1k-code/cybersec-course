---
id: misc-blockchain-tools
title: "Инструменты Web3-CTF: Foundry, cast, Etherscan"
category: misc
parent: misc-blockchain
difficulty: medium
order: 3
tags: [foundry, forge, anvil, cast, etherscan, rpc, ctf]
prerequisites: [misc-blockchain-solidity]
useful_for:
  - "CTF Blockchain категория"
  - "Аудит смарт-контрактов"
  - "Разбор транзакций"
estimated_minutes: 30
summary: "Окружение Foundry, forge/anvil/cast, форк mainnet, чтение байткода и storage, отладка транзакций и воспроизведение реальных эксплойтов."
---

Инструменты решают половину задачи в Web3-CTF. Foundry — де-факто стандарт: он позволяет за одну секунду развернуть локальную цепочку, форкнуть mainnet, написать тест-эксплойт и увидеть пошаговую трассировку. В этом уроке — полный рабочий цикл.

## Установка Foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup          # ставит forge, cast, anvil, chisel
forge --version
# forge 0.2.0 ...
```

Компоненты:

| Бинарь | Назначение |
|--------|-----------|
| `forge` | сборка, тесты, скрипты деплоя |
| `anvil` | локальная EVM-нода (RPC) |
| `cast` | RPC-вызовы, кодирование/декодирование, чтение storage |
| `chisel` | REPL для Solidity |

## Проект и первый тест

```bash
forge init myctf && cd myctf
ls
# lib  script  src  test  foundry.toml
```

Пишем тест-эксплойт:

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
    Target t;
    function setUp() public { t = new Target(); }
    function testExploit() public {
        vm.deal(address(this), 1 ether);
        t.deposit{value: 1 ether}();
        assertEq(address(t).balance, 1 ether);
    }
}
```

Запуск:

```bash
forge test -vvv
# [PASS] testExploit() (gas: 87001)
```

## anvil — локальная нода

```bash
anvil
# Listening on 127.0.0.1:8545
# Available Accounts
# (0) 0xf39F...2266 (10000.000000000000000000 ETH)
# Private Keys
# (0) 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

`anvil` печатает готовые аккаунты и приватные ключи — их можно сразу использовать в скриптах. Для форка реальной сети:

```bash
anvil --fork-url https://eth-mainnet.g.alchemy.com/v2/KEY
```

## cast — швейцарский нож

```bash
# баланс адреса
cast balance 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --rpc-url http://127.0.0.1:8545
# 1234567890000000000

# вызвать view-функцию по ABI
cast call 0xCONTRACT "balanceOf(address)(uint256)" 0xUSER --rpc-url http://127.0.0.1:8545

# прочитать слот 0
cast storage 0xCONTRACT 0 --rpc-url http://127.0.0.1:8545
# 0x0000000000000000000000000000000000000000000000000000000000000000

# отправить транзакцию
cast send 0xCONTRACT "withdraw()" --private-key $PK --rpc-url http://127.0.0.1:8545

# декодировать calldata
cast 4byte 0xa9059cbb
# transfer(address,uint256)

# получить байткод
cast code 0xCONTRACT --rpc-url ...
```

## Работа с байткодом и селекторами

Если исходников нет, начинают с селекторов:

```bash
cast code 0xTARGET --rpc-url $RPC > code.hex
# ищем PUSH4-константы (селекторы) глазами или через
python3 -c "import re;h=open('code.hex').read();print(set(re.findall(r'63([0-9a-f]{8})',h)))"
# {'a9059cbb','70a08231', ...}

cast 4byte 0x70a08231
# balanceOf(address)
```

Дальше — декомпиляторы (`heimdall`, `panoramix`) и реверс вручную.

## Отладка транзакций

`forge test -vvvv` печатает полную трассировку: вызовы, gas, возвраты, события. Пример:

```
[PASS] testReentrancy() (gas: 210000)
Traces:
  [210000] ExploitTest::testReentrancy()
    ├─ [12345] VulnerableBank::deposit{value: 1 ether}()
    ├─ [45678] VulnerableBank::withdraw()
    │   └─ [3210] Attacker::receive{value: 1 ether}()
    │       └─ [2000] VulnerableBank::withdraw()
    └─ [100] Attacker::drain()
```

Для реальной транзакции используют `cast run <txhash> --rpc-url ...` — воспроизводит её локально и печатает трассировку. Это ключевой приём при разборе чужих эксплойтов.

## Разбор эксплойта с Etherscan

Workflow для реального инцидента:

1. Найти адрес атакованного контракта и транзакцию атаки на Etherscan.
2. Скопировать хэш, выполнить `cast run <hash> --rpc-url $ARCHIVE`.
3. Прочитать исходники контракта (вкладка Contract) или декомпилировать.
4. Найти в трассировке точку, где баланс утекает.
5. Воспроизвести в Foundry: форк на блок **до** атаки, затем свой эксплойт.

Форк на конкретный блок:

```bash
forge test --fork-url $RPC --fork-block-number 17000000
```

## Частые ошибки и подводные камни

- Забыть `vm.deal` — у тестового адреса нет эфира.
- Использовать `--fork-block-number` **после** атаки — эксплойт «не сработает», потому что состояние уже изменено.
- Питаться публичным RPC без архивных данных — `cast run` не сработает.
- Путать `cast call` (view, без транзакции) и `cast send` (изменяет состояние).
- Забывать про ABI-кодирование: без правильной подписи `cast call` вернёт мусор.

## Что дальше / решение

Возьмите любую публичную CTF-задачу с контрактом, разверните через `anvil`, напишите `forge test` с PoC. Затем пройдите Ethernaut полностью локально (репозиторий `Ethernaut` + Foundry). Далее — `misc-blockchain-mev` о рыночных векторах и `misc-blockchain-reentrancy` для глубокого разбора.

## Справочная таблица команд

| Задача | Команда |
|--------|---------|
| Запустить ноду | `anvil --fork-url $RPC` |
| Баланс | `cast balance ADDR` |
| Вызвать view | `cast call ADDR "sig()(ret)" args` |
| Транзакция | `cast send ADDR "sig()" --private-key $PK` |
| Читать слот | `cast storage ADDR SLOT` |
| Селектор | `cast 4byte 0xdeadbeef` |
| Воспроизвести tx | `cast run TXHASH` |
| Тесты | `forge test -vvvv` |

## Дополнительная теория: ABI, селекторы и хранилище

Вызов функции в EVM кодируется по **ABI**: первые 4 байта calldata — селектор (`keccak256("func(uint256)")[:4]`), далее аргументы, выровненные по 32 байта. Понимание ABI позволяет вызывать функции вручную и читать calldata чужой транзакции. `cast sig "transfer(address,uint256)"` даёт селектор, `cast calldata "transfer(address,uint256)" 0x.. 100` — готовый calldata. В задачах, где нет исходников, вы восстанавливаете интерфейс по селекторам в байткоде.

Storage EVM — массив 256-битных слотов. Простые переменные занимают слоты по порядку; `mapping` использует `keccak256(key . slot)` как адрес; динамические массивы — `keccak256(slot)` для данных. Понимание раскладки нужно, чтобы читать «private» переменные через `cast storage` или `eth_getStorageAt`. Solidity-компилятор может упаковывать несколько маленьких переменных в один слот — это тоже надо учитывать. `solc --storage-layout` печатает точную раскладку.

## Форки, архивные ноды и воспроизведение

Чтобы воспроизвести реальный эксплойт, нужен форк mainnet **на блоке до атаки**. Публичные RPC часто не дают архивных данных (историческое состояние), поэтому `cast run` может упасть с «missing trie node». Решения: использовать архивный RPC (Alchemy/Infura с архивом, QuickNode), указать `--fork-block-number`, либо взять дамп состояния через `anvil_dumpState`/`anvil_loadState`. Для CTF обычно достаточно форка на конкретный блок с `anvil --fork-url $RPC --fork-block-number N`.

`forge` также умеет `--fork-url` и `--fork-block-number` прямо в тестах, а `vm.createSelectFork(url, block)` — переключать форки внутри теста. Это позволяет воспроизводить сложные многошаговые атаки.

## Разбор ошибок и отладка

Если `forge test` не компилируется — проверьте версию Solidity (`pragma`) и remappings. Если тест «проходит», но баланс не меняется — вероятно, вы не дали контракту эфир (`vm.deal`) или не вызвали нужный метод. Если `cast call` возвращает мусор — неверная подпись функции или отсутствие ABI. Если `cast run` не находит транзакцию — не тот RPC (нужна нода, где транзакция доступна). Используйте `-vvvv` для трассировки: она показывает каждый вызов, возврат и событие — это лучший отладчик в Web3. И всегда проверяйте, на каком блоке вы форкаете: состояние меняется каждые 12 секунд.

## Частые вопросы

**Обязателен ли Foundry, или можно обойтись Hardhat/Truffle?** Нет, не обязателен. Foundry удобнее для CTF из-за скорости, `cast` и трассировок. Hardhat (JS) тоже подходит, особенно если задача на JS/TS. `cast` можно использовать отдельно — он просто CLI к RPC. Главное — уметь читать storage, вызывать функции и форкать сеть.

**Как получить RPC без платного ключа?** Публичные RPC (`https://eth.llamarpc.com`, `https://rpc.ankr.com/eth`) дают базовый доступ, но не всегда архивный. Для исторических блоков нужен архивный нод (Alchemy/Infura/QuickNode с архивом) или локальный `anvil` с уже загруженным состоянием. В CTF организаторы обычно дают RPC в описании.

**Что делать, если нет исходников контракта?** Начните с селекторов в байткоде (`cast code`, поиск `PUSH4`-констант), сопоставьте с `4byte.directory`. Затем декомпилируйте (`heimdall`, `panoramix`) и реверсьте. Часто достаточно найти одну функцию (например, `isSolved`) и понять, что она проверяет.

**Можно ли запускать всё без интернета?** Да: `anvil` работает локально, `forge` компилирует и тестирует офлайн. Форк mainnet требует сети, но для локальных задач (развёрнутые контракты) — не нужен.

## Практический разбор: от адреса к эксплойту

Дано: адрес контракта, исходников нет. Цикл:

```bash
# 1. байткод
cast code 0xTARGET --rpc-url $RPC > code.hex

# 2. селекторы (PUSH4 = 0x63)
python3 -c "import re;h=open('code.hex').read();print(set(re.findall(r'63([0-9a-f]{8})',h)))"
# {'a9059cbb','70a08231','d0e30db0',...}

# 3. сопоставляем
for s in a9059cbb 70a08231 d0e30db0; do cast 4byte $s; done
# transfer(address,uint256)
# balanceOf(address)
# deposit()

# 4. читаем storage (owner? implementation?)
for i in 0 1 2; do echo "slot $i:"; cast storage 0xTARGET $i --rpc-url $RPC; done

# 5. если owner в слоте 1 и есть delegatecall — подменяем реализацию
```

Найдя уязвимую функцию (например, публичный `init` или `delegatecall` по подменяемому адресу), пишем `forge`-тест на форке:

```bash
forge test --fork-url $RPC --fork-block-number N -vvvv
```

Трассировка покажет, где происходит запись в storage. Так реверс байткода + форк + трассировка складываются в готовый эксплойт без исходников.

## Квиз

```quiz
- question: "Какой бинарь Foundry поднимает локальную EVM-ноду?"
  options:
    - "anvil"
    - "forge"
    - "cast"
    - "chisel"
  answer: 0
  explanation: "anvil — локальный RPC-узел с готовыми аккаунтами."
- question: "Что делает `cast storage ADDR 0`?"
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
- question: "Чем `cast call` отличается от `cast send`?"
  options:
    - "call — read-only view, send изменяет состояние и тратит газ"
    - "call работает только с ERC-20"
    - "send не требует приватного ключа"
    - "Ничем"
  answer: 0
  explanation: "call не создаёт транзакцию; send создаёт."
```

## Где пригодится

- **CTF:** все Blockchain-задачи проходят через Foundry.
- **Аудит:** тесты инвариантов, форки mainnet.
- **Разбор инцидентов:** `cast run` воспроизводит реальные эксплойты.
- **Работа:** разработка и отладка контрактов, CI.
