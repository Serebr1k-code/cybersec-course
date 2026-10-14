---
id: stego-tool-cyberchef
title: "CyberChef: рецепты, Magic и операции для стего"
category: stego
parent: stego-module-tools-ctf
difficulty: easy
order: 1
tags: [stego, cyberchef, magic, recipe, tooling, ctf]
prerequisites: [stego-tooling-advanced]
useful_for:
  - "CTF Stego: неизвестные кодирования"
  - "Форензика: декодирование вложений"
  - "Blue team: разбор обфускации"
estimated_minutes: 14
summary: "CyberChef как конвейер операций: рецепты, Magic, ключевые операции (From Base64, XOR, Gunzip, Extract LSB, Detect File Type) и воспроизведение рецепта на Python."
lab:
  kind: shell
  title: "Практика: base64 → XOR"
  toolset: [core, python3]
  workdir: /home/student/task
  files: [task.md, blob.txt, chef.py]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Строка похожа на base64 (есть `=` в конце)."
    - "После base64 остаётся XOR с однобайтовым ключом."
    - "`python3 chef.py` декодирует и печатает метку."
    - "`python3 chef.py | grep nto > found.txt`."
---

## Вопрос, с которого всё начинается
Ты получил файл `blob.txt`: длинная строка из букв, цифр и `=`. Похоже на base64,
но декодирование даёт мусор. Значит, поверх кодирования есть второй слой —
например, XOR. Вручную перебирать комбинации долго; CyberChef делает это
автоматически через операцию **Magic**.

## Наш пример
Возьмём `blob.txt`. Прогоним его через CyberChef-подобную цепочку: base64 →
XOR → текст, и получим метку.

## Шаг 1: что такое CyberChef
CyberChef — браузерный «швейцарский нож» для данных. Ты собираешь **рецепт** из
операций: `From Base64`, `XOR`, `Gunzip`, `Extract LSB`, `Detect File Type`,
`Strings` и сотен других. Каждая операция принимает вход и отдаёт выход; рецепт
применяется слева направо.

## Шаг 2: операция Magic
`Magic` перебирает десятки операций и их параметров, пытаясь превратить вход во
что-то осмысленное. Это быстрый способ «размотать» неизвестную цепочку. Magic
часто сам определяет base64 → gzip → текст.

## Шаг 3: ключевые операции для стего
- **From Base64 / To Base64** — кодирование.
- **XOR / XOR Brute Force** — перебор однобайтового ключа.
- **Gunzip / Zlib Inflate / Raw Inflate** — распаковка.
- **Extract LSB** — извлечение младших битов из изображения.
- **Detect File Type** — определение формата по магии.
- **Strings / Extract** — извлечение строк/подстрок по шаблону.
- **Rot13 / ROT47 / Atbash** — простые шифры.

## Шаг 4: ручной рецепт для нашего файла
Если Magic не сработал, строим цепочку вручную. Наш `blob.txt` — base64, после
декодирования — байты, XOR-нутые ключом `0x42`:

```python
import base64
raw = base64.b64decode(open('blob.txt','rb').read())
print(bytes(b ^ 0x42 for b in raw).decode())
```

Вывод:

```
nto{cyberchef_recipe_xor}
```

В CyberChef то же самое — рецепт `From Base64` → `XOR (0x42)`.

## Шаг 5: автоматизация и CLI
CyberChef — браузерный, но есть CLI-обёртки (`cyberchef-cli`, `node cyberchef`)
для пакетной обработки. Для CTF удобно держать набор готовых рецептов:
`base64→gunzip`, `xor-bruteforce→strings`, `extract-lsb→png`.

## Что мы теперь знаем
- CyberChef — конвейер операций над данными.
- Magic автоматически подбирает цепочку декодирования.
- Ключевые операции: base64, XOR, gunzip, Extract LSB, Detect File Type.
- Рецепт воспроизводим вручную на Python.

## Квиз

Проверь себя.

```quiz
- question: "Что такое рецепт в CyberChef?"
  options:
    - "Последовательность операций, применяемых к данным слева направо"
    - "Пароль"
    - "Тип файла"
    - "Ключ шифрования"
  answer: 0
  explanation: "Рецепт — конвейер операций."
- question: "Что делает операция Magic?"
  options:
    - "Перебирает операции и параметры, пытаясь декодировать вход"
    - "Удаляет файл"
    - "Шифрует данные"
    - "Рисует график"
  answer: 0
  explanation: "Magic — автоматический подбор цепочки."
- question: "Какая операция извлекает младшие биты изображения?"
  options:
    - "Extract LSB"
    - "From Base64"
    - "Gunzip"
    - "ROT13"
  answer: 0
  explanation: "Extract LSB достаёт битовые плоскости."
- question: "Чем полезна 'XOR Brute Force'?"
  options:
    - "Перебирает однобайтовый ключ XOR и показывает осмысленный результат"
    - "Сжимает данные"
    - "Кодирует в base64"
    - "Строит график"
  answer: 0
  explanation: "XOR Brute Force находит ключ по эвристике осмысленности."
```

## Куда дальше
CyberChef — про кодирования. Дальше — binwalk: поиск встроенных сигнатур и
распаковка «матрёшек». О нём — в следующем уроке.

## Где пригодится
- **CTF:** быстрый разбор неизвестных кодирований.
- **Форензика:** декодирование вложений.
- **Blue team:** анализ обфусцированных payload.
