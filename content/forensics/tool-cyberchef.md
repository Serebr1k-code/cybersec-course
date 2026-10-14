---
id: tool-cyberchef
title: 'CyberChef: швейцарский нож преобразований'
category: forensics
parent: forensics-tools-utility
difficulty: easy
order: 1
tags: [forensics, tools, cyberchef, encoding, decoding]
prerequisites: [forensics-tooling]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 40
summary: 'Как CyberChef помогает декодировать, расшифровывать и преобразовывать данные: операции, рецепты и типовые задачи.'
lab:
  kind: shell
  title: "Практика: рецепт CyberChef"
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, cyberchef_input.txt]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - "CyberChef — это Input → Operations → Output; первый операцией тут идёт From Base64."
    - "Декодировать без браузера: `base64 -d cyberchef_input.txt`."
    - "Сохрани результат в answer.txt: `base64 -d cyberchef_input.txt > answer.txt`."
---

## Вопрос, с которого всё начинается

Перед тобой строка `S2FsaSBpcyBoZXJl` или blob в base64 внутри base64. Декодировать
руками больно. **CyberChef** — браузерный конструктор преобразований: собираешь
«рецепт» из операций и применяешь. Разберём.

## Наш пример: закодированные данные

## Шаг 1: идея

CyberChef — это **Input → Operations → Output**. Ты добавляешь операции в «рецепт»:

- From Base64;
- From Hex;
- Gunzip;
- XOR;
- Decrypt AES.

## Шаг 2: типовой рецепт

Строка в base64, внутри gzip, внутри текст:

```
Input:  H4sIAAAA...
Ops:    From Base64 → Gunzip
Output: "secret message"
```

CyberChef показывает результат по шагам — видно, что происходит.

## Шаг 3: XOR-брут

Классика CTF — XOR одним байтом:

```
Op: XOR Brute Force (key 1..255)
```

CyberChef прогоняет все ключи и показывает читаемые результаты.

## Шаг 4: «Magic»

Кнопка **Magic** автоматически подбирает операции:

```
Magic → detected: Base64 → Gunzip → UTF-8
```

Иногда угадывает; иногда подсказывает направление.

## Шаг 5: практика

- декодирование CTF-строк;
- расшифровка простых шифров;
- разбор вредоносных скриптов;
- работа с protobuf/JSON;
- извлечение из бинарных данных.

## Что мы теперь знаем

- CyberChef собирает рецепты из операций.
- Работает по шагам, показывает промежуточный результат.
- XOR Brute Force и Magic ускоряют разбор.
- Идеален для CTF и разбора скриптов.

## Если не сработало

- Слишком сложно для Magic? Разбирай по шагам вручную.
- Нужна криптография? Используй операции Decrypt.
- Данные большие? Ограничь объём/используй скрипт.

## Квиз

Проверь себя.

```quiz
- question: Что такое CyberChef?
  options:
    - 'антивирус'
    - 'конструктор преобразований данных'
    - 'сканер портов'
    - 'шифрование диска'
  answer: 1
  explanation: 'CyberChef собирает «рецепты» из операций над данными.'
- question: Что делает операция XOR Brute Force?
  options:
    - 'удаляет файлы'
    - 'прогоняет XOR по всем ключам и показывает читаемые результаты'
    - 'шифрует'
    - 'сканирует сеть'
  answer: 1
  explanation: 'Полезна для разбора XOR-обфускации.'
- question: Что делает кнопка Magic?
  options:
    - 'удаляет данные'
    - 'автоматически подбирает цепочку операций'
    - 'шифрует диск'
    - 'сканирует порты'
  answer: 1
  explanation: 'Magic пытается угадать операции декодирования.'
- question: Для чего чаще всего используют CyberChef?
  options:
    - 'для игр'
    - 'для декодирования и разбора данных (CTF/скрипты)'
    - 'для сети'
    - 'для памяти'
  answer: 1
  explanation: 'Инструмент для преобразований и декодирования.'
```
