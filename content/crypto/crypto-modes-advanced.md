---
id: crypto-modes-advanced
title: 'Продвинутые режимы: SIV, tweakable и Feistel'
category: crypto
parent: crypto-modern-modes
difficulty: hard
order: 5
tags: [crypto, modes, siv, gcm-siv, ocb, xts, adiantum, feistel]
prerequisites: [crypto-modern-modes]
useful_for:
  - 'CTF Crypto: нестандартные режимы'
  - 'Понимать nonce-misuse-resistant шифрование'
estimated_minutes: 12
summary: 'Продвинутые режимы: nonce-misuse-resistant (SIV, GCM-SIV), OCB/EAX, tweakable-шифры (XTS, Adiantum, Threefish) и обобщённые сети Фейстеля (unbalanced, Luby-Rackoff, тип-1/2/3).'
---

Этот модуль продолжает тему режимов. В `crypto-modern-modes` были CBC, CTR, GCM. Здесь — режимы, которые решают конкретные проблемы: устойчивость к повтору nonce (SIV), шифрование дисков (XTS, Adiantum) и теоретические конструкции (Feistel, Luby-Rackoff).

## Что покрывает модуль

- **crypto-block-cipher-modes-siv** — SIV и GCM-SIV: что делать, если nonce повторился. SIV делает шифрование **детерминированным по содержимому**, поэтому повтор nonce не катастрофа.
- **crypto-tweakable-deep** — tweakable-шифры: XEX, XTS (диски), Adiantum (ChaCha+NH), Threefish (Skein). Tweak — это «ключ для позиции», не требующий повторного расписания.
- **crypto-feistel-advanced** — сети Фейстеля вглубь: unbalanced, тип-1/2/3, конструкция Luby-Rackoff (3-4 раунда дают псевдослучайную перестановку).

## Почему такой порядок

SIV идёт первым: он показывает, как «защититься от ошибки использования». Затем tweakable-шифры — практический инструмент для дисков, где важно шифровать блок по номеру сектора. И в конце — теория сетей Фейстеля, объясняющая, почему 3-4 раунда достаточно и как строить шифр из хэш-функции (Luby-Rackoff).

## Что вы сможете после модуля

- Реализовать AES-XTS и понимать, зачем два ключа.
- Объяснить, почему SIV устойчив к повтору nonce.
- Строить псевдослучайную перестановку из round-функции (Feistel).
- Понимать ограничения режимов и выбирать подходящий.

## Квиз

```quiz
- question: "В чём главное преимущество SIV-режима?"
  options:
    - "Он быстрее GCM"
    - "Он устойчив к повтору nonce (nonce-misuse-resistant)"
    - "Он не требует ключа"
    - "Он использует XOR"
  answer: 1
- question: "Зачем в XTS два ключа?"
  options:
    - "Для удвоения стойкости ключа"
    - "Один для данных, второй для генерации tweak по номеру сектора"
    - "Для резервного копирования"
    - "Для хэширования"
  answer: 1
- question: "Сколько раундов Luby-Rackoff достаточно для псевдослучайной перестановки?"
  options:
    - "1"
    - "3 (4 для сильной)"
    - "16"
    - "32"
  answer: 1
```

## Где пригодится

- **CTF Crypto:** режимы и их слабости.
- **Дисковое шифрование:** LUKS/BitLocker используют XTS.
- **Протоколы:** выбор режима под угрозы.
- **Обучение:** теория конструкций из примитивов.
