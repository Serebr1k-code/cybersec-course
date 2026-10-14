---
id: crypto-rng-engineering
title: 'Инженерия случайности: PRNG, DRBG, энтропия'
category: crypto
parent: crypto-prng
difficulty: hard
order: 5
tags: [crypto, prng, drbg, entropy, rng, urandom, roca, debian]
prerequisites: [crypto-prng]
useful_for:
  - 'CTF Crypto: предсказание PRNG'
  - 'Аудит генерации ключей'
estimated_minutes: 12
summary: 'Инженерия случайности: неcryptographic PRNG (glibc rand, xorshift, PCG, splitmix) и восстановление их состояния; DRBG (CTR/Hash/Dual_EC) и бэкдоры; энтропия и источники (/dev/urandom, seed-recovery); аппаратные RNG; реальные катастрофы (Debian OpenSSL, Android SecureRandom, ROCA).'
---

Этот модуль — про **источник случайности**. Даже идеальный шифр бесполезен, если ключ сгенерирован предсказуемым PRNG. Именно так произошли крупнейшие крипто-катастрофы: Debian OpenSSL (2006-2008), Android SecureRandom (2013), ROCA (2017). Здесь ты научишься восстанавливать состояние генераторов и понимать, где рождается слабость.

## Что покрывает модуль

- **crypto-prng-glibc-xorshift** — неcryptographic PRNG: glibc `rand` (lagged Fibonacci), xorshift, PCG, splitmix. Все они **линейны** и предсказуемы по нескольким выходам.
- **crypto-drbg-backdoors** — DRBG (Deterministic Random Bit Generator): CTR-DRBG, Hash-DRBG и скандальный Dual_EC_DRBG с бэкдором NSA.
- **crypto-rng-entropy** — энтропия, `/dev/urandom`, `/dev/random`, seed-recovery: когда генератор засеян временем или PID.
- **crypto-hardware-rng** — аппаратные генераторы: RDSEED, TRNG, их отказы и атаки.
- **crypto-rng-cves** — реальные CVE: Debian OpenSSL, Android SecureRandom, ROCA, dual_ec.

## Почему такой порядок

Начинаем с простых PRNG: они предсказуемы, и это легко показать. Затем DRBG — «правильные» генераторы и их потенциальные бэкдоры. Потом энтропия: даже хороший PRNG бесполезен с плохим seed. И в конце — аппаратные RNG и реальные катастрофы, где всё это сломалось.

## Что вы сможете после модуля

- Восстанавливать состояние glibc `rand` и xorshift по выходам.
- Понимать устройство CTR-DRBG и почему Dual_EC_DRBG — бэкдор.
- Оценивать энтропию seed и атаковать время-зависимые ключи.
- Знать историю реальных RNG-катастроф.

## Квиз

```quiz
- question: "Почему неcryptographic PRNG (glibc rand) нельзя использовать для ключей?"
  options:
    - "Он медленный"
    - "Он линеен: по нескольким выходам восстанавливается состояние и предсказываются будущие значения"
    - "Он не работает на Linux"
    - "Он выдаёт 0"
  answer: 1
- question: "Что не так с Dual_EC_DRBG?"
  options:
    - "Он медленный"
    - "В нём заложен бэкдор: знание секрета к константе позволяет предсказывать выход"
    - "Он не использует эллиптические кривые"
    - "Он выдаёт мало битов"
  answer: 1
- question: "Чем опасен seed из времени или PID?"
  options:
    - "Ничем"
    - "Пространство seed мало, его можно перебрать и восстановить все ключи"
    - "Он слишком длинный"
    - "Он не воспроизводим"
  answer: 1
```

## Где пригодится

- **CTF Crypto** — предсказание PRNG и seed-recovery.
- **Аудит** — проверка генерации ключей и токенов.
- **Bug bounty** — слабая случайность в сессиях/токенах.
- **Работа** — правильное использование CSPRNG.
