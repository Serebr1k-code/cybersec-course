---
id: hardware-mod-trusted-compute
title: "Модуль: Доверенная загрузка и TEE"
category: hardware
parent: hardware-secure-boot
difficulty: medium
order: 3
tags: [hardware, secure-boot, trustzone, tee, enclave, secure-element, module, roadmap]
prerequisites: [hardware-secure-boot, hardware-tpm]
useful_for:
  - "Анализ защищённых устройств"
  - "Пентест мобильных и платёжных систем"
  - "CTF Hardware (сложные)"
estimated_minutes: 16
summary: "Подмодуль о доверенных средах исполнения: secure enclave/TrustZone, secure element и anti-rollback."
---

Когда производитель хочет, чтобы прошивку нельзя было подменить, он строит цепочку доверия: загрузчик проверяет подпись ядра, ядро — подпись файловой системы, а секреты живут в отдельной доверенной среде. Этот подмодуль — про то, где именно хранятся секреты и как устроены механизмы, которые их защищают: TEE/secure enclave, secure element и anti-rollback.

## Что покрывает подмодуль

1. **Secure enclave и TrustZone** (`hardware-secure-enclave`) — разделение мира ARM на Normal и Secure, SMC-вызовы, OP-TEE, Trusty, Apple SEP; как TEE изолирует ключи от обычной ОС.
2. **Anti-rollback и verified boot** (`hardware-firmware-rollback`) — почему нельзя откатиться на уязвимую прошивку, как работают счётчики версий и e-fuse, чем грозит откат.
3. **Secure element** (`hardware-secure-element`) — отдельный чип с защищённым хранилищем (ATECC, SE050, STSAFE), его роль в платёжных и IoT-устройствах, интерфейсы I2C/SPI и защита от извлечения ключа.

## Почему такой порядок

Secure enclave объясняет базовую модель изоляции, без которой не понять остальное. Anti-rollback логично идёт вторым: это первый рубеж, который вы встретите при попытке залить модифицированную или старую прошивку. Secure element завершает картину: это аппаратный «сейф» для ключей, и его взлом — отдельная дисциплина (side-channel, glitch, инвазивные атаки), к которой подводят предыдущие уроки.

## Как проходить

- Прочитайте уроки по порядку: каждый опирается на предыдущий.
- Для практики подойдут платы с TrustZone (Raspberry Pi 4 в 64-битном режиме, STM32MP1) и любой secure element вроде ATECC608.
- Разбирайте реальные схемы защиты: загрузка Android, iOS Secure Enclave, платёжный терминал.
- Отмечайте, где заканчивается «логическая» защита и начинается аппаратная: это граница, которую придётся переходить с инструментами side-channel.

## Чему вы научитесь

- Объяснять модель ARM TrustZone и находить границу Normal/Secure.
- Понимать, как anti-rollback и e-fuse блокируют откат прошивки.
- Работать с secure element по I2C/SPI и понимать пределы его защиты.
- Строить план атаки на устройство с доверенной загрузкой.

## Квиз

```quiz
- question: "На какие два мира делит процессор ARM TrustZone?"
  options:
    - "Normal и Secure"
    - "User и Kernel"
    - "Real и Protected"
  answer: 0
- question: "Зачем нужен anti-rollback?"
  options:
    - "Чтобы ускорить загрузку"
    - "Чтобы запретить откат на старую (уязвимую) прошивку"
    - "Чтобы сжимать образ"
  answer: 1
- question: "Что такое secure element?"
  options:
    - "Отдельный чип — защищённое хранилище ключей"
    - "Раздел флеш-памяти"
    - "Программный модуль ядра"
  answer: 0
```

## Где пригодится

- **Пентест:** анализ платёжных терминалов, смарт-карт, мобильных устройств.
- **CTF:** задачи на обход secure boot и извлечение ключей из TEE.
- **Работа:** проектирование устройств с доверенной загрузкой и их аудит.
- **Исследования:** поиск уязвимостей в TEE и secure element.
