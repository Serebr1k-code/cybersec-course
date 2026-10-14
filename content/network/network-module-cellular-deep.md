---
id: network-module-cellular-deep
title: "Модуль: детали сотовых сетей — 3G, слои LTE, SIM и IMSI-catcher"
category: network
parent: network-module-telecom-core
difficulty: hard
order: 3
tags: [network, telecom, umts, lte, sim, esim, imsi-catcher, module]
prerequisites: [network-module-telecom-core]
useful_for:
  - "CTF Network (сотовые технологии)"
  - "Пентест: SIM, трекинг, фейковые станции"
  - "Работа (SOC): детект IMSI-catcher"
estimated_minutes: 55
summary: "Навигационный модуль про детали сотовых сетей: 3G/UMTS и KASUMI, слои LTE, SIM/eSIM и их ключи, а также IMSI-catcher — как он работает и как его ловят."
---

## Вопрос, с которого всё начинается

Мы разобрали 5G и сигнализацию оператора. Но чтобы по-настоящему понимать сотовую связь, нужны детали: как устроена 3G и её шифр KASUMI, что происходит на каждом слое LTE, где в SIM-карте лежат ключи и почему IMSI-catcher до сих пор работает.

## Что покрывает этот модуль

- **3G/UMTS**: UTRAN, RNC/NodeB, интерфейсы Iu/Iub/Iur и шифр KASUMI.
- **Слои LTE**: PHY/MAC/RLC/PDCP — что где и как это видно в дампах.
- **SIM/eSIM**: UICC, апплеты, OTA-провижининг, извлечение ключей KI/OPc.
- **IMSI-catcher**: как фейковая станция собирает абонентов и как её детектируют.

## Как читать этот модуль

Сначала [`network-3g-umts`](network-3g-umts) — база 3G. Затем [`network-lte-layers`](network-lte-layers) — слоистая модель LTE. После — [`network-sim-esim`](network-sim-esim) о картах и ключах. И завершает [`network-cellular-imsi-catcher`](network-cellular-imsi-catcher) — практический трекинг и детект.

## Зачем это нужно

Понимание деталей отличает «я слышал про IMSI-catcher» от «я могу объяснить, почему он работает и как его поймать». А извлечение ключей из SIM — отдельный навык, востребованный в анализе защищённости IoT и авто.

## Что мы теперь знаем

- 3G/UMTS: UTRAN, RNC/NodeB, шифр KASUMI.
- LTE имеет слои PHY/MAC/RLC/PDCP, видимые в дампах.
- SIM/eSIM хранят ключи KI/OPc; их можно извлечь.
- IMSI-catcher эксплуатирует слабости 2G/3G; его детектируют по аномалиям.

## Квиз

Проверь себя.

```quiz
- question: "Какой шифр используется в 3G/UMTS?"
  options:
    - "A5/1"
    - "KASUMI (f8/f9)"
    - "AES-GCM"
    - "ChaCha20"
  answer: 1
  explanation: "В 3G применяется KASUMI: f8 для шифрования, f9 для целостности."
- question: "Какой слой LTE отвечает за надёжность и повторную передачу?"
  options:
    - "PHY"
    - "MAC"
    - "RLC"
    - "PDCP"
  answer: 2
  explanation: "RLC отвечает за сегментацию и повторную передачу."
- question: "Что хранится в SIM и позволяет аутентифицироваться?"
  options:
    - "Только телефон"
    - "Ключи KI/OPc"
    - "Только IMSI"
    - "Только баланс"
  answer: 1
  explanation: "Долговременные ключи KI/OPc лежат в защищённой области UICC."
- question: "На чём основана работа IMSI-catcher?"
  options:
    - "На шифровании"
    - "На слабостях 2G/3G, где идентификатор летит открыто"
    - "На GPS"
    - "На Bluetooth"
  answer: 1
  explanation: "В 2G/3G идентификатор и аутентификация слабее, чем в 4G/5G."
```

## Куда дальше

Начнём с [`network-3g-umts`](network-3g-umts): как устроена 3G и что можно сломать в её UTRAN.

## Где пригодится

- CTF: разбор сотовых дампов.
- Пентест: SIM-ключи, фейковые станции.
- SOC: детект IMSI-catcher.
