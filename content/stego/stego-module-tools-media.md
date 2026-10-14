---
id: stego-module-tools-media
title: "Модуль: Инструменты для аудио и медиа"
category: stego
parent: stego-tooling-advanced
difficulty: medium
order: 6
tags: [stego, roadmap, audacity, sonic-visualiser, deepsound, silenteye, audio]
prerequisites: [stego-tooling-advanced]
useful_for:
  - "CTF Stego: разбор аудио-задач"
  - "Форензика: акустические носители"
  - "Blue team: анализ медиа-вложений"
estimated_minutes: 8
summary: "Навигационный модуль по аудио-инструментам: Audacity/Sonic Visualiser (спектрограммы) и DeepSound/SilentEye (LSB-контейнеры с паролем)."
---

## Зачем этот модуль

Аудио-стего редко разбирают вручную: нужны инструменты для визуализации спектра и
для распаковки контейнеров. Этот модуль закрывает оба случая.

## Что разберём

- **stego-tool-audacity** — спектрограммы, настройки FFT, чтение «нарисованного»
  текста; Sonic Visualiser для тонкого анализа.
- **stego-tool-deepsound** — DeepSound/SilentEye: LSB-контейнеры в WAV, пароль,
  обнаружение.

## Как проходить

Сначала спектрограмма (самый частый случай), затем контейнеры с паролем. В каждом
уроке — реальный WAV и разбор.

## Что вы будете уметь

- Строить и читать спектрограммы.
- Подбирать окно FFT и диапазон частот.
- Извлекать данные из аудио-контейнеров.
