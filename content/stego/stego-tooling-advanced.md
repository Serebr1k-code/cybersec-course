---
id: stego-tooling-advanced
title: "Инструменты: StegSolve, stegdetect, jsteg/cloakify"
category: stego
parent: stego-tooling
difficulty: easy
order: 2
tags: [stego, roadmap, stegsolve, stegdetect, jsteg, cloakify, stegohide]
prerequisites: [stego-tooling]
useful_for:
  - "CTF Stego: продвинутый инструментарий"
  - "Планирование порядка изучения стеганографии"
estimated_minutes: 10
summary: "Группа тем про продвинутые инструменты: StegSolve/AperiSolve/StegOnline (каналы и кадры), stegdetect/jphide/jpseek и аудио-инструменты, jsteg/cloakify/camouflage/StegHide."
lab:
  kind: shell
  title: "Практика: stegdetect + jpseek"
  toolset: [core, stego]
  workdir: /home/student/task
  files: [task.md, notes.txt, image.jpg, wordlist.txt]
  check: "grep -q 'nto{' found.txt"
  hints:
    - "Определи алгоритм детектором: `stegdetect image.jpg`."
    - "Гипотеза jphide => парный извлекатель jpseek."
    - "Пароль — одно из слов в `wordlist.txt`. Пробуй: `jpseek -p <пароль> image.jpg`."
    - "Запиши флаг: `jpseek -p steg0 image.jpg > found.txt`."
---

Этот модуль — продолжение базового инструментария. Если stego-tooling покрывал OutGuess, steghide, stegseek и zsteg, то здесь собраны инструменты для визуального анализа каналов (StegSolve, AperiSolve, StegOnline), детекторы и встраиватели в JPEG и аудио (stegdetect, jphide/jpseek, mp3stego, DeepSound, SilentEye, OpenStego, snow) и утилиты для «незаметной» передачи (jsteg, cloakify, camouflage, StegHide со всеми флагами). Цель — научиться выбирать правильный инструмент под конкретный формат и алгоритм.

## Что покрывает этап

- **stego-tool-stegsolve** — StegSolve, AperiSolve, StegOnline: методология перебора канальных плоскостей, bit-plane и frame browser.
- **stego-tool-stegdetect** — stegdetect, jphide/jpseek, mp3stego, DeepSound, SilentEye, OpenStego, snow: детекторы и встраиватели.
- **stego-tool-jsteg-cloakify** — jsteg, cloakify, camouflage, StegHide со всеми флагами: встраивание и извлечение.

## Почему такой порядок

Визуальный анализ идёт первым: StegSolve/StegOnline дают быстрый результат, когда данные видны на конкретной битовой плоскости или в кадре, и не требуют знания алгоритма. Детекторы — следующий шаг: они подсказывают, каким инструментом, вероятно, прятали данные. Встраиватели/извлекатели замыкают модуль: это уже целевые инструменты под известный алгоритм, которые применяют, когда детектор или формат дали зацепку.

## Что вы сможете после этапа

- Просматривать каналы и битовые плоскости в StegSolve/AperiSolve/StegOnline и находить визуальные аномалии.
- Запускать stegdetect и интерпретировать его вердикты по JPEG.
- Извлекать данные из JPEG через jsteg/jphide и встраивать через cloakify/camouflage.
- Работать со StegHide во всех режимах: встраивание, извлечение, генерация отчёта.

## Квиз

```quiz
- question: "Когда StegSolve/AperiSolve удобнее целевых инструментов?"
  options:
    - "Когда данные видны на битовой плоскости или в кадре и алгоритм неизвестен"
    - "Когда файл зашифрован AES"
    - "Когда нужно брутить пароль steghide"
    - "Когда файл — это pcap"
  answer: 0
- question: "Что делает stegdetect?"
  options:
    - "Определяет, каким алгоритмом, вероятно, встроены данные в JPEG"
    - "Расшифровывает AES"
    - "Восстанавливает удалённые файлы"
    - "Строит спектрограмму"
  answer: 0
- question: "Для чего нужен cloakify?"
  options:
    - "Для встраивания данных в текст, похожий на обычную речь"
    - "Для сжатия PNG"
    - "Для анализа EXIF"
    - "Для брута пароля"
  answer: 0
```

## Где пригодится

- **CTF:** быстрый визуальный анализ и подбор инструмента под формат.
- **Bug bounty:** проверка медиафайлов на скрытый контент.
- **Форензика:** детектирование стеганографии в подозрительных файлах.
- **Работа:** построение пайплайна анализа медиа на скрытые данные.
