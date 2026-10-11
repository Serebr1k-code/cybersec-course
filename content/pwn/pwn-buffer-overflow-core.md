---
id: pwn-buffer-overflow-core
title: "Переполнение буфера: format string, shellcode, integer overflow, stack clash"
category: pwn
parent: pwn-buffer-overflow
difficulty: medium
order: 1
tags: [pwn, buffer-overflow, format-string, shellcode, integer-overflow, stack-clash]
prerequisites: [pwn-buffer-overflow]
useful_for:
  - "CTF Pwn: классические stack-задачи"
  - "Аудит C/C++ кода"
estimated_minutes: 10
summary: "Модуль классического переполнения буфера: format string, shellcode, integer overflow и stack clash."
---
Этот модуль собирает классические разновидности переполнения буфера и связанных с ними уязвимостей стека — от format string до integer overflow и stack clash. Вместе они покрывают основу CTF-задач начального и среднего уровня.

## Что покрывает этап

**pwn-format-string** — format string: чтение и запись памяти через управляемый форматный спецификатор.
**pwn-shellcode** — shellcode: написание и размещение полезной нагрузки.
**pwn-integer-overflow** — integer overflow и type confusion как путь к переполнению буфера.
**pwn-stack-clash** — stack clash: атака на обработку больших стековых аллокаций.

## Почему такой порядок

Format string идёт первым: это отдельный и очень наглядный класс баг, не требующий переполнения. Shellcode — практический навык размещения полезной нагрузки. Integer overflow и stack clash замыкают модуль как менее очевидные, но важные пути к порче памяти.

## Что вы сможете после этапа

- Читать и записывать память через format string.
- Писать и размещать shellcode.
- Использовать integer overflow для достижения переполнения.
- Понимать механику stack clash и способы защиты от неё.

## Квиз

```quiz
- question: "Чем format string отличается от классического переполнения буфера?"
  options:
    - "Это отдельный класс баг, не требующий переполнения"
    - "Это то же самое"
    - "Он работает только в ядре"
    - "Он требует GPU"
  answer: 0
  explanation: "Format string использует управляемые спецификаторы формата."
- question: "Что нужно уметь делать с shellcode?"
  options:
    - "Писать и размещать полезную нагрузку"
    - "Только компилировать"
    - "Только шифровать"
    - "Только декомпилировать"
  answer: 0
  explanation: "Shellcode — это полезная нагрузка эксплойта."
- question: "Почему integer overflow и stack clash идут последними?"
  options:
    - "Это менее очевидные, но важные пути к порче памяти"
    - "Они проще остальных"
    - "Они не связаны с переполнением"
    - "Они устарели"
  answer: 0
  explanation: "Они требуют более глубокого понимания семантики."
```

## Где пригодится

- **CTF:** задачи категории pwn и смежные.
- **Bug bounty:** поиск и воспроизведение уязвимостей в реальном ПО.
- **Пентест:** работа с бинарями и встроенными системами на этапе эксплуатации.
- **Работа:** анализ инцидентов, реверс и vulnerability research.
