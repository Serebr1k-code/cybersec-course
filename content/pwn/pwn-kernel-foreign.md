---
id: pwn-kernel-foreign
title: "Модуль: ядра других ОС (macOS/XNU, iOS, Android, FreeBSD)"
category: pwn
parent: pwn-kernel-intro
difficulty: expert
order: 3
tags: [pwn, module, roadmap, kernel, macos, xnu, iokit, ios, android, gki, freebsd]
prerequisites: [pwn-kernel-intro]
useful_for:
  - "Эксплуатация ядер macOS/iOS/Android/FreeBSD"
  - "Мобильная и десктопная kernel-эксплуатация"
estimated_minutes: 12
summary: "Навигационный модуль: kernel-эксплуатация за пределами Linux — XNU/IOKit (macOS), iOS (KTRR/PPL/PAC), Android (GKI/SELinux) и FreeBSD. Другие API, другие структуры, другие защиты."
---

## Что покрывает этот этап

Мы разбирали ядро Linux. Но у каждой ОС — своё ядро, свой драйверный API и свои
защиты:

- **macOS / XNU** — гибрид Mach + BSD, драйверы через **IOKit**, атакуемая
  поверхность — `IOExternalMethod` и MIG-интерфейсы.
- **iOS** — XNU плюс аппаратные защиты: **KTRR** (защита кода ядра),
  **PPL** (page protection layer), PAC в ядре.
- **Android** — ядро Linux, но с **GKI** (Generic Kernel Image), строгим
  **SELinux** и отдельными патчами Android.
- **FreeBSD** — ближайший родственник macOS по API; драйверы через `ioctl`.

## Чем это отличается от Linux-kernel

Три принципиальных отличия:

1. **Другой интерфейс атаки.** В Linux это системные вызовы, netfilter, eBPF; в
   macOS/iOS — IOKit-методы; в FreeBSD — ioctl; в Android — Linux-поверхность
   плюс binder/ashmem.
2. **Другие структуры объектов.** Нет `struct cred`/`task_struct` в привычном
   виде; в XNU — `proc`/`kauth_cred`, в FreeBSD — `ucred`.
3. **Аппаратные защиты ядра.** KTRR/PPL на iOS и PAC меняют то, как достигается
   исполнение кода в ядре; часто работают data-only техники.

## Как устроены эти уроки

Каждый урок — одна ОС: поверхность атаки, типичные классы багов, структуры,
нужные для примитива, и чем техника отличается от Linux. Для iOS отдельно —
как KTRR/PPL/PAC влияют на достижение kernel read/write.

## Что вы сможете после этапа

- Ориентироваться в поверхности атаки четырёх ядер.
- Понимать, какие структуры дают kernel read/write на каждой платформе.
- Учитывать аппаратные защиты при выборе техники.
- Переносить Linux-методологию (info-leak → R/W → privesc) на другие ядра.

## Квиз

Проверь себя.

```quiz
- question: Через что атакуют драйверы в macOS/XNU?
  options:
    - "Через netfilter"
    - "Через IOKit и IOExternalMethod"
    - "Через eBPF"
    - "Через systemd"
  answer: 1
  explanation: Основная поверхность XNU-драйверов — IOKit и MIG-интерфейсы.
- question: Что такое KTRR на iOS?
  options:
    - "Сетевой протокол"
    - "Аппаратная защита кода ядра от записи"
    - "Аллокатор"
    - "Файловая система"
  answer: 1
  explanation: KTRR защищает страницы кода ядра; поэтому часто нужны data-only атаки.
- question: Чем Android-ядро отличается от ванильного Linux?
  options:
    - "Ничем"
    - "GKI, SELinux и патчи Android"
    - "Оно на Windows"
    - "Оно не имеет syscall"
  answer: 1
  explanation: Android добавляет GKI, строгий SELinux и собственные подсистемы.
- question: Как называется структура учётных данных процесса в FreeBSD?
  options:
    - "cred"
    - "ucred"
    - "kauth_cred"
    - "task_struct"
  answer: 1
  explanation: В FreeBSD это ucred (в XNU — kauth_cred, в Linux — cred).
```

## Куда дальше

Начни с **macOS/XNU** — он хорошо документирован и близок к FreeBSD. Затем
**Android** (Linux + GKI), **iOS** (самые жёсткие защиты) и **FreeBSD**. А пока
главное: **сначала изучи поверхность атаки и структуры конкретного ядра — Linux-
рецепты напрямую не переносятся**.

## Где пригодится

- Мобильная и десктопная kernel-эксплуатация.
- Исследование драйверов и подсистем разных ОС.
- Понимание аппаратных защит ядра.
