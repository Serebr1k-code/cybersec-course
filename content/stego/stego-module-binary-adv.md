---
id: stego-module-binary-adv
title: "Модуль: Двоичные форматы и архивы (Git, Docker, ELF, Mach-O)"
category: stego
parent: stego-binary-carriers
difficulty: medium
order: 5
tags: [stego, roadmap, git, docker, elf, macho, binary]
prerequisites: [stego-binary-carriers]
useful_for:
  - "CTF Stego: репозитории, образы, бинарники"
  - "Форензика: данные в двоичных уликах"
  - "Blue team: закладки в артефактах сборки"
estimated_minutes: 8
summary: "Навигационный модуль по двоичным носителям: Git-объекты (zlib + blob), Docker-слои (tar + whiteouts), ELF (overlay, note-секции) и Mach-O (load-команды, LC_NOTE). Общий приём — найти «служебное» поле или хвост."
---

## Зачем этот модуль

Современные артефакты разработки и исполнения — репозитории, образы, бинарники —
сложные контейнеры. У каждого есть служебные области: висячие объекты, whiteouts,
note-секции, load-команды. Именно там прячут данные, и именно их не проверяют
инструменты.

## Что разберём

- **stego-git-objects** — Git-объекты (zlib + `blob <len>\0`), висячие blob,
  packfiles.
- **stego-docker-layers** — Docker/OCI-образы: манифест, слои-tar, whiteouts.
- **stego-elf-notes** — ELF: overlay после конца файла, note-секции, `.comment`.
- **stego-macho** — Mach-O: load-команды, `LC_NOTE`, padding, fat-бинарь.

## Как проходить

По порядку. В каждом уроке — реальный двоичный артефакт и короткий Python-парсер
(`zlib`, `tarfile`, `struct`).

## Что вы будете уметь

- Распаковывать Git-объект и находить висячие blob.
- Разбирать слои Docker-образа и whiteouts.
- Вычислять конец ELF и читать overlay.
- Проходить по load-командам Mach-O.

