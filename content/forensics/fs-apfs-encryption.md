---
id: fs-apfs-encryption
title: 'APFS-шифрование: keybag и ключи'
category: forensics
parent: forensics-fs-extra
difficulty: hard
order: 2
tags: [forensics, apfs, encryption, keybag, macos]
prerequisites: [forensics-fs-structure]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Как устроено шифрование APFS, что такое keybag и как получить ключи для расшифровки тома.'
lab:
  kind: shell
  title: 'Практика: APFS-шифрование'
  toolset: [core, grep, strings]
  workdir: /home/student/task
  files: [task.md]
  check: 'grep -q ''nto{'' answer.txt'
  hints:
    - 'Прочитай файл-артефакт: `cat <файл>`.'
    - 'Ищи строку с меткой nto{.'
    - 'Сохрани: `grep nto <файл> > answer.txt`.'
---

## Вопрос, с которого всё начинается

Том APFS зашифрован. Чтобы прочитать данные, нужны ключи. Где они и как устроены?
Разберём **keybag** — хранилище ключей APFS.

## Наш пример: зашифрованный том

## Шаг 1: как шифруется APFS

APFS шифрует **каждый файл** своим ключом. Ключи хранятся в **keybag** — структуре с
несколькими «связками» (keybags):

- `Bag1` — том (volume);
- `Bag2` — метаданные;
- `Bag3` — пользователи.

## Шаг 2: где keybag

На macOS ключи привязаны к **Secure Enclave** (аппаратный чип). Извлечь их «в лоб»
нельзя. При анализе образа keybag лежит внутри тома:

```
$ apfs-fuse --help | grep -i keybag
```

## Шаг 3: пароль и ключи

Расшифровка возможна, если есть:

- **пароль пользователя** (для user keybag);
- **recovery key**;
- **институциональный ключ** (MDM/FileVault).

```
$ apfs-fuse -p <password> disk.img /mnt/apfs
```

`-p` передаёт пароль для разблокировки user keybag.

## Шаг 4: что внутри keybag

Keybag содержит зашифрованные ключи (wrapped keys). Чтобы их развернуть, нужен
KEK (key-encryption key), выводимый из пароля:

```
(password) → PBKDF2 → KEK → unwrap → VEK → decrypt volume
```

Без пароля цепочка не запускается.

## Шаг 5: практика

- если пароль известен — `apfs-fuse -p`;
- если есть Secure Enclave — нужен живой разблокированный Mac;
- brute-force пароля FileVault практически невозможен (сильный KDF).

## Что мы теперь знаем

- APFS шифрует файлы; ключи — в keybag.
- Keybags: том, метаданные, пользователи.
- На Apple Silicon ключи в Secure Enclave.
- Пароль разблокирует user keybag (apfs-fuse -p).
- Без пароля расшифровка невозможна.

## Если не сработало

- Нет пароля? Ищи recovery key у владельца.
- Secure Enclave? Нужен живой Mac.
- MDM? Проверь институциональный ключ.

## Квиз

Проверь себя.

```quiz
- question: Что такое keybag в APFS?
  options:
    - 'архив файлов'
    - 'хранилище ключей шифрования'
    - 'сетевой пакет'
    - 'обои'
  answer: 1
  explanation: 'Keybag содержит wrapped-ключи тома/пользователя.'
- question: Чем разблокируется user keybag?
  options:
    - 'ничем'
    - 'паролем пользователя/recovery key'
    - 'сетью'
    - 'обоями'
  answer: 1
  explanation: 'Из пароля выводится KEK, которым разворачиваются ключи.'
- question: Где ключи на Apple Silicon?
  options:
    - 'в файле'
    - 'в Secure Enclave'
    - 'в облаке'
    - 'в реестре'
  answer: 1
  explanation: 'Ключи защищены аппаратным Secure Enclave.'
- question: Что нужно для расшифровки тома на образе?
  options:
    - 'ничего'
    - 'пароль/recovery key'
    - 'сеть'
    - 'браузер'
  answer: 1
  explanation: 'Без пароля цепочка вывода ключей не работает.'
```
