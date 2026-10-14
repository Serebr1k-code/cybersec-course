---
id: mal-go-rust
title: 'Go и Rust-малварь: особенности статических бинарников'
category: forensics
parent: forensics-malware-families
difficulty: hard
order: 5
tags: [malware, golang, rust, static, forensics]
prerequisites: [forensics-malware-yara]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 50
summary: 'Чем Go/Rust-образцы отличаются от C/C++: большие статические бинарники, свои рантаймы, как их анализировать.'
lab:
  kind: shell
  title: 'Практика: Go и Rust-малварь'
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

Современная малварь всё чаще пишется на **Go** и **Rust**. Такие образцы — большие,
статические, со своим рантаймом. Обычные приёмы анализа дают много шума. Разберём
особенности.

## Наш пример: Go-образец

## Шаг 1: как распознать

```
$ file sample.bin
sample.bin: ELF 64-bit LSB executable, statically linked, not stripped
$ ls -la sample.bin
-rwxr-xr-x 1 root root 8.2M sample.bin
```

Размер в мегабайты + `not stripped` + `static` — почти наверняка Go. Строки содержат
пути рантайма:

```
$ strings sample.bin | grep -m3 'go1\.'
go1.21.5
```

`go1.x` — версия компилятора. Для Rust — ищи `rustc` и `core::`.

## Шаг 2: символы Go

Go-бинарники часто **не stripped**, и это подарок:

```
$ go tool nm sample.bin 2>/dev/null | grep -i 'main\.' | head
```

Имена функций `main.main`, `main.beacon` дают структуру. `GoReSym` восстанавливает
символы, если их почистили.

## Шаг 3: строки и конфиг

```
$ strings sample.bin | grep -iE 'http|10\.10' | head
https://203.0.113.5/api
```

В Go-малвари строки лежат плотно; часто весь C2-конфиг виден в `strings`.

## Шаг 4: крипто-библиотеки

Go несёт в себе `crypto/tls`, `crypto/aes` — их символы указывают на шифрование:

```
$ go tool nm sample.bin 2>/dev/null | grep -i 'crypto/tls' | head
```

Rust использует `ring`, `openssl`; ищи соответствующие символы.

## Шаг 5: анализ

- **`strings` + `grep`** — быстрый старт;
- **`GoReSym`/`redress`** — восстановление типов и символов;
- **YARA** — правила под Go/Rust;
- **Динамика** — рантайм создаёт много потоков (goroutines).

## Что мы теперь знаем

- Go/Rust-образцы — большие статические бинарники.
- Go выдаёт `go1.x` в строках, Rust — `rustc`.
- Go часто не stripped — символы дают структуру.
- Конфиг C2 виден в `strings`.
- Рантайм-библиотеки (crypto/tls) дают зацепки.

## Если не сработало

- Символы удалены? Используй GoReSym.
- Обфускация (garble)? Часть имён восстановима по строкам.
- Нужна логика? Динамический анализ в песочнице.

## Квиз

Проверь себя.

```quiz
- question: Как отличить Go-бинарник?
  options:
    - 'маленький размер'
    - 'большой статический бинарник + строки go1.x'
    - 'нет строк'
    - 'формат PE'
  answer: 1
  explanation: 'Go-образцы крупные, статические и содержат версию рантайма.'
- question: Что даёт go tool nm?
  options:
    - 'сеть'
    - 'таблицу символов (имена функций)'
    - 'пароли'
    - 'обои'
  answer: 1
  explanation: 'nm показывает символы; у Go часто видны имена main.*.'
- question: Чем полезен GoReSym?
  options:
    - 'шифрует'
    - 'восстанавливает символы/типы Go-бинарника'
    - 'удаляет файлы'
    - 'сканирует сеть'
  answer: 1
  explanation: 'GoReSym реконструирует метаданные Go даже после stripping.'
- question: Почему Rust-образцы узнаваемы?
  options:
    - 'по расширению'
    - 'по строкам rustc/ring и структуре'
    - 'по размеру 1 КБ'
    - 'по имени'
  answer: 1
  explanation: 'Строки и символы Rust-рантайма/крейтов выдают компилятор.'
```
