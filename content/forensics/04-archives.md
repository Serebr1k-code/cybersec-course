---
id: forensics-archives
title: "Архивы и пароли: ZIP, RAR, 7z"
category: forensics
parent: forensics-carving
difficulty: easy
order: 1
tags: [zip, rar, 7z, password, john, hashcat, fcrackzip]
prerequisites: [forensics-carving]
useful_for:
  - "CTF Forensics категория"
  - "Восстановление защищённых архивов"
  - "Криминалистика данных"
estimated_minutes: 35
summary: "Анализ архивов, восстановление паролей ZIP/RAR/7z, работа с encrypted headers и известные атаки."
---
Архивы — один из самых частых контейнеров в форензике: ZIP, RAR, 7z, tar, gzip прячут файлы, пароли и вложенные слои. Атакующие упаковывают в них полезную нагрузку, а CTF-задачи часто строятся вокруг запароленного или повреждённого архива. Этот урок — про анализ архивов, восстановление паролей и нестандартные атаки: ZipCrypto vs AES, encrypted headers у 7z, known-plaintext и кража хешей.

## Идентификация архива

Первый шаг — понять формат и его защиту. `7z l` и `unzip -v` показывают метод сжатия и шифрование, а сигнатуры — реальный тип (расширение врёт).

```bash
$ file secret.zip
secret.zip: Zip archive data, at least v2.0 to extract
$ unzip -v secret.zip
  Length   Method    Size  Cmpr    Date    Time   CRC-32   Name
  1048576  Defl:N   128456  88%  2024-01-01 12:00  1a2b3c4d  data.bin
$ 7z l -slt secret.7z | head -30
Path = data.bin
Encrypted = +
Method = LZMA2:24 7zAES:19
```

Ключевой момент: у ZIP шифрование бывает двух видов — устаревший **ZipCrypto** (потоковый, уязвим к known-plaintext) и современный **AES-256** (WinZip). У 7z — **AES-256** с опциональным **encrypted header** (когда даже имена файлов зашифрованы). RAR5 — собственный AES.

## Извлечение: инструменты и флаги

```bash
# unzip: список, тест, извлечение
$ unzip -l a.zip          # список
$ unzip -t a.zip          # проверить целостность
$ unzip -o a.zip -d out/  # извлечь, перезаписывая
$ unzip -P pass a.zip     # с паролем
$ unzip -j a.zip -d out/  # без путей (junk paths)

# 7z: универсален, читает почти всё
$ 7z l a.7z
$ 7z x a.7z -oout/ -pPASS
$ 7z x -so a.7z data.bin > out.bin   # поток в stdout
$ 7z t a.7z                # тест

# RAR: unrar (пакет unrar / unrar-free)
$ unrar l a.rar
$ unrar x -pPASS a.rar out/
$ unrar x a.rar -pp            # не спрашивать пароль (пустой)
```

Для tar/gzip и других потоков смотрите урок `forensics-archive-deep`.

## Восстановление паролей: john и hashcat

Сначала нужно извлечь хеш из архива. У John есть конвертеры:

```bash
# ZIP: извлекает $pkzip2$ хеш
$ zip2john secret.zip > zip.hash
# RAR
$ rar2john secret.rar > rar.hash
# 7z
$ 7z2john.pl secret.7z > 7z.hash   # или python 7z2john
```

Дальше — офлайн-подбор:

```bash
# John
$ john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
$ john --format=pkzip2 --incremental zip.hash   # маска/брут
$ john --show zip.hash

# hashcat (mode 17200 = PKZIP, 13000 = RAR5, 11600 = 7-Zip)
$ hashcat -m 17200 -a 0 zip.hash rockyou.txt
$ hashcat -m 17200 -a 3 zip.hash '?d?d?d?d?d?d'   # 6 цифр
$ hashcat -m 17200 --show zip.hash
```

| Формат | hashcat mode | John converter |
|--------|-------------|----------------|
| ZIP (ZipCrypto) | 17200 | `zip2john` |
| ZIP (WinZip AES) | 13600 | `zip2john` |
| RAR3 | 12500 | `rar2john` |
| RAR5 | 13000 | `rar2john` |
| 7-Zip | 11600 | `7z2john` |
| gzip | 17220 | `gzip2john` |

`fcrackzip` — быстрый вариант только для ZipCrypto:

```bash
$ fcrackzip -u -D -p rockyou.txt secret.zip    # -u проверить распаковкой, -D словарь
$ fcrackzip -u -b -c '1a' secret.zip           # брут: только буквы и цифры
```

## ZipCrypto и known-plaintext

ZipCrypto использует потоковый шифр с известным алгоритмом ключа. Если у вас есть хотя бы 12 байт **известного открытого текста** одного из файлов, ключ восстанавливается почти мгновенно без брутфорса — `bkcrack` (CVE-2018-… семейство атак на ZipCrypto):

```bash
# plaintext.txt — известные байты файла внутри архива (>=12 байт)
$ bkcrack -C secret.zip -c data.bin -p plaintext.bin
[...] keys: 1a2b3c4d 5e6f7a8b 9c0d1e2f
# расшифровать всё с найденными ключами
$ bkcrack -C secret.zip -k 1a2b3c4d 5e6f7a8b 9c0d1e2f -D decrypted.zip
```

Почему работает: ZipCrypto хранит 12-байтовую «проверку пароля» и шифрует поток ключом из 3×32 бита, который однозначно определяется парой plaintext/ciphertext. AES-256 так не ломается — только брутфорс.

## Encrypted headers и нестандартные случаи

У 7z с `-mhe=on` имена файлов тоже зашифрованы: `7z l` не покажет содержимое без пароля, а `7z2john` не извлечёт хеш. Тогда работают только словарные/масковые атаки по всему контейнеру (`7z x` с паролем). У ZIP с «шифрованием имён» (`zip -e` не шифрует имена, но некоторые реализации — да) ситуация похожа.

Другие трюки:
- **Вложенные архивы** — `binwalk -e -M` распакует рекурсивно.
- **Повреждённый архив** — `zip -FF broken.zip --out fixed.zip` перестроит центральный каталог; для 7z — `7z x` иногда игнорирует хвост.
- **Zip-bomb** — маленький архив, разворачивающийся в терабайты; не распаковывайте «в лоб», ограничивайте `ulimit`.

## Разобранный пример

Дан `flag.zip` (ZipCrypto) с известным открытым текстом.

```bash
$ file flag.zip
flag.zip: Zip archive data, at least v2.0 to extract
$ unzip -l flag.zip
  Length      Name
  30          flag.txt
  1024        readme.txt
$ unzip -P '' flag.zip
[flag.zip] flag.txt password:
   skipping: flag.txt   incorrect password
```

`readme.txt` — предсказуемый файл, у нас есть его версия.

```bash
$ bkcrack -C flag.zip -c readme.txt -p readme.txt
[bkcrack] keys: 8f3a2b1c 4d5e6f70 8192a3b4
$ bkcrack -C flag.zip -k 8f3a2b1c 4d5e6f70 8192a3b4 -D out.zip
$ unzip -o out.zip
$ cat flag.txt
CTF{known_plaintext_wins}
```

Альтернатива, если known-plaintext нет:

```bash
$ zip2john flag.zip > h
$ hashcat -m 17200 -a 0 h /usr/share/wordlists/rockyou.txt
h:summer2024
$ unzip -P summer2024 flag.zip
```

## Частые ошибки

- **Путать ZipCrypto и AES.** `hashcat -m 17200` не возьмёт AES-архив (нужен 13600).
- **Забывать `-o`.** `unzip` спрашивает подтверждение и в скрипте «зависает».
- **Использовать онлайн-брут по 7z с encrypted header** — дорого и бесполезно без словаря.
- **Распаковывать zip-bomb** без ограничения размера.
- **Не фиксировать хеш архива** до распаковки — для цепочки улик.
- **Игнорировать known-plaintext** — самая быстрая атака на ZipCrypto.

## Что дальше / решение

Определите формат (`file`, `7z l -slt`) → извлеките хеш (`zip2john`/`rar2john`/`7z2john`) → подберите офлайн (`john`/`hashcat`) → при ZipCrypto без словаря примените `bkcrack`. Связка: `forensics-carving` (как достать архив из образа) и `forensics-archive-deep` (потоки gzip/zstd/tar и битые контейнеры).

## Вложенные архивы и рекурсивная распаковка

Атакующие и авторы CTF часто упаковывают архив в архив, иногда с разными форматами на каждом слое (ZIP → 7z → RAR → gzip). Ручная распаковка быстро утомляет, поэтому автоматизируйте:

```bash
# binwalk найдёт и рекурсивно распакует все слои
$ binwalk -e -M nested.bin
# цикл по всем найденным архивам с автоопределением
$ 7z x nested.zip -oout/ -y && find out -name '*.7z' -exec 7z x {} -oo2/ -y \;
# atool: единый интерфейс к zip/rar/7z/tar
$ aunpack archive.rar -X out/
```

Пароль на верхнем слое часто повторно используется на вложенных — извлечённый пароль из `zip.hash` стоит применить и к внутренним архивам. Если внутри архива снова зашифрованный контейнер, повторите конвейер `7z2john` → `hashcat`.

## Безопасность и фиксация улик

Работа с архивами — это работа с уликами, поэтому фиксируйте целостность **до** любых операций:

```bash
$ sha256sum suspect.zip | tee hash.txt
$ cp --reflink=auto suspect.zip suspect.zip.bak   # рабочая копия
$ unzip -o suspect.zip.bak -d out/                # распаковываем копию
$ sha256sum suspect.zip | diff - hash.txt && echo intact
```

Правила гигиены: не распаковывайте zip-bomb в домашний каталог (ограничьте `ulimit -f`, проверяйте `unzip -l` на суммарный `Length`), не запускайте подозрительные бинарники из архива, а офлайн-брут выполняйте только по извлечённому хешу, а не «в лоб» по сервису.

## Квиз

```quiz
- question: "Какой инструмент конвертирует ZIP в хеш для john?"
  options:
    - "`zip2john`"
    - "`rar2john`"
    - "`unzip -p`"
    - "`hashid`"
  answer: 0
- question: "ZipCrypto (legacy) известен тем, что…"
  options:
    - "невозможно взломать"
    - "ломается known-plaintext атакой (bkcrack)"
    - "использует AES-256"
    - "не шифрует данные"
  answer: 1
- question: "Какой режим hashcat соответствует WinZip AES?"
  options:
    - "17200"
    - "13600"
    - "11600"
    - "12500"
  answer: 1
- question: "Что делать, если EOCD ZIP повреждён?"
  options:
    - "удалить архив"
    - "`zip -FF broken.zip --out fixed.zip`"
    - "`tar xf`"
    - "переименовать в .rar"
  answer: 1
- question: "Чем 7z с encrypted headers сложнее для перебора?"
  options:
    - "он использует только XOR"
    - "каждая проверка пароля требует дорогого KDF"
    - "он не поддерживает словари"
    - "он не шифрует"
  answer: 1
```

## Где пригодится

- **CTF:** задачи «архив с паролем» и «матрешка из архивов».
- **Data recovery:** доступ к защищённым бэкапам.
- **Incident Response:** анализ архивов, украденных злоумышленником.
- **Криминалистика:** вскрытие зашифрованных контейнеров с доказательствами.
- **Пентест:** тестирование политик паролей на архивах.
