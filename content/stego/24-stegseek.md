---
id: stego-stegseek
title: "Брут парольной стеганографии: stegseek и stegcracker"
category: stego
parent: stego-tooling
difficulty: easy
order: 4
tags: [stego, stegseek, stegcracker, wordlist, brute, steghide]
prerequisites: [stego-image-tools, stego-outguess]
useful_for:
  - "CTF Stego — парольные контейнеры"
  - "Автоматизация перебора словарём"
  - "Forensics: восстановление доступа к контейнеру"
estimated_minutes: 30
summary: "Как быстро вскрывать steghide-контейнеры: stegseek против rockyou, stegcracker, подготовка словарей и стратегия перебора вместо слепого брута."
---

## Вопрос, с которого всё начинается

Ты нашёл JPEG, `steghide info` подтвердил, что внутри данные. Но `steghide extract` просит пароль, а ты его не знаешь. Угадывать вручную бесполезно. Что делать?

Ответ — **перебор словарём**. Инструмент `stegseek` умеет прогонять миллионы паролей в секунду. Разберём это на конкретном контейнере.

## Наш пример: secret.jpg

Проверим, что данные вообще есть:

```
$ steghide info secret.jpg
"secret.jpg": contains embedded data (size 0.2 KB)
```

Попробуем извлечь — он спросит пароль. Но вместо ручного ввода запустим перебор по словарю:

```
$ stegseek secret.jpg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/stegseek
[i] Found passphrase: "sunshine" 
[i] Original filename: "flag.txt"
[i] Extracting to "secret.jpg.out"
$ cat secret.jpg.out
flag{stegseek_rockyou}
```

За секунды пароль найден. `stegseek` — C++-крэкер steghide-контейнеров, многопоточный, использует все ядра.

## Шаг 1: как устроена парольная стеганография

`steghide` прячет данные в JPEG/BMP/WAV/AU и **шифрует** их паролем (AES/Blowfish по введённой фразе). Без пароля извлечь нельзя — но пароль можно подобрать. При неверном пароле `steghide` молчит, поэтому перебор сводится к «получилось / нет», что идеально для быстрого крэкера.

```bash
steghide embed -cf cover.jpg -ef secret.txt -p pass   # спрятать
steghide info cover.jpg                                # что внутри
steghide extract -sf cover.jpg -p pass                 # извлечь
```

## Шаг 2: полный набор флагов stegseek

```bash
stegseek cover.jpg /usr/share/wordlists/rockyou.txt     # брут словарём
stegseek cover.jpg words.txt extracted.out              # в указанный файл
stegseek --seed cover.jpg                               # извлечь seed-данные
stegseek --crack cover.jpg words.txt -f out.txt         # явный режим crack
stegseek --version
```

Полезные приёмы:

```bash
# быстро понять, steghide ли это (без полного словаря)
stegseek --seed cover.jpg
# ограничить по времени, если словарь огромный
timeout 300 stegseek cover.jpg big.txt
```

## Шаг 3: словари и правила

Перебор — это на 90 % качество словаря, а не мощность.

| Источник | Путь | Когда |
|---|---|---|
| rockyou | `/usr/share/wordlists/rockyou.txt` | универсальный старт |
| SecLists passwords | `.../Passwords/Common-Credentials/*` | расширенный |
| кастомный | свой файл | контекст задачи (автор, домен, название) |
| мутации | `hashcat --stdout -r best64.rule` | усиление базового списка |

```bash
# мутации: добавить цифры/регистр/символы
hashcat --stdout base.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt
stegseek cover.jpg mutated.txt
```

Собери контекстный список: название CTF, имя автора, домен, «flag», год, типовые пароли (`password`, `secret`, `admin`).

## Шаг 4: stegcracker — медленная альтернатива

```bash
pip install stegcracker
stegcracker cover.jpg rockyou.txt
stegcracker cover.jpg words.txt --threads 8
```

`stegcracker` вызывает `steghide` на каждый пароль (новый процесс на пароль) — на порядки медленнее `stegseek`. Используй его только для совместимости.

## Шаг 5: когда не steghide

Не всякая парольная стего — это steghide:

| Инструмент | Носитель | Подбор пароля |
|---|---|---|
| `outguess` | JPEG | отдельный, часто пароль в задаче |
| `DeepSound` | WAV/MP3 | GUI/скрипт |
| `MP3Stego` | MP3 | извлечение с паролем |
| `zsteg` | PNG/BMP | не парольный (LSB) |
| `openstego` | PNG/JPG | парольный, свой формат |

Если `stegseek --seed` показывает, что данных steghide нет, — контейнер сделан другим инструментом.

## Шаг 6: почему слепой брут нереален

Полный перебор 6 символов — это астрономическое пространство. Пароль подбирают по **словарю** и **контексту**, а не вслепую. Если rockyou не помог — строй кастомный список из подсказок задачи.

## Если не сработало

- Проверь `steghide info` — есть ли данные вообще.
- `stegseek --seed` — правильный ли формат (steghide).
- rockyou не помог — мутации (`best64.rule`) и кастомный список.
- Не steghide — пробуй `outguess`/`DeepSound`/`MP3Stego`.
- Извлечённый файл нечитаем — это может быть архив/изображение: разбирай `file`/`binwalk`.

## Что мы теперь знаем

1. `stegseek` — быстрый крэкер steghide (миллионы паролей/сек).
2. `steghide info` показывает данные без пароля.
3. Перебор — это в первую очередь качество словаря.
4. `stegcracker` — медленная обёртка над steghide.
5. Для outguess/DeepSound/MP3Stego — свои подходы.

## Шаг 7: шпаргалка и частые сценарии

```bash
# проверить контейнер и найти пароль
steghide info cover.jpg                      # есть ли данные
stegseek --seed cover.jpg                    # какой формат
stegseek cover.jpg /usr/share/wordlists/rockyou.txt out.bin
# если rockyou не помог — мутации
hashcat --stdout base.txt -r /usr/share/hashcat/rules/best64.rule > mut.txt
stegseek cover.jpg mut.txt
# извлечь вручную с найденным паролем
steghide extract -sf cover.jpg -p <pass>
```

Частые сценарии на практике:

1. `stegseek` не находит пароль — словарь не содержит нужного; собери контекстный список (название CTF, автор, домен, «flag»).
2. `steghide info` говорит «нет данных» — контейнер не steghide, проверь outguess/DeepSound/MP3Stego.
3. Пароль найден, но `steghide` молчит — проверь, тот ли файл-носитель (`-sf`).
4. Извлечённый файл нечитаем — это может быть архив/изображение, разбирай `file`/`binwalk`.

## Шаг 8: оптимизация перебора

- `stegseek` уже многопоточный и использует все ядра.
- Держи словарь локально и исключи дубликаты: `sort -u words.txt > words_u.txt`.
- Для outguess/DeepSound массового крэкера нет — сокращай словарь контекстом.
- Запускай с `timeout 300 stegseek ...`, чтобы не ждать огромный словарь бесконечно.

## Шаг 9: что писать в отчёте

Для воспроизводимости фиксируй: инструмент, словарь (путь и число строк), найденный пароль и извлечённый артефакт (имя/тип/размер) и дальнейшую цепочку разбора. Без этого результат не подтвердить.

## Шаг 10: установка и сравнение крэкеров

```
$ sudo apt install stegseek        # или из релизов GitHub
$ stegseek --version
StegSeek 0.6
```

`stegseek` — C++-крэкер, использует все ядра. `stegcracker` — Python-обёртка над `steghide` (медленнее, но проще). Сравнение:

| Инструмент | Скорость | Когда применять |
|---|---|---|
| `stegseek` | миллионы паролей/сек | основной выбор |
| `stegcracker` | тысячи/сек | скрипты, совместимость |
| `steghide` | ручной ввод | один известный пароль |

Если `stegseek` не находит пароль за разумное время, дело почти всегда в словаре, а не в инструменте.

## Квиз

Проверь себя.

```quiz
- question: "Какой инструмент быстрее всего подбирает пароль steghide?"
  options:
    - "`stegseek`"
    - "`stegcracker`"
    - "`zsteg`"
    - "`exiftool`"
  answer: 0
  explanation: "stegseek прогоняет миллионы паролей в секунду."
- question: "Что нужно для перебора пароля стего-контейнера?"
  options:
    - "Словарь (rockyou) и/или правила мутаций"
    - "Только имя файла"
    - "EXIF"
    - "Палитра"
  answer: 0
  explanation: "Перебор опирается на словарь/мутации."
- question: "Для какого инструмента нет быстрого крэкера вроде stegseek?"
  options:
    - "outguess"
    - "steghide"
    - "zip"
    - "gzip"
  answer: 0
  explanation: "Для outguess подбор медленнее/отдельный."
- question: "Как расширить словарь мутациями?"
  options:
    - "`hashcat --stdout -r best64.rule`"
    - "`jadx`"
    - "`mmls`"
    - "`zsteg`"
  answer: 0
  explanation: "Правила hashcat генерируют варианты слов."
- question: "Почему слепой брут 6 символов нереален?"
  options:
    - "Пространство паролей слишком велико"
    - "Он шифрован"
    - "Он требует root"
    - "Он медленный только для PNG"
  answer: 0
  explanation: "Полный перебор коротких паролей огромен; нужен контекст."
```

## Куда дальше

Дальше — **zsteg и stegsolve**: системный перебор LSB-каналов и визуальный анализ плоскостей, то есть «где искать», а не «как подобрать пароль». А пока запомни: парольные контейнеры вскрывают словарём, и `stegseek` — самый быстрый способ.

## Где пригодится

- **CTF (Stego):** парольные контейнеры — очень частый формат задач.
- **Forensics:** восстановление доступа к зашифрованным контейнерам.
- **Blue team:** оценка стойкости стего-каналов.
- **Работа:** понимание словарных атак в целом.
