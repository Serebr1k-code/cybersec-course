---
id: stego-stegseek
title: "Брут парольной стеганографии: stegseek и stegcracker"
category: stego
parent: stego-tooling
difficulty: easy
order: 2
tags: [stego, stegseek, stegcracker, wordlist, brute, steghide]
prerequisites: [stego-image-tools, stego-outguess]
useful_for:
  - "CTF Stego — парольные контейнеры"
  - "Автоматизация перебора словарём"
  - "Forensics: восстановление доступа к контейнеру"
estimated_minutes: 30
summary: "Как быстро вскрывать steghide-контейнеры: stegseek против rockyou, stegcracker, подготовка словарей и стратегия перебора вместо слепого брута."
---

Инструменты вроде `steghide`/`outguess` прячут данные под паролем. Если пароль неизвестен, его подбирают словарём. `stegseek` — быстрый (миллионы паролей/сек) крэкер steghide-контейнеров; `stegcracker` — обёртка над steghide. Это превращает «неизвестный пароль» в решаемую задачу за минуты при хорошем словаре.

## stegseek

```bash
# установка
apt install stegseek    # или из релизов
# брут словарём
stegseek image.jpg rockyou.txt
# указать выходной файл
stegseek image.jpg rockyou.txt extracted.out
# определить формат (steghide/outguess)
stegseek --seed image.jpg
```

Скорость: порядка миллионов паролей/сек — rockyou (14M) прогоняется за секунды-минуты.

## stegcracker

```bash
pip install stegcracker
stegcracker image.jpg rockyou.txt
# с кастомным словником
stegcracker image.jpg /usr/share/wordlists/rockyou.txt
```

`stegcracker` вызывает `steghide` по каждому паролю; медленнее stegseek, но прост.

## Стратегия перебора

- **Сначала словарь** (rockyou, seclists/Passwords, common.txt), потом маски.
- **Подсказки:** пароль может быть в метаданных/задаче; соберите кастомный список (название задачи, автор, домен).
- **Правила (rules):** мутации словаря (`hashcat --stdout -r rules/best64.rule`).
- **Не слепой брут:** 4-6 символов вслепую нереально; используйте контекст.

```bash
# сгенерировать мутации словаря
hashcat --stdout words.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt
stegseek image.jpg mutated.txt
```

## Когда не steghide

- **outguess:** отдельный инструмент, свой брут (нет быстрого крэкера; часто пароль в задаче).
- **DeepSound:** парольная стего в аудио (GUI/скрипт).
- **MP3Stego:** пароль для mp3.
- **PNG zsteg:** не парольный, но проверьте LSB.

## Разобранный пример

CTF: `secret.jpg`, подсказка «пароль — слово из задачи». Пентестер:
1. `steghide extract -sf secret.jpg` → просит пароль.
2. `stegseek secret.jpg rockyou.txt` → находит пароль → извлекает файл → флаг.

## Частые ошибки

- Пытаться угадать пароль вручную вместо словаря.
- Использовать медленный stegcracker там, где stegseek в разы быстрее.
- Не собирать контекстный словарь (название/автор задачи).
- Брутить outguess тем же методом (нужен другой инструмент).

## Что делать дальше

- **Пароль найден** → извлеките и разберите файл.
- **rockyou не сработал** → правила/кастомный словарь.
- **Не steghide** → outguess/DeepSound/MP3Stego.
- **Контейнер другой** → zsteg/бит-плоскости.

## steghide и парольные контейнеры: как это устроено

`steghide` прячет данные в JPEG/BMP/WAV/AU, шифруя их паролем (AES/Blowfish по введённой фразе). Без пароля извлечь нельзя — но пароль можно подобрать. `steghide` при неверном пароле молчит, поэтому перебор = «получилось/нет», идеально для быстрого крэкера.

```bash
# Базовая работа с steghide
steghide embed -cf cover.jpg -ef secret.txt        # спрятать
steghide embed -cf cover.jpg -ef secret.txt -p pass
steghide extract -sf cover.jpg                      # извлечь (спросит пароль)
steghide info cover.jpg                             # что внутри
```

## stegseek: полный набор флагов и режимы

`stegseek` — C++-крэкер steghide (миллионы паролей/сек), использует все ядра.

```bash
stegseek cover.jpg /usr/share/wordlists/rockyou.txt          # брут словарём
stegseek cover.jpg words.txt extracted.out                   # в файл
stegseek --seed cover.jpg                                    # извлечь seed-данные
stegseek --crack cover.jpg words.txt -f out.txt              # явный crack
stegseek --version / --help
```

Полезные приёмы:

```bash
# быстро проверить, steghide ли это (без полного словаря)
stegseek --seed cover.jpg
# ограничить по времени, если словарь огромный
timeout 300 stegseek cover.jpg big.txt
```

## Словари и правила: как строить

Перебор — это на 90% качество словаря, а не мощность.

| Источник | Путь | Когда |
|----------|------|-------|
| rockyou | `/usr/share/wordlists/rockyou.txt` | универсальный старт |
| SecLists passwords | `.../Passwords/Common-Credentials/*` | расширенный |
| кастомный | свой файл | контекст задачи (автор, домен, название) |
| мутации | `hashcat --stdout -r best64.rule` | усиление базового списка |

```bash
# мутации: добавить цифры/регистр/символы
hashcat --stdout base.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt
stegseek cover.jpg mutated.txt
# комбинировать два словаря
hashcat --stdout -a 1 a.txt b.txt > combo.txt
```

Соберите контекстный список: название CTF, имя автора задачи, домен, «flag», год, типовые пароли (`password`, `secret`, `admin`).

## stegcracker и другие крэкеры

```bash
pip install stegcracker
stegcracker cover.jpg rockyou.txt           # обёртка над steghide (медленнее)
stegcracker cover.jpg words.txt --threads 8
```

`stegcracker` вызывает `steghide` на каждый пароль (процесс на пароль) — на порядки медленнее `stegseek`; используйте его только для совместимости/скриптов.

## Когда не steghide

| Инструмент | Носитель | Подбор пароля |
|------------|----------|---------------|
| `outguess` | JPEG | отдельный, часто пароль в задаче |
| `DeepSound` | WAV/MP3 | GUI/скрипт, свой перебор |
| `MP3Stego` | MP3 | `-X` извлечение с паролем |
| `zsteg` | PNG/BMP | не парольный (LSB) |
| `openstego` | PNG/JPG | парольный, свой формат |

## Оптимизация: скорость, GPU, параллель

- `stegseek` уже многопоточный и использует все ядра.
- Словарь держите локально (быстрое чтение), исключите дубликаты: `sort -u`.
- Для outguess/DeepSound массового крэкера нет — сокращайте словарь контекстом.
- Прогресс: запускайте с `timeout` и смотрите, растёт ли счётчик; если 100k паролей за секунды — словарь мал.

## Разобранные примеры

**1. stegseek.** `steghide extract -sf secret.jpg` просит пароль → `stegseek secret.jpg rockyou.txt` за секунды находит → извлекает `flag.txt`.

**2. Кастомный словарь.** rockyou не подошёл; из подсказки «пароль — имя автора» собрали список → попал.

**3. Не steghide.** `stegseek --seed` показывает, что данных steghide нет → это outguess; ищем пароль в задаче.

## Частые ошибки и отладка

- **Угадывать вручную** вместо словаря.
- **stegcracker вместо stegseek** — в разы медленнее.
- **Игнорировать контекст** задачи при составлении словаря.
- **Брутить outguess как steghide** — другой инструмент.
- **Отладка:** `steghide info` — есть ли вообще данные; `stegseek --seed` — правильный ли формат; если «нет данных», контейнер может быть не steghide.

## Что делать дальше / дерево решений

1. `steghide info` → данные есть? → `stegseek` со словарём.
2. Нет → `stegseek --seed` → формат не steghide → outguess/DeepSound/MP3Stego.
3. Словарь не сработал → правила/кастомный список.
4. Извлекли → разберите (файл может быть архивом/изображением).
5. Пароль не находится → контекст задачи, метаданные, README.

## Шпаргалка и частые сценарии

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

Частые сценарии на практике: (1) `stegseek` не находит пароль — словарь не содержит нужного; соберите контекстный список (название CTF, автор, домен, «flag»); (2) `steghide info` говорит «нет данных» — контейнер не steghide, проверьте outguess/DeepSound/MP3Stego; (3) пароль найден, но `steghide` всё равно молчит — проверьте, не указан ли другой файл-носитель (`-sf`); (4) извлечённый файл нечитаем — это может быть архив/изображение, разбирайте `file`/`binwalk`. В отчёте укажите: инструмент, словарь, найденный пароль и извлечённый артефакт.

## Квиз

```quiz
- question: "Какой инструмент быстрее всего подбирает пароль steghide?"
  options:
    - "stegseek"
    - "stegcracker"
    - "zsteg"
    - "exiftool"
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
    - "hashcat --stdout -r best64.rule"
    - "jadx"
    - "mmls"
    - "zsteg"
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

## Где пригодится

- **CTF Stego:** парольные контейнеры.
- **Forensics:** восстановление доступа.
- **Bug bounty:** скрытые данные.
- **Работа:** анализ контейнеров.
