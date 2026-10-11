---
id: misc-encoding
title: "Кодировки, QR и штрихкоды"
category: misc
parent: misc-core
difficulty: easy
order: 2
tags: [encoding, base64, qr, barcode, rot13, unicode, cyberchef]
prerequisites: [misc-intro]
useful_for:
  - "Узнавать и декодировать незнакомые представления данных"
  - "Читать QR и штрихкоды из картинок"
  - "Строить цепочки декодирования в CyberChef"
estimated_minutes: 28
summary: "Кодировка — это не шифрование: данные обратимо преобразованы в другой алфавит. Разбираем base-семейство, hex, URL, ROT/Цезарь, морзянку, Unicode-трюки, QR/штрихкоды и как выстраивать цепочки декодирования."
---
## Введение

Кодировка — это не шифрование: данные просто представлены в другом алфавите, и преобразование обратимо без ключа. Большинство misc-задач начинается с вопроса «что это за строка?». Навык распознавания и быстрого декодирования — базовый для всего CTF: он встречается в web, crypto, forensics и reverse. В этом уроке — распознавание по виду, инструменты декодирования, многослойные цепочки и разбор типовых сюжетов.

Ключевое различие, которое надо усвоить сразу: кодирование сохраняет данные и не требует секрета; шифрование скрывает данные и требует ключ. Если строка выглядит «непонятно», сначала проверьте кодировки — это дешевле, чем строить атаку.

## Распознавание по виду

| Вид | Вероятная кодировка |
|-----|---------------------|
| `SGVsbG8=` | Base64 (с `=` на конце) |
| `48656c6c6f` | Hex |
| `%48%65%6c` | URL-encoding |
| `01101000` | Бинарный ASCII |
| `.... . .-..` | Морзе |
| `S$G$V$s` | ROT/подстановка |
| `4` `1` `2` | Decimal/ASCII-коды |
| `JBSWY3DP` | Base32 |
| `StV1o` | Base58 (нет `0OIl`) |

```bash
echo 'SGVsbG8=' | base64 -d
echo '48656c6c6f' | xxd -r -p
python3 -c "import urllib.parse;print(urllib.parse.unquote('%48%65'))"
```

## Base-семейство

```bash
base64 -d <<< 'SGVsbG8='      # Base64
base32 -d <<< 'JBSWY3DP'      # Base32
base58 -d <<< 'StV1o'         # Base58 (нет 0OIl)
python3 -c "import base64;print(base64.b85decode(b'Xk~0{Zv'))"
```

Признаки: Base64 — `A-Za-z0-9+/=`, длина кратна 4; Base32 — `A-Z2-7=`, кратна 8; Base58 — без `0OIl`; Base85 — широкий набор символов. Base62 и кастомные алфавиты требуют явной таблицы.

```python
import base64
print(base64.b64decode('SGVsbG8=').decode())
print(base64.b32decode('JBSWY3DP'))
print(base64.b85decode('Xk~0{Zv'))
```

## Hex, URL, бинарь, морзе

```bash
echo '68 65 6c 6c 6f' | xxd -r -p
python3 -c "import urllib.parse;print(urllib.parse.unquote_plus('a%20b+c'))"
python3 -c "print(''.join(chr(int('01101000',2))))"
```

Морзе:

```python
m={'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G',
   '....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N',
   '---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U',
   '...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1'}
s='.... . .-.. .-.. ---'
print(''.join(m.get(c,'') for c in s.split()))
# HELLO
```

## Классические подстановки

```python
import codecs
codecs.decode('Uryyb', 'rot13')       # Hello
def caesar(s, n):
    return ''.join(chr((ord(c)-65+n)%26+65) if c.isupper() else c for c in s)
def atbash(s):
    return ''.join(chr(219-ord(c)) if c.isalpha() else c for c in s)
```

Перебирайте ROT-N (1..25) — не только ROT13. Atbash — обратный алфавит. Частотный анализ вскрывает более сложные моноалфавитные подстановки.

## QR и штрихкоды

```bash
zbarimg qr.png
python3 -c "from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('qr.png')))"
zbarimg barcode.png
qrencode -o out.png 'flag{test}'
```

Проблемы: низкий контраст, повреждённые/перевёрнутые коды, «инвертированные» QR (белое на чёрном). В таких случаях помогает бинаризация через PIL/OpenCV перед `zbarimg`.

## Цепочки декодирования (CyberChef)

Данные часто закодированы несколько раз:

```bash
echo 'U0dWc2JHOD0=' | base64 -d | xxd -r -p | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

В CyberChef: drag-n-drop операций (`From Base64` → `From Hex` → `ROT13`); «Magic» подбирает цепочку автоматически. При автоматизации используйте Python-скрипт с рекурсивным base64-декодированием.

## Разобранный пример: многослойная строка

**Дано:** `Vm0wd2QyUXlVWGxW...`

1. По виду (base64-подобно) декодируем: `echo ... | base64 -d` → снова base64.
2. Повторяем, пока не получим читаемое:

```bash
s='Vm0wd2QyUXlVWGxW...'
while :; do
  n=$(echo "$s" | base64 -d 2>/dev/null) || break
  [ -z "$n" ] && break
  s="$n"; echo "$s"
done
```

3. На выходе — флаг или следующий слой (hex/ROT).

## Частые ошибки и подводные камни

- **Путать кодирование и шифрование** — кодировка не требует ключа.
- **Забыть про несколько слоёв** — base64 от base64 обычное дело.
- **Неверный алфавит Base** — base58/62/85 имеют свои таблицы.
- **Игнорировать контекст** — `=` на конце сильный признак base64.
- **Плохое качество картинки QR** — нужен чёткий контраст/бинаризация.
- **Пропускать ROT-N** — не только ROT13; перебирайте все сдвиги.
- **Забыть про Unicode-нормализацию** — «похожие» символы скрывают текст.

## Справочная таблица

| Признак | Кодировка | Команда |
|---------|-----------|---------|
| `A-Za-z0-9+/=` | Base64 | `base64 -d` |
| `A-Z2-7=` | Base32 | `base32 -d` |
| `0-9a-f` | Hex | `xxd -r -p` |
| `%xx` | URL | `unquote` |
| точки/тире | Морзе | свой словарь |
| `0/1` | бинарь | `int(...,2)` |
| QR/баркод | изображение | `zbarimg` |

## Что дальше / решение

- Строка `A-Za-z0-9+/=` → Base64.
- Только `0-9a-f` → Hex.
- `%` → URL.
- Точки/тире → Морзе.
- QR/баркод → `zbarimg`.
- Смежные уроки: `misc-intro`, `misc-unicode`, `misc-binary-misc`.

## Unicode-кодировки и гомоглифы

Помимо байтовых кодировок, часто встречаются Unicode-трюки:

- **UTF-8 vs UTF-16 vs UTF-32:** одна и та же строка в разных байтовых представлениях.
- **Zero-width символы:** `\u200b`, `\u200c`, `\u200d`, `\ufeff` невидимы и могут кодировать биты.
- **Гомоглифы:** кириллическая `а` вместо латинской `a` ломает сравнение.
- **Нормализация:** NFC/NFD меняют представление; сравнение без нормализации уязвимо.

```python
import unicodedata
s = "pаypal"  # 'а' кириллическая
print([hex(ord(c)) for c in s])
print(unicodedata.normalize('NFKC', s))
# вытащить невидимые символы
print([c for c in s if unicodedata.category(c) == 'Cf'])
```

## Многослойные цепочки: автоматизация

```python
import base64, binascii, codecs, re
def try_all(s):
    for name, fn in [('b64', lambda x: base64.b64decode(x)),
                     ('b32', lambda x: base64.b32decode(x)),
                     ('hex', lambda x: binascii.unhexlify(x))]:
        try:
            out = fn(s.encode())
            if out: print(name, out[:60])
        except Exception: pass
```

Рекурсивно применяйте декодеры, пока результат остаётся «печатным или закодированным». CyberChef Magic делает это интерактивно, но скрипт полезен в пайплайне.

## Чек-лист распознавания

| Вопрос | Действие |
|--------|----------|
| Есть `=` в конце? | base64 |
| Только 0-9a-f? | hex |
| `%`? | URL |
| Точки/тире? | Морзе |
| Только 0/1? | бинарь |
| Невидимые символы? | zero-width/Unicode |
| Картинка? | zbarimg/QR |

## Что дальше

- Пробуйте декодеры от простого к сложному, фиксируя каждый слой.
- Для Unicode — нормализация и поиск невидимых символов.
- Для картинок — бинаризация перед `zbarimg`.

## Практика: быстрый декодер-скрипт

```python
import base64, binascii, urllib.parse, codecs, re
def autodecode(s, depth=0):
    if depth > 8 or not s.strip(): return s
    s = s.strip()
    for fn in (lambda x: base64.b64decode(x),
               lambda x: binascii.unhexlify(re.sub(r'[\s:]', '', x)),
               lambda x: urllib.parse.unquote(x).encode()):
        try:
            out = fn(s.encode())
            if out and out != s.encode():
                txt = out.decode('utf-8', 'replace')
                print('  '*depth, txt[:80])
                return autodecode(txt, depth+1)
        except Exception:
            pass
    return s
```

Такой рекурсивный декодер за секунды проходит цепочки base64/hex/URL. Для морзянки и ROT добавьте свои ветки.

## Итоговая шпаргалка распознавания

| Строка | Кодировка | Декодер |
|--------|-----------|---------|
| `SGVsbG8=` | Base64 | `base64 -d` |
| `JBSWY3DP` | Base32 | `base32 -d` |
| `48656c6c6f` | Hex | `xxd -r -p` |
| `%48%65` | URL | `unquote` |
| `.... .` | Морзе | словарь |
| `01001000` | бинарь | `int(x,2)` |
| невидимые | Unicode | `category=='Cf'` |
| картинка | QR/баркод | `zbarimg` |

Держите под рукой `python3` с `base64`/`binascii`/`codecs` — этого достаточно для 90% задач на кодировки.

## Квиз

```quiz
- question: "Чем кодирование отличается от шифрования?"
  options:
    - "Кодирование обратимо без ключа, шифрование требует ключ"
    - "Они одинаковы"
    - "Кодирование всегда с ключом"
    - "Шифрование необратимо"
  answer: 0
  explanation: "Кодировка — представление, не секрет."
- question: "Какой признак у Base64?"
  options:
    - "Алфавит A-Za-z0-9+/ и часто = на конце"
    - "Только цифры"
    - "Только 0 и 1"
    - "Только заглавные"
  answer: 0
  explanation: "Символы и выравнивание выдают Base64."
- question: "Чем декодировать QR из картинки?"
  options:
    - "zbarimg"
    - "base64"
    - "rot13"
    - "xxd"
  answer: 0
  explanation: "zbarimg читает QR и штрихкоды."
- question: "Что делает ROT13?"
  options:
    - "Сдвигает буквы на 13 (самообратимо)"
    - "Шифрует AES"
    - "Кодирует Base64"
    - "Сжимает данные"
  answer: 0
  explanation: "ROT13 — сдвиг на 13, обратен себе."
- question: "Почему задача может требовать несколько шагов?"
  options:
    - "Данные закодированы несколько раз разными способами"
    - "Кодировка всегда одна"
    - "Флаг всегда в открытом виде"
    - "Base64 необратим"
  answer: 0
  explanation: "Многослойные цепочки — обычная практика."
```

## Где пригодится

- **CTF Misc:** базовый навык распознавания и декодирования.
- **Bug bounty:** обход фильтров кодировками.
- **Пентест:** разбор обфускации.
- **Работа:** работа с данными в разных представлениях.
- **Дальше по дереву:** `misc-encoding-text`, `misc-encoding-media`.
