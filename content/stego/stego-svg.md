---
id: stego-svg
title: "Стеганография в SVG: XML-комментарии, атрибуты и path-данные"
category: stego
parent: stego-image-formats-exotic
difficulty: easy
order: 1
tags: [stego, svg, xml, comments, path, css, metadata]
prerequisites: [stego-image-formats-exotic, stego-text]
useful_for:
  - "CTF Stego: SVG-задачи"
  - "Веб-безопасность: анализ SVG"
  - "Анализ векторной графики"
estimated_minutes: 40
summary: "SVG — это текст на XML: данные прячут в комментариях, неиспользуемых атрибутах, data:URI, CSS и координатах path; разбираем приёмы и инструменты извлечения."
---

SVG принципиально отличается от растровых форматов: это **текст на XML**, и его можно читать глазами. Отсюда и специфические каналы стеганографии: XML-комментарии `<!-- -->`, неиспользуемые/кастомные атрибуты, `data:` URI, встроенные `<metadata>`, CSS-свойства и даже **координаты path** — числа с избыточной точностью, младшие разряды которых кодируют биты. Плюс SVG может содержать вложенный растр (base64 PNG) и внешние ссылки. Разбор начинается с простого `cat`, но при аккуратном встраивании данные можно сделать незаметными для беглого взгляда.

## Структура SVG

SVG — это XML-документ с корнем `<svg>` и namespace. Данные могут лежать где угодно между тегами.

```xml
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <!-- 666c61677b... -->                 <!-- комментарий -->
  <rect x="0" y="0" width="200" height="200" fill="#fff" data-x="c2VjcmV0"/>
  <metadata>encoded: ZmxhZ3t... </metadata>
  <path d="M10.0000001 10 L20.0000002 20 ..."/>
</svg>
```

```bash
file image.svg
head -40 image.svg
xmllint --format image.svg | head -60   # отформатировать для чтения
```

## Основные каналы

| Канал | Пример | Извлечение |
|---|---|---|
| XML-комментарий | `<!-- data -->` | `grep -o '<!--.*-->'` |
| Неиспользуемый атрибут | `data-x="..."` | `grep -oE 'data-[a-z]+="[^"]*"'` |
| `<metadata>` | текст/XML внутри | `xmllint --xpath` |
| `data:` URI | base64 внутри | decode base64 |
| CSS-свойства | `--var: url(...)` | `grep` по `<style>` |
| Координаты path | избыточная точность | парсинг младших разрядов |
| Вложенный растр | base64 PNG | декод → zsteg |

## Комментарии и атрибуты

```bash
# все комментарии
grep -oP '(?s)<!--.*?-->' image.svg
# подозрительные атрибуты
grep -oE '[a-zA-Z-]+="[A-Za-z0-9+/=]{16,}"' image.svg
# base64-подобные строки в любом месте
grep -oE '[A-Za-z0-9+/]{20,}={0,2}' image.svg | while read s; do echo "$s" | base64 -d 2>/dev/null; done
```

## Координаты path как битовый канал

Аккуратный приём: числа в `d` записываются с лишней точностью, и младший разряд кодирует бит. Например, `10.0000001` vs `10.0000000`. Визуально path не меняется, но данные есть.

```python
import re
svg=open('image.svg').read()
nums=re.findall(r'\d+\.(\d+)', svg)
bits=''.join(str(int(n[-1])&1) for n in nums)
print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8)))
```

## Вложенный растр и data: URI

SVG может нести base64-картинку внутри `data:image/png;base64,...`. Это отдельный носитель — после декода к нему применимы все растровые техники.

```bash
# найти data:image и декодировать
python3 - <<'PY'
import re,base64
svg=open('image.svg').read()
for m in re.finditer(r'data:image/(png|jpeg|gif);base64,([A-Za-z0-9+/=]+)', svg):
    ext=m.group(1); data=base64.b64decode(m.group(2))
    open(f'embedded.{ext}','wb').write(data); print('wrote embedded.'+ext, len(data))
PY
zsteg embedded.png
```

## Разобранный пример

CTF: `logo.svg`.

```bash
$ grep -oP '(?s)<!--.*?-->' logo.svg
<!-- ZmxhZ3tzdmdfY29tbWVudHN9 -->

$ echo 'ZmxhZ3tzdmdfY29tbWVudHN9' | base64 -d
flag{svg_comments}
```

Флаг был base64 в комментарии. Если комментарий пуст — следующий шаг:

```bash
# атрибуты с base64
grep -oE '="[A-Za-z0-9+/=]{20,}"' logo.svg
# метаданные
xmllint --xpath '//*[local-name()="metadata"]/text()' logo.svg 2>/dev/null
# координаты path
python3 -c "import re;svg=open('logo.svg').read();print(re.findall(r'\.\d{4,}',svg)[:20])"
# вложенный растр
grep -oE 'data:image/[a-z]+;base64,[A-Za-z0-9+/=]+' logo.svg | head -c 80
```

## Краевые случаи и подводные камни

- **Многострочные комментарии:** `grep` без `(?s)` не поймает `<!-- ... \n ... -->` — используй `grep -ozP` или парсер.
- **XML entities:** данные могут быть закодированы как `&#102;&#108;...` — декодируй entities (`xmllint --noent`).
- **CDATA:** `<![CDATA[...]]>` прячет содержимое от парсеров XML.
- **Сжатый SVG (.svgz):** это gzip — распакуй (`gunzip`) и разбирай как обычный SVG.
- **Внешние ссылки:** `<image href="http://...">` — SSRF/утечка; для стего — проверь, не указывает ли на data-канал.

## Что дальше / решение

Пайплайн: `head`/`cat` → `xmllint --format` для читаемости → `grep -oP '(?s)<!--.*?-->'` для комментариев → `grep` по base64-подобным атрибутам и `data:` URI → `xmllint --xpath` по `<metadata>` → анализ координат path → декод вложенного растра и `zsteg`. SVG — самый «текстовый» из графических форматов: если данные вообще есть, они почти всегда видны после нормального парсинга.

## Справочные таблицы

| Инструмент | Команда | Назначение |
|---|---|---|
| xmllint | `--format` | форматирование |
| xmllint | `--noent` | раскрыть entities |
| xmllint | `--xpath` | выбор узла |
| grep | `-ozP '(?s)<!--.*?-->'` | многострочные комментарии |
| base64 | `-d` | декод data:URI |

| Канал | Сложность | Заметность |
|---|---|---|
| Комментарий | низкая | низкая |
| Кастомный атрибут | низкая | средняя |
| data:URI | средняя | низкая |
| Координаты path | высокая | очень низкая |
| CDATA | средняя | низкая |

## XXE и SSRF в SVG как отдельный вектор

SVG — это XML, а значит, к нему применимы XML-атаки, которые часто идут рука об руку со стеганографией. Внешние сущности (XXE) позволяют читать файлы, а ссылки на внешние ресурсы — делать SSRF. В контексте задачи «найти скрытое» это ещё один слой, который стоит проверить.

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

```bash
# проверить, есть ли DOCTYPE/ENTITY
grep -iE 'DOCTYPE|ENTITY|SYSTEM' image.svg
# раскрыть entities (может выдать содержимое)
xmllint --noent image.svg 2>/dev/null | head -20
```

Если SVG загружается сервером и обрабатывается, XXE/SSRF — реальная уязвимость, а не только CTF-трюк. Всегда фиксируйте такие находки отдельно от стеганографии.

## CSS и анимации как носитель

SVG поддерживает `<style>` и SMIL-анимации. CSS-переменные, `content`-свойства и комментарии внутри `<style>` — удобные каналы, которые не видны при рендеринге.

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <style>
    /* ZmxhZ3tjc3Nfc3RlZ28= */
    .a { --data: "hidden"; }
  </style>
  <rect class="a" width="10" height="10"/>
</svg>
```

```bash
# все стили и комментарии внутри них
grep -oP '(?s)<style>.*?</style>' image.svg
# base64 внутри CSS
grep -oE '[A-Za-z0-9+/]{20,}={0,2}' image.svg | while read s; do echo "$s" | base64 -d 2>/dev/null; done
```

SMIL-анимации (`<animate>`, `<set>`) могут нести данные в значениях `values`/`to` — тоже канал, который легко пропустить.

## Автоматический парсер SVG

Соберём скрипт, который вытаскивает все «подозрительные» строки: комментарии, base64-подобные атрибуты, `data:` URI, длинные координаты.

```python
import re, base64
svg=open('image.svg',encoding='utf-8').read()
# комментарии
for m in re.findall(r'<!--(.*?)-->', svg, re.S):
    print('COMMENT:', m.strip()[:200])
# base64-подобные строки
for s in re.findall(r'[A-Za-z0-9+/]{24,}={0,2}', svg):
    try:
        dec=base64.b64decode(s)
        if all(32<=b<127 or b in (9,10,13) for b in dec):
            print('B64:', dec[:120])
    except Exception:
        pass
# длинные дробные числа (path)
print('PATH NUMS:', re.findall(r'\.\d{5,}', svg)[:20])
```

Скрипт за один прогон закрывает комментарии, base64, `data:` URI и координаты. Если ничего — проверьте `&#...;` entities и CDATA.

## Краевые случаи и защита

- **Минифицированный SVG:** всё в одну строку — используйте `xmllint --format` перед анализом.
- **Экранированные символы:** `\u003c` и подобные последовательности внутри JS в `<script>` — декодируйте.
- **Внешние `<use href>`:** могут тянуть данные извне — проверьте и как утечку.
- **Безопасность:** при приёме SVG на сервере — запрещайте DOCTYPE, фильтруйте `<script>` и внешние ссылки; иначе XXE/SSRF/XSS.

## Разобранный пример 2: path-стего и CSS

Задача: `chart.svg`, визуально — обычный график. Комментарии и атрибуты чистые.

```bash
$ grep -oP '(?s)<!--.*?-->' chart.svg | head
(пусто)
$ grep -oE '[A-Za-z0-9+/]{24,}={0,2}' chart.svg | head
(пусто)
```

Остаются координаты path и CSS. Смотрим длинные дробные числа:

```bash
$ python3 -c "import re;print(re.findall(r'\.\d{4,}', open('chart.svg').read())[:12])"
['.0000001', '.0000000', '.0000001', '.0000001', '.0000000', '.0000001', ...]
```

Младший разряд кодирует биты. Собираем:

```python
import re
svg=open('chart.svg').read()
bits=''.join(n[-1] for n in re.findall(r'\.(\d{4,})', svg))
# берём последнюю цифру каждого длинного дробного числа
bits=''.join(n[-1] for n in re.findall(r'\.(\d{4,})', svg))
print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits)-7,8)))
# b'flag{svg_path_bits}'
```

Флаг был в младших разрядах координат. Такой приём незаметен визуально и переживает обычную валидацию XML. Если path-числа «круглые», проверьте CSS-переменные и SMIL-анимации — там тоже бывают данные.

## Частые ошибки и как их избежать

Разбор SVG кажется тривиальным, но есть устойчивые грабли, на которых теряют время.

- **Бинарный вид файла:** если `head` показывает нечитаемые байты, а `file` говорит «SVG», возможно, это `.svgz` (gzip). Проверьте первые байты `\x1f\x8b` и распакуйте через `gunzip`.
- **Однострочный SVG:** редакторы минифицируют документ, и `grep` по `<!--` не находит комментарий, потому что он внутри одной строки. Используйте `xmllint --format` или `grep -ozP`.
- **Entities вместо текста:** данные могут быть закодированы как `&#102;&#108;...`. Примените `xmllint --noent` или `python -c "import html; print(html.unescape(...))"`.
- **Namespace-префиксы:** тег может быть `<svg:metadata>` или `<x:metadata>` — учитывайте префиксы при XPath-запросах.
- **Внешние ссылки:** `<image href="data:...">` с большим base64 легко пропустить при беглом чтении; ищите `base64,` по всему файлу.

Практический порядок: `file` → распаковка при необходимости → `xmllint --format` → поиск комментариев → base64/`data:` → `<metadata>` → path-координаты → CSS/SMIL. Такой порядок закрывает и текстовые, и «числовые» каналы SVG за один проход.

## Итоговый чек-лист по SVG

1. `file` — SVG это или gzip (`.svgz`); распаковать при необходимости.
2. `xmllint --format` — привести к читаемому виду.
3. Поиск комментариев (`grep -ozP '(?s)<!--.*?-->'`).
4. Поиск base64 и `data:` URI по всему файлу.
5. `<metadata>` через `xmllint --xpath`; раскрыть entities (`--noent`).
6. Анализ длинных координат path (младшие разряды).
7. Проверка CSS/SMIL и внешних ссылок (XXE/SSRF).

## Квиз

```quiz
- question: "Почему SVG удобен для стеганографии?"
  options:
    - "Это текстовый XML-формат: данные прячут в комментариях, атрибутах и path"
    - "Он бинарный и сжатый"
    - "Он не поддерживает текст"
    - "Он работает только с аудио"
  answer: 0
- question: "Как хранят биты в координатах path?"
  options:
    - "Избыточной точностью чисел, кодируя младший разряд"
    - "Через CRC"
    - "Через палитру"
    - "Через DCT"
  answer: 0
- question: "Чем .svgz отличается от .svg?"
  options:
    - "Это gzip-сжатый SVG, нужно распаковать"
    - "Это WebP"
    - "Это TIFF"
    - "Это архив ZIP с паролем"
  answer: 0
- question: "Что делает xmllint --noent?"
  options:
    - "Раскрывает XML-entities"
    - "Удаляет комментарии"
    - "Сжимает файл"
    - "Считает CRC"
  answer: 0
```

## Где пригодится

- **CTF Stego:** задачи на SVG-комментарии и path.
- **Веб-безопасность:** анализ SVG на XSS/SSRF и скрытые данные.
- **Работа:** разбор векторной графики и дизайн-ассетов.
- **Bug bounty:** проверка загружаемых SVG.
