---
id: osint-social-mastodon
title: "Mastodon и Fediverse OSINT: инстансы, профили, федерация"
category: osint
parent: osint-social-niche
difficulty: medium
order: 2
tags: [osint, mastodon, fediverse, activitypub, social, webfinger]
prerequisites: [osint-username-enum]
useful_for:
  - "CTF категория OSINT"
  - "Расследования"
  - "Мониторинг сообществ"
estimated_minutes: 30
summary: "Разведка в федеративной сети: как устроен Fediverse, поиск профилей по нику и WeblFinger, инстансы, миграции и данные через ActivityPub."
---
Fediverse (федеративная вселенная) — это сеть независимых серверов (инстансов), общающихся по открытому протоколу **ActivityPub**. Mastodon — крупнейшая реализация. Для OSINT Fediverse интересен тремя свойствами: **открытые API**, **федеративная доставка** (контент расходится по инстансам) и **отсутствие единого «входа»** (нет одного каталога пользователей). Это одновременно усложняет и обогащает разведку: профили легко читаются через API, но ник привязан к инстансу.

## Теория: как устроен Fediverse

Ключевые понятия:
- **Инстанс** — отдельный сервер (например, `mastodon.social`, `fosstodon.org`).
- **Актор** — учётная запись вида `@user@instance.tld`.
- **WebFinger** — протокол, по которому по адресу `acct:user@instance` находят профиль.
- **ActivityPub** — протокол публикации/подписки; API отдаёт посты в JSON.
- **Федерация** — инстансы обмениваются контентом; удалённый пост может кэшироваться у подписчиков.

Следствие для OSINT: даже удалённый пост может остаться в кэше другого инстанса, а публичные API позволяют читать профили без входа.

## WebFinger: найти профиль по адресу

WebFinger — «DNS» для Fediverse. По адресу получаем реальный профиль:

```bash
curl -s "https://mastodon.social/.well-known/webfinger?resource=acct:target@mastodon.social" \
  | python3 -m json.tool
```

Вывод:

```json
{
  "subject": "acct:target@mastodon.social",
  "links": [
    { "rel": "self", "type": "application/activity+json",
      "href": "https://mastodon.social/users/target" },
    { "rel": "http://webfinger.net/rel/profile-page",
      "href": "https://mastodon.social/@target" }
  ]
}
```

Из `links` берём ActivityPub-эндпоинт (`/users/target`) — дальше работаем с ним.

## Чтение профиля через ActivityPub

```bash
curl -s -H 'Accept: application/activity+json' https://mastodon.social/users/target \
  | python3 -m json.tool
```

Ответ содержит:

```json
{
  "id": "https://mastodon.social/users/target",
  "type": "Person",
  "preferredUsername": "target",
  "name": "Ivan Petrov",
  "summary": "<p>Dev, opinions my own</p>",
  "url": "https://mastodon.social/@target",
  "published": "2019-04-02T00:00:00Z",
  "attachment": [ {"name": "GitHub", "value": "<a href=\"https://github.com/ipetrov\">ipetrov</a>"} ],
  "icon": { "url": "https://.../avatar.png" },
  "publicKey": { "id": "...", "owner": "...", "publicKeyPem": "-----BEGIN PUBLIC KEY-----..." }
}
```

Что полезно:
- `published` — дата регистрации (коррелируется с другими аккаунтами).
- `attachment` — «метаданные» профиля: часто GitHub, сайт, email.
- `publicKey` — **публичный ключ актора**: стабильный криптографический идентификатор.
- `icon.url` — аватар для обратного поиска.

## Лента и посты

Публичные посты отдаются через ActivityPub:

```bash
curl -s -H 'Accept: application/activity+json' \
  "https://mastodon.social/users/target/outbox?page=true" | python3 -m json.tool | head -60
```

Каждый пост — JSON с `published`, `content`, вложениями, `to` (аудитория). Из этого извлекаются:
- **геолокация** (если включены геотеги),
- **упоминания** других аккаунтов (граф),
- **ссылки** (на личные сайты, другие платформы),
- **времена активности** (часовой пояс).

## Поиск по федерации

У Mastodon есть поиск по инстансу:

```bash
curl -s "https://mastodon.social/api/v2/search?q=target&type=accounts&resolve=true" \
  | python3 -m json.tool
```

`resolve=true` заставляет инстанс «подтянуть» удалённый аккаунт. Также есть:
- `q=target@instance` — точный адрес;
- `q=#hashtag` — поиск по хэштегу (найти сообщество);
- сторонние каталоги: `fedilab.app`, `instances.social`.

## Миграции аккаунтов

В Mastodon можно перенести аккаунт, и старый профиль указывает `movedTo`:

```bash
curl -s -H 'Accept: application/activity+json' https://mastodon.social/users/oldtarget \
  | grep -i moved
# "movedTo": "https://fosstodon.org/users/target"
```

Это **золото** для OSINT: цепочка миграций связывает старый и новый аккаунт (атрибуция!), а также показывает активность в разных сообществах.

## Разобранный пример: от ника к личности

Дано: ник `target`.

Шаг 1 — поиск инстанса через каталог:

```bash
curl -s "https://instances.social/api/1.0/instances/list?count=0" | head
```

Шаг 2 — пробуем популярные инстансы:

```bash
for inst in mastodon.social fosstodon.org infosec.exchange techhub.social; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://$inst/@target")
  echo "$inst -> $code"
done
```

Шаг 3 — на найденном инстансе читаем профиль и метаданные (GitHub, сайт).

Шаг 4 — идём по ссылкам в `attachment` и по `movedTo`.

Итог: Fediverse-профиль → личный сайт → другие соцсети → личность.

## Таблица: эндпоинты Fediverse

| Цель | Эндпоинт |
|------|----------|
| Найти профиль | `/.well-known/webfinger?resource=acct:user@inst` |
| Профиль (JSON) | `/users/<name>` c `Accept: activity+json` |
| Посты | `/users/<name>/outbox` |
| Поиск | `/api/v2/search?q=...&resolve=true` |
| Инстанс-инфо | `/api/v1/instance` |
| Миграция | поле `movedTo` в профиле |

## Ошибки и подводные камни

- **Искать «во всём Fediverse» одним запросом.** Нет глобального поиска — нужен перебор инстансов или `resolve`.
- **Забывать заголовок `Accept: application/activity+json`.** Без него вернётся HTML, а не JSON.
- **Путать локальный и федеративный контент.** Пост может быть виден на одном инстансе и скрыт на другом.
- **Игнорировать `publicKey`.** Это стабильный идентификатор, полезный для корреляции.
- **Считать удалённый пост исчезнувшим.** Он мог остаться в кэше подписчиков.
- **Не учитывать rate limit.** Публичные API ограничивают запросы; делайте паузы.

## Что дальше / решение

Fediverse даёт открытый, машинночитаемый профиль и цепочки миграций. Дальше: **Twitch** (`osint-social-twitch`) и **подкасты** (`osint-social-podcast`) для аудио/видео-следов, **разрешение идентичностей** (`osint-identity-resolution`) для связывания профиля с личностью. Итог: Fediverse — самый «прозрачный» для OSINT сегмент соцсетей: JSON-профиль, публичный ключ, история миграций — всё доступно без входа.

## Массовый поиск актора по инстансам

Поскольку нет глобального каталога, полезен скрипт перебора популярных инстансов. Он проверяет, где зарегистрирован ник, и сохраняет найденное.

```bash
#!/usr/bin/env bash
# fedi-find.sh — поиск актора по списку инстансов
NICK="$1"
INSTANCES=$(cat <<'EOF'
mastodon.social
fosstodon.org
infosec.exchange
techhub.social
mstdn.social
hachyderm.io
mas.to
mastodon.online
EOF
)
while read -r inst; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/activity+json' \
         "https://$inst/users/$NICK")
  [ "$code" = "200" ] && echo "FOUND @$NICK@$inst"
done <<< "$INSTANCES"
```

Запуск:

```bash
chmod +x fedi-find.sh
./fedi-find.sh target
# FOUND @target@fosstodon.org
```

После находки читаем профиль и метаданные, ищем `attachment`-ссылки и `movedTo`.

## Работа с публичным ключом

Каждый актор имеет пару ключей; публичный ключ — стабильный идентификатор. Извлекаем:

```bash
curl -s -H 'Accept: application/activity+json' https://fosstodon.org/users/target \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['publicKey']['publicKeyPem'])"
```

Сравнивая отпечаток ключа между аккаунтами на разных инстансах, можно связать их криптографически — это сильнее, чем совпадение ника.

## Хэштеги и сообщества

Мониторинг сообщества через хэштег:

```bash
curl -s "https://mastodon.social/api/v2/search?q=%23infosec&type=statuses&resolve=true" \
  | python3 -m json.tool | grep -E 'content|published' | head
```

Хэштег-фиды позволяют отслеживать обсуждения темы и выявлять активных участников (кандидатов на дальнейшую разведку). Так Fediverse превращается в источник и профилей, и контекста.

## Ограничения и этика

- **Публичность зависит от настроек видимости.** Не все посты доступны через API.
- **Инстансы банят ботов.** Не злоупотребляйте запросами.
- **Контент может быть чувствительным.** Уважайте приватность даже публичных аккаунтов.
- **Кэш ≠ согласие.** Наличие поста в кэше не делает его «свободным» для публикации.

## Чтение подписчиков и подписок

ActivityPub отдаёт коллекции `following` и `followers` (если не скрыты):

```bash
curl -s -H 'Accept: application/activity+json' \
  "https://fosstodon.org/users/target/following" | python3 -m json.tool | grep -E 'totalItems|href'
```

Список подписок — это **интересы и связи**: на кого человек подписан, кто на него. Пересечение подписок двух аккаунтов — сигнал связи. Для публичных аккаунтов это даёт граф сообщества.

## Экспорт и архивирование

Данные Mastodon легко архивировать для офлайн-анализа:

```bash
# экспорт постов актора в JSONL
curl -s -H 'Accept: application/activity+json' \
  "https://fosstodon.org/users/target/outbox?page=true" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); [print(json.dumps(i)) for i in d.get('orderedItems',[])]" \
  > posts.jsonl
wc -l posts.jsonl
```

Из архива извлекаются даты, упоминания, ссылки и вложения — база для таймлайна и графа.

## Децентрализованные идентификаторы

В Fediverse встречаются **DID** (decentralized identifiers) и `did:web`:

```bash
curl -s "https://example.com/.well-known/did.json" | python3 -m json.tool
```

DID-документ содержит публичные ключи и сервисные эндпоинты — ещё один стабильный идентификатор для корреляции.

## Работа с релеями и поисковыми инстансами

Некоторые инстансы предоставляют «релей» — агрегированный поток постов с многих серверов. Это компенсирует отсутствие глобального поиска:

```bash
# пример: поиск по публичному релею (инстанс-зависимо)
curl -s "https://relay.example/api/v1/statuses?limit=40" | python3 -m json.tool | grep -iE 'content|account'
```

Также существуют индексаторы (например, `fedisearch`), которые собирают публичные посты. Через них можно искать по ключевым словам, не перебирая инстансы вручную. Учтите: индексатор видит только публичные посты и зависит от федерации конкретного инстанса.

## Оценка достоверности профиля

Fediverse-профиль легко подделать (создать аккаунт с похожим ником). Проверяйте:
- **дату регистрации** (`published`) — свежий аккаунт подозрителен;
- **перекрёстные ссылки** на проверяемые сайты;
- **публичный ключ** — совпадает ли с ключом на других платформах;
- **историю постов** — консистентность личности.

Совокупность этих признаков отличает настоящий аккаунт от клона.

## Клиенты и приложения

Разные клиенты Mastodon (Tusky, Elk, Phanpy, официальное приложение) по-разному отображают метаданные профиля. Через веб-клиент инстанса видны все поля профиля и ссылки; через API — полный JSON с ключами. Если профиль отдаёт меньше данных, чем ожидается, проверьте его через `curl` с `Accept: application/activity+json`: часто веб-интерфейс скрывает то, что доступно в API.

## Квиз

```quiz
- question: "Какой протокол лежит в основе Mastodon и Fediverse?"
  options:
    - "SMTP"
    - "ActivityPub"
    - "BitTorrent"
    - "Gopher"
  answer: 1
- question: "Что такое WebFinger в контексте Fediverse?"
  options:
    - "Сканер портов"
    - "Протокол поиска профиля по адресу `acct:user@instance`"
    - "Тип сертификата"
    - "Формат аватара"
  answer: 1
- question: "Какой заголовок нужен, чтобы получить профиль в формате JSON?"
  options:
    - "`Accept: text/html`"
    - "`Accept: application/activity+json`"
    - "`Content-Type: image/png`"
    - "`Authorization: none`"
  answer: 1
- question: "Что означает поле `movedTo` в профиле?"
  options:
    - "Профиль удалён"
    - "Аккаунт мигрировал — цепочка атрибуции"
    - "Профиль приватный"
    - "Это бот"
  answer: 1
- question: "Почему в Fediverse нет глобального поиска?"
  options:
    - "Поиск запрещён"
    - "Это федерация независимых инстансов без единого каталога"
    - "Поиск только платный"
    - "Он есть, но скрыт"
  answer: 1
```

## Где пригодится

- **CTF (OSINT):** в метаданных профиля Mastodon спрятана ссылка к флагу.
- **Расследования:** найти профили в федерации и цепочки миграций.
- **Мониторинг сообществ:** отслеживать хэштеги и обсуждения (infosec, активизм).
- **Threat intelligence:** атрибуция аккаунтов по публичному ключу.
- **Журналистика:** верификация профилей и их истории.
