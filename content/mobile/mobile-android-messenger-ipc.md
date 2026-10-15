---
id: mobile-android-messenger-ipc
title: 'Messenger/Binder-обмен в Android: подделка и повтор сообщений'
category: mobile
parent: mobile-android-ipc-binder
difficulty: hard
order: 3
tags: [android, messenger, handler, message, binder, replay]
prerequisites: [mobile-android-aidl]
useful_for:
  - 'Пентест Android-приложений'
  - 'Аудит IPC'
  - 'CTF Mobile'
estimated_minutes: 40
summary: 'Как сервис общается с клиентом через Messenger и Handler, и почему подделка или повтор Message может обойти логику приложения.'
lab:
  kind: shell
  title: 'Практика: аудит Messenger-обработчика'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, SyncService.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Осмотри файл: `ls -la`, затем `cat SyncService.txt`.'
    - 'Найди команду, которая меняет состояние без проверки вызывающего.'
    - 'Рядом с ней в логе лежит флаг — запиши его в `found.txt`.'
---

## Вопрос, с которого всё начинается

Иногда сервису неудобно отдавать методы напрямую: он хочет общаться **сообщениями** —
асинхронно, как в очереди. Для этого в Android есть `Messenger`. Но если сообщения
может послать любой клиент, то **что мешает послать чужое сообщение или повторить
уже отправленное?** Разберёмся на живом примере.

## Наш пример: сервис синхронизации с Messenger

Приложение держит `SyncService`, который принимает команды через `Messenger`. В
декомпилированном коде видим:

```java
public class SyncService extends Service {
  static final int MSG_SYNC = 1;
  static final int MSG_SET_TOKEN = 2;

  class IncomingHandler extends Handler {
    public void handleMessage(Message msg) {
      switch (msg.what) {
        case MSG_SET_TOKEN:
          token = msg.getData().getString("token");
          break;
        case MSG_SYNC:
          doSync();
          break;
      }
    }
  }
  Messenger messenger = new Messenger(new IncomingHandler());
  public IBinder onBind(Intent i) { return messenger.getBinder(); }
}
```

Сервис принимает два вида сообщений: установку токена и запуск синхронизации. Метода
`onBind` возвращает `messenger.getBinder()` — то есть наружу отдаётся Binder для
отправки сообщений.

## Шаг 1: что такое Message и Messenger

**Message** — это контейнер: поле `what` (номер команды), `arg1`/`arg2` (числа) и
`Bundle data` (произвольные значения). **Messenger** — обёртка над Binder, которая
превращает `send(Message)` в Binder-транзакцию, а на той стороне — в вызов
`Handler.handleMessage`.

Получается мост: клиент шлёт `Message` → Binder → `Handler` сервиса разбирает его в
`switch`. Никаких AIDL-методов вручную писать не нужно — весь маршалинг делает
система.

## Шаг 2: клиент и его conn

Клиент подключается так же, как к любому bound-сервису:

```java
ServiceConnection conn = new ServiceConnection() {
  public void onServiceConnected(ComponentName c, IBinder b) {
    Messenger svc = new Messenger(b);
    Message m = Message.obtain(null, SyncService.MSG_SET_TOKEN);
    Bundle d = new Bundle();
    d.putString("token", "attacker-token");
    m.setData(d);
    try { svc.send(m); } catch (RemoteException e) {}
  }
  public void onServiceDisconnected(ComponentName c) {}
};
```

Мы создали `Message`, положили в `Bundle` свой токен и отправили. Сервис его примет и
запишет как свой. Если у него нет проверки, кто прислал сообщение, — токен подменён.

## Шаг 3: почему это проходит

Обрати внимание: `MSG_SET_TOKEN` меняет состояние сервиса. В коде `handleMessage` нет
ни одной проверки вызывающего — ни `checkCallingPermission`, ни `Binder.getCallingUid`.
Сервис считает, что раз он экспортирован «для своего приложения», то и сообщения
приходят только от него.

Но Binder не различает «своих» и «чужих»: раз `onBind` вернул Binder, его получит
любой клиент, который смог подключиться.

## Шаг 4: повтор сообщения (replay)

Даже если сервис проверяет токен, у Messenger есть вторая слабость — **повтор**. В
сообщении нет встроенного счётчика или nonce. Поэтому перехваченное (или ранее
записанное) сообщение можно отправить ещё раз:

```java
// отправили MSG_SYNC сто раз
for (int i = 0; i < 100; i++) svc.send(Message.obtain(null, SyncService.MSG_SYNC));
```

Если синхронизация запускает операцию со побочным эффектом (списание, отправка), её
повтор — уже атака. Защита здесь та же, что в сетевых протоколах: одноразовое значение
в `Bundle`, которое сервис проверяет и «гасит» после использования.

## Шаг 5: как искать такое в реальном APK

Маркеры Messenger-сервиса ищутся по коду:

```bash
$ grep -rn "new Messenger" bank/smali* | head
bank/smali/com/example/bank/SyncService.smali
$ grep -n "getCallingUid\|checkCalling" bank/smali/com/example/bank/SyncService.smali
(пусто)
```

Пустой второй grep — тревожный знак: сервис не проверяет вызывающего. Дальше смотрим,
какие `MSG_*` меняют состояние, и пробуем их отправить.

## Шаг 6: replyTo и обратный канал

У `Message` есть поле `replyTo` — это `Messenger` отправителя, по которому получатель
может ответить. Это и есть обратный канал: клиент шлёт запрос, сервис отвечает ему по
указанному `replyTo`.

```java
Messenger myReply = new Messenger(new Handler(Looper.getMainLooper()) {
  public void handleMessage(Message msg) {
    Log.d("attack", "service replied: " + msg.getData().getString("result"));
  }
});
Message m = Message.obtain(null, SyncService.MSG_SYNC);
m.replyTo = myReply;      // подсовываем свой обратный канал
svc.send(m);
```

Если сервис без проверки отправляет по `replyTo` чувствительные данные (токен,
результат операции, список файлов), они уйдут атакующему. Здесь важно, что сервис
доверяет полю из сообщения — а поле полностью контролирует клиент.

Вторая слабость — **исчерпание очереди**. `Handler` обрабатывает сообщения по одному;
если завалить сервис тысячами `MSG_SYNC`, очередь забьётся, а полезная работа встанет.
Это отказ в обслуживании на ровном месте, без единой уязвимости памяти.

## Если не сработало

* Сервис не экспортирован — тот же приём, что и с bound-сервисом: ищи посредника.
* `handleMessage` проверяет `Binder.getCallingUid()` — тогда подделка сообщения не
  пройдёт, и остаётся только replay, если нет nonce.
* Сообщения с неизвестным `what` просто игнорируются — сверь константы `MSG_*` в
  декомпилированном коде: возможно, ты шлёшь не тот номер команды.

## Что мы теперь знаем

- `Messenger` превращает `send(Message)` в Binder-вызов `Handler.handleMessage`.
- Поле `what` — номер команды; `Bundle` несёт произвольные данные.
- Если `handleMessage` не проверяет вызывающего, состояние сервиса можно подменить.
- В сообщении нет счётчика, поэтому replay — отдельный вектор.
- Ищем `new Messenger` и отсутствие `checkCallingPermission` в декомпилированном коде.

## Квиз

Проверь себя.

```quiz
- question: Что делает Messenger.send(Message)?
  options:
    - Пишет в лог
    - Отправляет Binder-транзакцию, превращающуюся в handleMessage
    - Открывает Activity
    - Читает файл
  answer: 1
  explanation: Messenger — обёртка над Binder: сообщение доходит до Handler получателя.
- question: Где живёт номер команды в Message?
  options:
    - В поле what
    - В Bundle
    - В arg1
    - В replyTo
  answer: 0
  explanation: what — целочисленный код команды, по нему идёт switch.
- question: Почему подделка сообщения возможна?
  options:
    - Messenger медленный
    - Сервис не проверяет вызывающего
    - Binder шифруется
    - Bundle сжат
  answer: 1
  explanation: Если нет checkCallingUid/Permission, любой подключившийся клиент шлёт свои сообщения.
- question: Чем опасен replay в Messenger?
  options:
    - Расходует батарею
    - Повторяет побочный эффект команды
    - Ломает Binder
    - Меняет тему
  answer: 1
  explanation: Без nonce/счётчика перехваченное сообщение можно воспроизвести повторно.
- question: Что искать в декомпилированном коде?
  options:
    - new Messenger и отсутствие проверки вызывающего
    - Только строки
    - Иконки
    - Размер APK
  answer: 0
  explanation: Messenger + пустой grep по checkCalling — типичный признак незащищённого IPC.
```

## Куда дальше

Мы закрыли Binder-триаду: bound-сервис, AIDL, Messenger. Дальше логично вернуться к
поверхностям данных и посмотреть, что ещё приложение отдаёт наружу — `ContentProvider`
и гранты URI. А пока запомни: **Messenger — это те же Binder-вызовы; если в
`handleMessage` нет проверки вызывающего, состояние сервиса принадлежит атакующему**.

## Где пригодится

- **Пентест:** Android, аудит IPC
- **CTF:** Mobile
- **Работа:** AppSec, ревью сервисов
