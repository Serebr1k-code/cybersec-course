---
id: mobile-android-aidl
title: 'AIDL-интерфейсы Android: контракт, Parcel и подделка вызова'
category: mobile
parent: mobile-android-ipc-binder
difficulty: hard
order: 2
tags: [android, aidl, parcel, binder, marshalling, ipc]
prerequisites: [mobile-android-bound-service]
useful_for:
  - 'Пентест Android-приложений'
  - 'Аудит IPC'
  - 'CTF Mobile'
estimated_minutes: 42
summary: 'Что генерирует AIDL, как данные превращаются в Parcel и как подделанный вызов обходит проверки на стороне сервиса.'
lab:
  kind: shell
  title: 'Практика: разбери Parcel-контракт'
  toolset: [core, grep]
  workdir: /home/student/task
  files: [task.md, IBalance.aidl, onTransact.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Осмотри файлы: `ls -la`, `cat onTransact.txt`.'
    - 'Сопоставь номер транзакции с методом и его аргументами.'
    - 'Найди флаг рядом с описанием подделанного вызова.'
---

## Вопрос, с которого всё начинается

В прошлом уроке мы вызвали `transfer()` на чужом сервисе. Но откуда клиент знает, в
каком порядке упаковать аргументы и как их прочитать? Ответ — **AIDL**. И тут же
возникает вопрос посложнее: если данные вызова собирает сам клиент, **можно ли собрать
их так, чтобы сервис повёл себя неожиданно?**

## Наш пример: интерфейс из двух методов

Вернёмся к `IBalance`. Разработчик описал его так:

```java
// IBalance.aidl
package com.example.bank;

interface IBalance {
    int getBalance();
    boolean transfer(int amount, String to);
}
```

Это обычное текстовое описание. Никакого кода тут нет — только контракт: имена методов
и типы аргументов. Сборка превращает его в настоящий код.

## Шаг 1: что AIDL генерирует

Компилятор AIDL создаёт файл `IBalance.java` с двумя вложенными классами: `Stub`
(сторона сервиса) и `Proxy` (сторона клиента).

```java
public interface IBalance extends android.os.IInterface {
  public static abstract class Stub extends Binder implements IBalance { ... }
  private static class Proxy implements IBalance {
    public int getBalance() {
      Parcel _data = Parcel.obtain();
      Parcel _reply = Parcel.obtain();
      _data.writeInterfaceToken(DESCRIPTOR);
      mRemote.transact(TRANSACTION_getBalance, _data, _reply, 0);
      int _result = _reply.readInt();
      return _result;
    }
  }
}
```

Видно главное: клиент сам упаковывает аргументы в `Parcel` (`_data`), вызывает
`transact` с номером метода и читает ответ из `_reply`. Контракт — это просто
договорённость о формате буфера.

## Шаг 2: как устроен Parcel

**Parcel** — плоский буфер байт. У него нет схемы: значения пишутся подряд, в том
порядке, в каком их пишет код. `writeInt` кладёт 4 байта, `writeString` — длину и
байты строки. Читающая сторона обязана читать в **точно том же порядке**.

Отсюда два свойства, важных для атаки:

* если клиент прочитал на один `int` меньше — все следующие значения «съедут»;
* `writeInterfaceToken` кладёт имя интерфейса; сервис проверяет его в `onTransact`.

## Шаг 3: сторона сервиса — onTransact

Когда вызов приходит, Binder вызывает `onTransact(code, data, reply, flags)`. Код,
сгенерированный из AIDL, выглядит так:

```java
@Override
public boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
  switch (code) {
    case TRANSACTION_getBalance: {
      data.enforceInterface(DESCRIPTOR);
      int _result = this.getBalance();
      reply.writeInt(_result);
      return true;
    }
    case TRANSACTION_transfer: {
      data.enforceInterface(DESCRIPTOR);
      int amount = data.readInt();
      String to = data.readString();
      boolean _result = this.transfer(amount, to);
      reply.writeBoolean(_result);
      return true;
    }
  }
}
```

`enforceInterface` — та самая проверка имени интерфейса. Она защищает от вызова метода
«не того» интерфейса, но **не проверяет, кто вызывает**. Поэтому любой процесс,
знающий номер транзакции и формат, может отправить свой `Parcel`.

## Шаг 4: собираем вызов вручную

Не будем писать клиент на Java — отправим вызов прямо через `service call`. Это
системная команда, которая сама формирует `transact`:

```bash
$ adb shell service list | grep bank
7   com.example.bank.balance: [com.example.bank.IBalance]
$ adb shell service call com.example.bank.balance 1 i32 100 s16 attacker
Result: Parcel(00000000 00000001   '........')
```

Первый аргумент после имени сервиса — номер транзакции (`1` = `transfer`), дальше —
аргументы в формате `i32`/`s16`. Мы только что инициировали перевод, не имея кода
приложения вообще.

## Шаг 5: подделка типа (type confusion)

Теперь тонкий момент. В `onTransact` для `transfer` ожидается `int`, затем `String`.
Что, если отправить не `int`, а, скажем, число со знаком минус?

```bash
$ adb shell service call com.example.bank.balance 1 i32 -1 s16 attacker
Result: Parcel(00000000 00000001   '........')
```

Отрицательная сумма может означать «списать» вместо «зачислить» — зависит от того, как
написан сервис. Схема буфера не защищает от семантики: AIDL гарантирует порядок байт,
но не то, что значения осмысленны. Проверка диапазона — обязанность сервиса, и её
часто забывают, потому что «UI и так не даёт ввести минус».

## Что мы теперь знаем

- AIDL — это контракт; из него генерируются `Stub` (сервис) и `Proxy` (клиент).
- Данные идут через `Parcel` — плоский буфер без схемы; порядок чтения критичен.
- `enforceInterface` проверяет имя интерфейса, но не личность вызывающего.
- `service call` позволяет собрать вызов руками, без кода приложения.
- Валидация значений (диапазоны, знаки) — на стороне сервиса, не в UI.

## Квиз

Проверь себя.

```quiz
- question: Что описывает файл .aidl?
  options:
    - Реализацию методов
    - Контракт интерфейса: имена методов и типы аргументов
    - Разрешения приложения
    - Список Activity
  answer: 1
  explanation: AIDL — только контракт; код генерируется компилятором.
- question: Что такое Parcel?
  options:
    - Схема базы данных
    - Плоский бинарный буфер без схемы
    - Формат картинок
    - Сетевой пакет
  answer: 1
  explanation: Parcel хранит значения подряд, без описания структуры.
- question: Что проверяет enforceInterface?
  options:
    - Пароль пользователя
    - Имя интерфейса в буфере
    - Размер файла
    - Уровень заряда
  answer: 1
  explanation: Это проверка interface token, а не личности вызывающего.
- question: Чем опасна подделка типа (type confusion)?
  options:
    - Замедляет приложение
    - Значения могут обойти проверки, рассчитанные на UI
    - Ломает экран
    - Меняет иконку
  answer: 1
  explanation: Схема не гарантирует осмысленность; валидация должна быть в сервисе.
- question: Какая команда собирает Binder-вызов вручную?
  options:
    - adb shell am start
    - adb shell service call
    - adb shell pm list
    - adb shell input tap
  answer: 1
  explanation: service call формирует transact с указанными аргументами.
```

## Куда дальше

Мы научились собирать синхронный вызов вручную. В следующем уроке разберём
**Messenger** — асинхронный Binder, где вместо методов ходят `Message`, и увидим, чем
опасны подделка и повтор сообщений. А пока запомни: **AIDL задаёт формат, но не
доверие — доверие должен обеспечить код сервиса**.

## Где пригодится

- **Пентест:** Android, аудит Binder-интерфейсов
- **CTF:** Mobile
- **Работа:** AppSec, ревью AIDL-контрактов
