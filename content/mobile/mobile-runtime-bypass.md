---
id: mobile-runtime-bypass
title: "Обход runtime-защит"
category: mobile
parent: mobile-dynamic-frida
difficulty: medium
order: 1
tags: [mobile, ssl-pinning, root-detection, bypass]
prerequisites: [mobile-dynamic-frida]
useful_for:
  - "CTF: Mobile"
  - "Bug bounty: мобильные API"
  - "Пентест: динамический анализ"
estimated_minutes: 12
summary: "Этап обхода SSL-пиннинга и root/anti-Frida детекта."
---

Этот урок — **этап-навигатор** в ветке. Он короткий: его задача — объяснить, что вы будете изучать на этом этапе, почему темы идут именно в таком порядке и что вы сможете делать после прохождения.

## О чём этот этап

Второй этап динамики — про преодоление защит. Вы обойдёте SSL pinning, чтобы перехватить HTTPS, и root-детект с anti-Frida/anti-debug, чтобы получить контроль над процессом.

## Что вы освоите

- Обход SSL Pinning: перехват HTTPS-трафика
- Обход root-детекта и anti-Frida/anti-debug
- Методично снимать защиты в рантайме

## Как проходить

Сначала SSL pinning (без него не увидеть API), затем root/anti-Frida. Держите несколько техник обхода: Frida-скрипты, патч APK, Magisk/Zygisk.

## Квиз

```quiz
- question: "Зачем обходить SSL pinning?"
  options:
    - "Чтобы перехватить и изменить HTTPS-трафик"
    - "Чтобы ускорить приложение"
    - "Чтобы сжать данные"
    - "Чтобы сменить сертификат сервера"
  answer: 0
  explanation: "Pinning мешает MITM-прокси; его обход открывает трафик."
- question: "Что проверяет root-детект?"
  options:
    - "Наличие root/изменённой среды"
    - "Скорость сети"
    - "Версию Android"
    - "Размер APK"
  answer: 0
  explanation: "Приложение отказывается работать на скомпрометированном устройстве."
- question: "Какой инструмент помогает прятать root от приложения?"
  options:
    - "Magisk/Zygisk"
    - "jadx"
    - "binwalk"
    - "nmap"
  answer: 0
  explanation: "Magisk со Zygisk скрывает следы root от выбранных приложений."
```

## Где пригодится

- **CTF:** Mobile
- **Bug bounty:** мобильные API
- **Пентест:** динамический анализ
