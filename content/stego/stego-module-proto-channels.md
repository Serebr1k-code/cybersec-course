---
id: stego-module-proto-channels
title: "Модуль: Сетевые протоколы как covert-каналы (TLS, IPv6, gRPC, WebSocket)"
category: stego
parent: stego-network
difficulty: medium
order: 5
tags: [stego, roadmap, tls, ipv6, grpc, protobuf, websocket, covert-channel]
prerequisites: [stego-network]
useful_for:
  - "CTF Stego: задачи на сетевых дампах"
  - "Планирование порядка изучения стеганографии"
estimated_minutes: 8
summary: "Навигационный модуль по сетевым covert-каналам: TLS (расширения ClientHello), IPv6 (extension headers), gRPC/protobuf (varint и поля) и WebSocket (маскированные фреймы). В каждом — «поле», которое получатель не проверяет."
---

## Зачем этот модуль

Уроки про сеть объясняли HTTP-заголовки, ICMP и тайминги. Но современный трафик —
это TLS, IPv6, gRPC и WebSocket. У них другие структуры, и «лишние» поля в них почти
никто не смотрит: TLS шифрует полезную нагрузку, но заголовки и расширения — открыты;
IPv6-заголовок полон расширяемых опций; protobuf допускает неизвестные поля;
WebSocket-фреймы маскируются, но маска не мешает разбору.

## Что разберём

- **stego-tls** — расширения ClientHello, SNI, session ticket; что видно без ключей.
- **stego-ipv6-header** — extension headers и опции; произвольные option-типы.
- **stego-grpc-protobuf** — varint, теги полей, неизвестные поля как носитель.
- **stego-websocket** — фреймы, маскирование, длина payload.

## Как проходить

По порядку. В каждом уроке — конкретный байтовый дамп (ClientHello, IPv6-пакет,
protobuf-сообщение, WS-фрейм), который разбирается вручную. Готовые инструменты
(Wireshark, `tshark`, `protoc`) показываются, но закладку ты достаёшь сам.

## Что вы будете уметь

- Читать TLS ClientHello и его расширения.
- Разбирать IPv6 extension headers и опции.
- Декодировать protobuf varint и поля.
- Снимать маску WebSocket и читать payload.
