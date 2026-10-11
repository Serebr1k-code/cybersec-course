# ==================================================================
#  CTF Learning Tree — Makefile
#  Go-бэкенд (stdlib) + Vue 3 / Vite SPA + markdown-уроки.
#
#  make            — собрать фронтенд и бэкенд (по умолчанию)
#  make run        — собрать фронт и запустить сервер на :8090
#  make dev        — dev-режим: бэкенд :8090 + Vite :5173
#  make help       — список целей
# ==================================================================

GO      ?= go
NPM     ?= npm
BIN     ?= bin/learningtree
PORT    ?= 8090
CONTENT ?= content
DATA    ?= data

# Проект — чистый stdlib-сервер, cgo не нужен. Отключаем его по умолчанию,
# иначе сборка падает в окружениях без libc-заголовков (gcc не находит
# stdint.h/errno.h и т.п.).
CGO_ENABLED ?= 0
export CGO_ENABLED

# Серверные переменные окружения (см. README -> Конфигурация).
SERVER_ENV = PORT=$(PORT) CONTENT_DIR=$(CONTENT) DATA_DIR=$(DATA)

.PHONY: all build run dev frontend backend clean distclean test fmt vet help

all: build

## build: собрать фронтенд и скомпилировать бэкенд
build: frontend backend

## frontend: установить зависимости и собрать SPA в frontend/dist
frontend:
	cd frontend && $(NPM) install && $(NPM) run build

## backend: скомпилировать сервер в bin/learningtree
backend:
	$(GO) build -o $(BIN) ./cmd/server

## run: собрать фронтенд и запустить сервер на :8090
run: frontend
	$(SERVER_ENV) $(GO) run ./cmd/server

## dev: бэкенд (:8090) и Vite dev-сервер (:5173) параллельно (Ctrl-C — стоп обоим)
dev:
	@echo "dev: бэкенд http://localhost:$(PORT) + vite http://localhost:5173"
	@trap 'kill 0' INT TERM; \
	( $(SERVER_ENV) $(GO) run ./cmd/server & \
	  cd frontend && $(NPM) run dev ) ; \
	wait

## test: go-тесты + фронтенд-тесты + валидатор контента
test:
	$(GO) test ./...
	cd frontend && $(NPM) run test
	$(GO) run ./tools/quizvalidate -content ./content

## fmt: gofmt по всему модулю
fmt:
	$(GO) fmt ./...

## vet: go vet по всему модулю
vet:
	$(GO) vet ./...

## clean: удалить артефакты сборки (bin/ и frontend/dist/)
clean:
	rm -rf bin frontend/dist
	@echo "Очищено: bin/ frontend/dist/"

## distclean: clean + удалить node_modules и data
distclean: clean
	rm -rf frontend/node_modules data
	@echo "Очищено: bin/ frontend/dist/ frontend/node_modules/ data/"

## help: показать этот список целей
help:
	@echo "Доступные цели:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
