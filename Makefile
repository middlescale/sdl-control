APP_NAME=sdl-control
ADMIN_APP_NAME=sdl-admin
VERSION ?= dev
GO_FILES=$(shell find . -name '*.go' -not -path "./vendor/*")
PROTO_DIR=proto
PROTO_FILES=$(wildcard $(PROTO_DIR)/*.proto)
GEN_GO_DIR=protocol/pb

.PHONY: all build run clean cert proto migrate-schema

all: build

build:
	go build -ldflags "-X main.Version=$(VERSION)" -o $(APP_NAME) main.go
	go build -o $(ADMIN_APP_NAME) ./cmd/sdl-admin

run:
	./$(APP_NAME)

migrate-schema: build
	DATABASE_URL="$(DATABASE_URL)" ./$(APP_NAME) migrate

clean:
	rm -f $(APP_NAME)
	rm -f $(ADMIN_APP_NAME)

cert:
	@echo "证书由 autocert 自动管理，无需手动生成。"

# 编译 proto 文件为 Go 代码
proto:
	mkdir -p $(GEN_GO_DIR)
	cd $(PROTO_DIR) && protoc --go_out=../$(GEN_GO_DIR) --go_opt=paths=source_relative --go-grpc_out=../$(GEN_GO_DIR) --go-grpc_opt=paths=source_relative *.proto
