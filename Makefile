SERVICE_NAME=bmt_user 
DB_URL=postgres://postgres:anhiuemlove33@127.0.0.1:5432/bmt_user?sslmode=disable

run:
	go run .\cmd\server\main.go

migrate_up:
	migrate -path ./db/migrations -database "$(DB_URL)" -verbose up
migrate_down:
	migrate -path ./db/migrations -database "$(DB_URL)" -verbose down

sqlc:
	sqlc generate

wire:
	wire ./internal/injectors/

.PHONY: run	migrate_up migrate_down slqc wire
