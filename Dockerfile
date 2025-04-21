# Build stage
FROM golang:1.23 AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main ./cmd/server

# Run stage
FROM debian:bullseye-slim

RUN useradd -m appuser

WORKDIR /app

COPY --from=builder /app/main .
COPY app.env .
COPY local.yaml .

USER appuser

EXPOSE 5002

CMD ["./main"]