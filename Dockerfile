# Build stage
FROM golang:1.23 AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

# Install migration tool (example: golang-migrate)
RUN curl -L https://github.com/golang-migrate/migrate/releases/download/v4.16.2/migrate.linux-amd64.tar.gz | tar xvz && \
    mv migrate /usr/local/bin/migrate

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main ./cmd/server

# Run stage
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y ca-certificates curl netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Copy migrate tool from builder stage
COPY --from=builder /usr/local/bin/migrate /usr/local/bin/migrate

RUN useradd -m appuser

WORKDIR /app

COPY --from=builder /app/main .
COPY --from=builder /app/db/migrations ./db/migrations
COPY app.env .
COPY local.yaml .
COPY start.sh .

RUN chmod +x start.sh

USER appuser

EXPOSE 5002

CMD ["./start.sh"]