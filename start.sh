#!/bin/bash
set -e

# Read database configuration from env or yaml file
CONTAINER_DB_URL=$(grep "CONTAINER_DB_URL" app.env | cut -d '=' -f2- | tr -d '\r')
if [ -z "$CONTAINER_DB_URL" ]; then
    # If not found in app.env, try getting it from local.yaml
    CONTAINER_DB_URL=$(grep -A 1 "database:" local.yaml | grep "url" | cut -d ':' -f2- | xargs)
fi

if [ -n "$CONTAINER_DB_URL" ]; then
    echo "running database migrations..."
    migrate -path ./db/migrations -database "$CONTAINER_DB_URL" up
else
    echo "warning: CONTAINER_DB_URL not found in configuration files"
fi

echo "starting the application..."
exec ./main