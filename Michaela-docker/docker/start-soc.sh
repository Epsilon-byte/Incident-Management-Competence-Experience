#!/bin/bash
set -e

cd "$(dirname "$0")"

if ! docker network inspect hive-network >/dev/null 2>&1; then
  echo "Creating external Docker network: hive-network"
  docker network create hive-network
fi

echo "Starting TheHive..."
docker compose -f prod1-thehive/docker-compose.yml up -d

echo "Starting Cortex..."
docker compose -f prod1-cortex/docker-compose.yml up -d

echo "Starting MISP..."
docker compose -f prod1-misp/docker-compose.yml up -d

echo "SOC stack started."