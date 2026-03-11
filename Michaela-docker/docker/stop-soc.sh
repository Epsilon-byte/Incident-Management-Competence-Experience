#!/bin/bash

echo "Stopping TheHive..."
docker compose -f prod1-thehive/docker-compose.yml down

echo "Stopping Cortex..."
docker compose -f prod1-cortex/docker-compose.yml down

echo "Stopping MISP..."
docker compose -f prod1-misp/docker-compose.yml down

echo "SOC stack stopped."