#!/bin/bash

echo "Starting TheHive..."
docker compose -f prod1-thehive/docker-compose.yml up -d

echo "Starting Cortex..."
docker compose -f prod1-cortex/docker-compose.yml up -d

echo "Starting MISP..."
docker compose -f prod1-misp/docker-compose.yml up -d

echo "SOC stack started."