#!/usr/bin/env bash
set -euo pipefail

echo "[*] Ensuring shared network exists..."
docker network inspect soc-net >/dev/null 2>&1 || docker network create soc-net

echo "[*] Starting MISP..."
( cd ~/docker/prod1-misp/misp-docker && docker compose up -d )

echo "[*] Starting TheHive..."
( cd ~/docker/prod1-thehive && docker compose up -d )

echo "[*] Testing TheHive -> MISP connectivity..."
docker exec -it thehive bash -lc "getent hosts misp-core >/dev/null && echo 'OK: thehive can resolve misp-core'"

echo
echo "MISP:    https://localhost:8444"
echo "TheHive: http://localhost:9000"
