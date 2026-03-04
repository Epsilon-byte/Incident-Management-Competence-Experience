#!/bin/bash
# =============================================================
# Catnip Games SOC Platform — Service Health Check
# Owner: Platform Reliability
# Usage: bash health_check.sh
# =============================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0

check_http() {
    local name="$1"
    local url="$2"
    local expected="${3:-200}"

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null)

    if [ "$HTTP_CODE" = "$expected" ]; then
        echo -e "${GREEN}[OK]${NC}   ${BOLD}${name}${NC} — HTTP $HTTP_CODE at $url"
        ((PASS++))
    else
        echo -e "${RED}[FAIL]${NC} ${BOLD}${name}${NC} — Expected HTTP $expected, got HTTP $HTTP_CODE at $url"
        ((FAIL++))
    fi
}

check_port() {
    local name="$1"
    local host="$2"
    local port="$3"

    if nc -z -w 3 "$host" "$port" 2>/dev/null; then
        echo -e "${GREEN}[OK]${NC}   ${BOLD}${name}${NC} — port $port open on $host"
        ((PASS++))
    else
        echo -e "${RED}[FAIL]${NC} ${BOLD}${name}${NC} — port $port not reachable on $host"
        ((FAIL++))
    fi
}

echo ""
echo -e "${BOLD}============================================${NC}"
echo -e "${BOLD}  Catnip Games SOC Platform — Health Check ${NC}"
echo -e "${BOLD}  $(date)${NC}"
echo -e "${BOLD}============================================${NC}"
echo ""

echo -e "${BOLD}Core Services:${NC}"
check_http "TheHive UI"       "http://localhost:9000"
check_http "Cortex UI"        "http://localhost:9001"
check_http "Elasticsearch"    "http://localhost:9200" "200"
check_http "Kibana"           "http://localhost:5601" "302"
check_port "MISP"             "localhost" "443"

echo ""
echo -e "${BOLD}Elasticsearch Cluster Health:${NC}"
ES_HEALTH=$(curl -s "http://localhost:9200/_cluster/health" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null || echo "unreachable")
if [ "$ES_HEALTH" = "green" ]; then
    echo -e "${GREEN}[OK]${NC}   Elasticsearch cluster status: green"
    ((PASS++))
elif [ "$ES_HEALTH" = "yellow" ]; then
    echo -e "${YELLOW}[WARN]${NC} Elasticsearch cluster status: yellow (single-node expected)"
    ((PASS++))
else
    echo -e "${RED}[FAIL]${NC} Elasticsearch cluster status: $ES_HEALTH"
    ((FAIL++))
fi

echo ""
echo -e "${BOLD}Backup Directory:${NC}"
if [ -d "/opt/backups" ]; then
    LATEST=$(find /opt/backups -name "*.tar.gz" -o -name "*.sql.gz" 2>/dev/null | sort | tail -1)
    if [ -n "$LATEST" ]; then
        AGE=$(( ( $(date +%s) - $(stat -c %Y "$LATEST") ) / 86400 ))
        if [ "$AGE" -le 1 ]; then
            echo -e "${GREEN}[OK]${NC}   Latest backup: $LATEST (${AGE}d ago)"
            ((PASS++))
        else
            echo -e "${YELLOW}[WARN]${NC} Latest backup is ${AGE} days old: $LATEST"
        fi
    else
        echo -e "${YELLOW}[WARN]${NC} No backups found in /opt/backups"
    fi
else
    echo -e "${YELLOW}[WARN]${NC} Backup directory /opt/backups does not exist"
fi

echo ""
echo -e "${BOLD}============================================${NC}"
echo -e "  Result: ${GREEN}${PASS} passed${NC}  |  ${RED}${FAIL} failed${NC}"
echo -e "${BOLD}============================================${NC}"
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
