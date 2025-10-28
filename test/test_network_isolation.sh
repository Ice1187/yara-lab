#!/bin/bash
# Test network isolation for YARA platform
# Verifies that scanner cannot access internet but API can

echo "=========================================="
echo "Testing Network Isolation"
echo "=========================================="
echo ""

# Check if containers are running
echo "1. Checking container status..."
docker compose ps
echo ""

# Test API container internet access
echo "2. Testing API container internet access..."
API_RESULT=$(docker compose exec -T api ping -c 2 -W 2 8.8.8.8 2>&1)
if echo "$API_RESULT" | grep -q "2 received"; then
    echo "✓ API container CAN access internet (expected)"
else
    echo "✗ API container CANNOT access internet (unexpected)"
fi
echo ""

# Test scanner container internet access (should fail)
echo "3. Testing scanner container internet access..."
SCANNER_RESULT=$(docker compose exec -T scanner ping -c 2 -W 2 8.8.8.8 2>&1)
if echo "$SCANNER_RESULT" | grep -q "Network is unreachable\|Operation not permitted\|0 received"; then
    echo "✓ Scanner container CANNOT access internet (expected - isolated!)"
else
    echo "✗ Scanner container CAN access internet (unexpected - security issue!)"
fi
echo ""

# Test API can reach scanner
echo "4. Testing API -> Scanner communication..."
API_TO_SCANNER=$(docker compose exec -T api ping -c 2 -W 2 scanner 2>&1)
if echo "$API_TO_SCANNER" | grep -q "2 received"; then
    echo "✓ API can communicate with Scanner (expected)"
else
    echo "✗ API cannot communicate with Scanner (unexpected)"
fi
echo ""

echo "=========================================="
echo "Network Isolation Test Complete"
echo "=========================================="

