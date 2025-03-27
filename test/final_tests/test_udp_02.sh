#!/bin/bash
# Tests common UDP ports with default interface

INTERFACE=$(ip route | awk '/default/ {print $5}')
TARGET="46.8.8.200"
TIMEOUT="3000"
TEST_PORTS="53,67,123"  # DNS, DHCP, NTP

echo "=== IPv4 UDP Port Scan Test ==="
echo "Interface: $INTERFACE, Target: $TARGET"

# Run scanner
results=$(sudo ../../ipk-l4-scan -i $INTERFACE --pu $TEST_PORTS -w $TIMEOUT $TARGET)
echo "$results"

# Verify output format
if grep -qE "$TARGET [0-9]+ udp open" <<< "$results"; then
    echo "✅ IPv4 UDP test passed"
    exit 0
else
    echo "❌ IPv4 UDP test failed"
    exit 1
fi
