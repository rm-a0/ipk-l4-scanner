#!/bin/bash

# Configuration
INTERFACE="lo"
TARGET="::1"
TIMEOUT="5000"
TEST_PORT="8080"

echo "=== Comprehensive IPv6 TCP Test ==="
echo "Interface: $INTERFACE, Target: $TARGET"

# 1. Verify system IPv6 support
echo -e "\n[1/5] Checking system IPv6 support..."
if ! test -f /proc/sys/net/ipv6/conf/all/disable_ipv6 || 
   [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" -ne 0 ]; then
    echo "❌ IPv6 is disabled system-wide"
    echo "Try: sudo sysctl net.ipv6.conf.all.disable_ipv6=0"
    exit 1
fi

if ! ip -6 addr show dev $INTERFACE | grep -q inet6; then
    echo "❌ No IPv6 address on $INTERFACE"
    ip -6 addr show
    exit 1
fi

# 2. Check for port conflicts
echo -e "\n[2/5] Checking port availability..."
if ss -6 -tlnp | grep -q ":$TEST_PORT"; then
    echo "⚠️ Port $TEST_PORT already in use:"
    ss -6 -tlnp | grep ":$TEST_PORT"
    read -p "Continue anyway? [y/N] " -n 1 -r
    [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
fi

# 3. Start test server
echo -e "\n[3/5] Starting IPv6 test server..."
cat <<'PYTHON_SERVER' > /tmp/ipv6_test_server.py
import socket, time
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::', 8080))
s.listen(1)
print("Server ready on [::]:8080")
while True:
    conn, addr = s.accept()
    conn.send(b'HTTP/1.1 200 OK\r\n\r\nIPv6 Test Server\n')
    conn.close()
PYTHON_SERVER

python3 /tmp/ipv6_test_server.py &
SERVER_PID=$!
sleep 2  # Wait for server to start

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ Failed to start test server"
    exit 1
fi

# 4. Run scanner test
echo -e "\n[4/5] Running port scan..."
results=$(sudo ../../ipk-l4-scan -i $INTERFACE --pt $TEST_PORT -w $TIMEOUT $TARGET 2>&1)
echo "--- Scanner Output ---"
echo "$results"
echo "---------------------"

# 5. Verification and cleanup
echo -e "\n[5/5] Verifying results..."
kill $SERVER_PID 2>/dev/null
rm -f /tmp/ipv6_test_server.py

if grep -q "$TARGET $TEST_PORT tcp open" <<< "$results"; then
    echo "✅ IPv6 TCP test PASSED"
    echo "::1 8080 tcp open"
    exit 0
else
    echo "❌ IPv6 TCP test FAILED"
    echo "Debug checklist:"
    echo "1. Confirm IPv6 is enabled:"
    echo "   ip -6 addr show dev lo"
    echo "2. Check server was listening:"
    echo "   sudo ss -6 -tlnp | grep 8080"
    echo "3. Test manual connection:"
    echo "   nc -6 -vz ::1 8080"
    echo "4. Check kernel modules:"
    echo "   lsmod | grep ipv6"
    exit 1
fi
