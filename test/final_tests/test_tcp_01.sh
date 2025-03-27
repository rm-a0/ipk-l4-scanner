#!/bin/bash

# Configuration
INTERFACE="lo"
TARGET="localhost"
TIMEOUT="2000"
TEST_PORTS="21,22,80,8000"

manage_port() {
    case $1 in
        "open")
            python3 -m http.server 8000 &>/dev/null &
            echo $! > /tmp/test_server.pid
            ;;
        "closed")
            kill $(lsof -ti :21) 2>/dev/null || true
            ;;
        "cleanup")
            kill $(cat /tmp/test_server.pid 2>/dev/null) 2>/dev/null || true
            rm -f /tmp/test_server.pid
            ;;
    esac
}

test_tcp_scan() {
    echo "=== TCP Port Scanning Test (open server on port 8000) ==="
    echo "Configuring test environment..."
    
    manage_port "open"
    manage_port "closed"
    
    declare -A expected=(
        ["21"]="closed"
        ["22"]="closed"
        ["80"]="closed"
        ["8000"]="open"
    )
    
    echo "Executing scan..."
    results=$(sudo ../../ipk-l4-scan -i $INTERFACE --pt $TEST_PORTS -w $TIMEOUT $TARGET)
    echo "Scanner output:"
    echo "$results"
    
    echo -e "\nVerifying results..."
    failures=0
    while read -r line; do
        # Correct parsing for IP PORT PROTOCOL STATUS format
        port=$(echo $line | awk '{print $2}')
        status=$(echo $line | awk '{print $4}')
        
        if [[ ${expected[$port]} == "$status" ]]; then
            echo "✓ Port $port: $status (expected)"
        else
            echo "✗ Port $port: $status (expected ${expected[$port]})"
            ((failures++))
        fi
    done <<< "$(echo "$results" | grep 'tcp')"
    
    manage_port "cleanup"
    
    if [ $failures -eq 0 ]; then
        echo "✅ All TCP tests passed"
        return 0
    else
        echo "❌ $failures TCP tests failed"
        return 1
    fi
}

test_tcp_scan
exit $?
