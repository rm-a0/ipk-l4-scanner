import subprocess
import pytest

SCANNER_BINARY = "../../ipk-l4-scan"

def run_process(args):
    """Runs scanner with given arguments and returns stdout output"""
    result = subprocess.run([SCANNER_BINARY] + args, capture_output=True, text=True)
    return result.stdout.strip()

@pytest.mark.parametrize("args, expected_output", [
    # Test case 1: Scan a single open TCP port (22)
    (["-i", "eth0", "-t", "22", "localhost"], 
     "Interface: eth0\nTCP Ports: 22\nUDP Ports: \nTimeout: 5000 ms\nTarget: localhost"),

    # Test case 2: Scan multiple TCP ports (22, 23)
    (["--interface", "eth0", "--pt", "22,23", "localhost"], 
     "Interface: eth0\nTCP Ports: 22 23\nUDP Ports: \nTimeout: 5000 ms\nTarget: localhost"),

    # Test case 3: Scan a single UDP port (53)
    (["-i", "eth0", "-u", "53", "localhost"], 
     "Interface: eth0\nTCP Ports: \nUDP Ports: 53\nTimeout: 5000 ms\nTarget: localhost"),

    # Test case 4: Scan multiple UDP ports (53, 67)
    (["-i", "eth0", "--pu", "53,67", "localhost"], 
     "Interface: eth0\nTCP Ports: \nUDP Ports: 53 67\nTimeout: 5000 ms\nTarget: localhost"),

    # Test case 5: Scan both TCP & UDP ports
    (["-i", "eth0", "-t", "22,80", "-u", "53,9999", "localhost"],
     "Interface: eth0\nTCP Ports: 22 80\nUDP Ports: 53 9999\nTimeout: 5000 ms\nTarget: localhost"),

    # Test case 6: Scan with a custom timeout
    (["-i", "eth0", "-t", "80", "-w", "3000", "localhost"], 
     "Interface: eth0\nTCP Ports: 80\nUDP Ports: \nTimeout: 3000 ms\nTarget: localhost"),

    # Test case 7: Scan an IPv6 address
    (["-i", "eth0", "-t", "22", "2001:67c:1220:809::93e5:917"], 
     "Interface: eth0\nTCP Ports: 22\nUDP Ports: \nTimeout: 5000 ms\nTarget: 2001:67c:1220:809::93e5:917"),
])

def test_scanner_output(args, expected_output):
    """Test scanner output for various inputs."""
    output = "\n".join(line.rstrip() for line in run_process(args).splitlines())
    expected_output = "\n".join(line.rstrip() for line in expected_output.splitlines())

    if output != expected_output:
        print(f"\nExpected:\n{repr(expected_output)}")
        print(f"\nGot:\n{repr(output)}")

    assert output == expected_output

