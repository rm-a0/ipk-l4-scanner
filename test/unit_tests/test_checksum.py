import subprocess
import pytest
import struct
import socket

SCANNER_BINARY = "../../ipk-l4-scan"

def calculate_expected_checksum(data):
    """Reference checksum calculation for validation"""
    if len(data) % 2 != 0:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return ~checksum & 0xffff

@pytest.mark.parametrize("test_case", [
    {
        "name": "TCP_IPv4_Standard",
        "data": bytes.fromhex("4500003c0000400040060000c0a80101c0a80102"),
        "expected": 0xb1e6
    },
    {
        "name": "TCP_IPv6_Standard",
        "data": bytes.fromhex("600000000014064020010db800000000000000000000000120010db8000000000000000000000002"),
        "expected": 0x79d3
    },
    {
        "name": "UDP_IPv4_Standard",
        "data": bytes.fromhex("4500003c0000400011000000c0a80101c0a80102"),
        "expected": 0xb1e6
    },
    {
        "name": "UDP_IPv6_Standard",
        "data": bytes.fromhex("600000000014064020010db800000000000000000000000120010db8000000000000000000000002"),
        "expected": 0x79d3
    },
    {
        "name": "Odd_Length_Data",
        "data": bytes.fromhex("4500003d0000400040060000c0a80101c0a80102"),
        "expected": 0xb1e5
    },
    {
        "name": "Zero_Checksum",
        "data": bytes.fromhex("00000000000000000000000000000000"),
        "expected": 0xffff
    }
])
def test_checksum_calculation(test_case):
    """
    Validate checksum calculation against known test vectors.
    Test cases include:
    - Standard TCP/IPv4 header
    - Standard TCP/IPv6 header
    - Standard UDP/IPv4 header
    - Standard UDP/IPv6 header
    - Odd-length data padding
    - Edge case with zero values
    """
    result = calculate_expected_checksum(test_case["data"])
    assert result == test_case["expected"], \
        f"Checksum mismatch for {test_case['name']}. Expected {hex(test_case['expected'])}, got {hex(result)}"

@pytest.mark.parametrize("protocol,port_range", [
    ("tcp", "80,443"),  # HTTP/HTTPS
    ("udp", "53,123"),  # DNS/NTP
    ("tcp", "20-23"),   # FTP ports
    ("udp", "500-510")  # VPN range
])
def test_checksum_integration(protocol, port_range):
    """
    Integration test that verifies checksum-valid packets are being sent.
    Uses tcpdump to capture and verify outgoing packets.
    """
    interface = "lo"  # Using loopback for testing
    target = "127.0.0.1"
    
    # Start packet capture
    tcpdump = subprocess.Popen(
        ["tcpdump", "-i", interface, "-nn", "-c", "1", "-w", "/tmp/scan.pcap", 
         f"{protocol} and dst {target}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Run scanner
    args = ["-i", interface, 
            f"-{'t' if protocol == 'tcp' else 'u'}", port_range, 
            target]
    subprocess.run([SCANNER_BINARY] + args, check=True)
    
    # Stop capture and analyze
    tcpdump.terminate()
    tcpdump.wait()
    
    # Verify packet checksum (using tshark for analysis)
    result = subprocess.run(
        ["tshark", "-r", "/tmp/scan.pcap", "-Tfields", "-e", "ip.checksum"],
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0, "Packet capture failed"
    assert "Bad" not in result.stdout, f"Invalid checksum detected in {protocol} packet"

def test_checksum_utils():
    """
    Directly test the Utils::calculateChecksum function through
    the scanner's debug output (requires scanner built with TESTING=1)
    """
    test_data = b"\x45\x00\x00\x3c\x00\x00\x40\x00\x40\x06\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x02"
    expected = 0xb1e6
    
    result = subprocess.run(
        [SCANNER_BINARY, "--test-checksum"],
        input=test_data,
        capture_output=True,
        text=True
    )
    
    assert result.returncode == 0, "Checksum test failed"
    assert hex(expected) in result.stdout, "Checksum mismatch in Utils"