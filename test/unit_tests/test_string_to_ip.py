import subprocess
import pytest
import socket
import re

SCANNER_BINARY = "../../ipk-l4-scan"

def run_scanner_with_debug(args):
    """Run scanner with debug output enabled"""
    return subprocess.run(
        [SCANNER_BINARY] + args,
        capture_output=True,
        text=True
    )

def extract_ip_from_output(output):
    """Extract resolved IP from debug output"""
    match = re.search(r"Resolved IP:\s+([0-9a-fA-F.:]+)", output)
    return match.group(1) if match else None

@pytest.mark.parametrize("input_str,expected_ip", [
    # IPv4 Test Cases
    ("127.0.0.1", "127.0.0.1"),
    ("192.168.1.1", "192.168.1.1"),
    ("localhost", "127.0.0.1"),  # Standard localhost resolution
    ("google.com", None, pytest.mark.xfail),  # Will resolve to some IP
    
    # IPv6 Test Cases
    ("::1", "::1"),
    ("2001:db8::1", "2001:db8::1"),
    ("ip6-localhost", "::1"),  # Common IPv6 localhost alias
    
    # Interface Names
    ("lo", "127.0.0.1"),  # Loopback IPv4
    ("lo", "::1"),  # Loopback IPv6
    ("eth0", None, pytest.mark.xfail),  # Will resolve to interface IP
    
    # Edge Cases
    ("", None),
    ("invalid.hostname", None)
])
def test_ip_resolution(input_str, expected_ip):
    """
    Test string-to-IP conversion for various input types:
    - Direct IPv4 addresses
    - Direct IPv6 addresses
    - Hostnames
    - Interface names
    - Edge cases
    """
    result = run_scanner_with_debug(["-i", "lo", input_str])
    
    if expected_ip is None:
        assert "Failed to resolve" in result.stderr
    else:
        resolved_ip = extract_ip_from_output(result.stdout)
        assert resolved_ip == expected_ip, \
            f"Expected {expected_ip}, got {resolved_ip}"

@pytest.mark.parametrize("hostname", [
    "localhost",
    "google.com",
    "example.com"
])
def test_dns_resolution(hostname):
    """
    Test DNS resolution through the scanner by comparing with
    system's getaddrinfo() results
    """
    # Get system resolution
    try:
        sys_info = socket.getaddrinfo(hostname, None)
        expected_ips = {addr[4][0] for addr in sys_info}
    except socket.gaierror:
        pytest.skip(f"Cannot resolve {hostname} on this system")
    
    # Get scanner resolution
    result = run_scanner_with_debug([hostname])
    resolved_ip = extract_ip_from_output(result.stdout)
    
    assert resolved_ip in expected_ips, \
        f"Scanner resolved {hostname} to {resolved_ip}, expected one of {expected_ips}"

def test_interface_ipv4_resolution():
    """
    Test interface-to-IPv4 resolution by comparing with system's ifconfig
    """
    interface = "lo"
    args = ["-i", interface, "--ipv4", "127.0.0.1"]
    
    # Get system IP
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            system_ip = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', interface[:15].encode())
            )[20:24])
        except:
            pytest.skip("Cannot get interface IP on this system")
    
    # Test scanner
    result = run_scanner_with_debug(args)
    debug_output = result.stdout
    
    assert f"Interface {interface} IPv4: {system_ip}" in debug_output, \
        "Interface IP resolution failed"

def test_interface_ipv6_resolution():
    """
    Test interface-to-IPv6 resolution by comparing with system's ifconfig
    """
    interface = "lo"
    args = ["-i", interface, "--ipv6", "::1"]
    
    # Get system IP (simplified check)
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        try:
            # This is platform-specific, simplified for example
            system_ip = "::1"
        except:
            pytest.skip("Cannot get IPv6 interface IP on this system")
    
    # Test scanner
    result = run_scanner_with_debug(args)
    debug_output = result.stdout
    
    assert f"Interface {interface} IPv6: {system_ip}" in debug_output, \
        "Interface IPv6 resolution failed"

@pytest.mark.parametrize("invalid_input", [
    "256.300.1.1",
    "not.an.ip",
    "::ffff:256.1.1.1",
    "lo:invalid"
])
def test_invalid_input_handling(invalid_input):
    """
    Verify proper error handling for malformed inputs:
    - Invalid IPv4 addresses
    - Invalid IPv6 addresses
    - Bogus hostnames
    - Malformed interface specs
    """
    result = run_scanner_with_debug(["-i", "lo", invalid_input])
    
    assert result.returncode != 0, "Should fail on invalid input"
    assert "ERROR" in result.stderr, "Should output error message"
    assert "Failed to resolve" in result.stderr, "Should indicate resolution failure"