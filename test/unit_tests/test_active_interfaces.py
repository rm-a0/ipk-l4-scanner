import subprocess
import pytest

SCANNER_BINARY = "../../ipk-l4-scan"

def run_process(args):
    """Runs scanner with given arguments and returns stdout output"""
    result = subprocess.run([SCANNER_BINARY] + args, capture_output=True, text=True)
    return result.stdout.strip()

def get_active_interfaces():
    """Fetches the active network interfaces using `ip link show`"""
    result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    interfaces = []

    for line in result.stdout.splitlines():
        # lo is considered as UP
        if "state UP" in line or "lo" in line:
            interface_name = line.split(":")[1].strip().split()[0]

            if interface_name and interface_name != "00":
                interfaces.append(interface_name)

    return interfaces

def disable_enp0s3():
    """Manually disables enp0s3 interfacer using ip link set checks active interfaces and sets enp0s3 back up"""
    # Disable enp0s3
    subprocess.run(["sudo", "ip", "link", "set", "enp0s3", "down"], check=True)

    # Check active interfaces after disabling enp0s3
    active_interfaces_after_disable = get_active_interfaces()

    # Enable enp0s3 again
    subprocess.run(["sudo", "ip", "link", "set", "enp0s3", "up"], check=True)

    return active_interfaces_after_disable

@pytest.mark.parametrize("args, expected_output", [
    # Test case 1: List default active netwrok interfaces
    ([], get_active_interfaces()),

    # Test case 2: Disable enp0s3 down
    # ([], disable_enp0s3()),
])
def test_scanner_output(args, expected_output):
    """Test scanner output for various inputs."""

    # Get the actual output from running the scanner
    output = "\n".join(line.rstrip() for line in run_process(args).splitlines())

    # Convert expected output to a formatted string (i.e., joining list items into a string)
    expected_output = "\n".join(line.rstrip() for line in expected_output)
 
    # Print debug information if there's a mismatch
    if output != expected_output:
        print(f"\nExpected:\n{repr(expected_output)}")
        print(f"\nGot:\n{repr(output)}")

    # Compare the actual output with the expected output
    assert output == expected_output

