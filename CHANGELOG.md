# CHANGELOG

## [1.0.0] - 2025.03.27
### Implemented Functionality  
- **TCP and UDP Scanning**: Supports scanning for open/closed/filtered ports on both TCP and UDP protocols.  
- **Flexible Port Ranges**: Allows specifying individual ports or ranges (e.g., `-t 1,2-10,11,12-18`).  
- **Interface and IP Address Support**: The interface argument accepts either a network interface name or an IP address.  
- **Automatic IP Version Selection**: Determines whether to use IPv4 or IPv6 based on the format of the provided address.  
- **Custom Timeout Settings**: Allows users to define timeout values for port response.  

### Known Limitations  
- **Inconsistent IPv6 Support**: IPv6 scanning may behave differently across various systems due to network stack differences and system-specific configurations. Some machines may experience unreliable detection or incomplete scanning results.  
- **Limited UDP Detection:** UDP scanning relies on response behavior, which varies by service. Since many UDP services do not respond to closed port probes, accurate detection can be challenging. Additionally, due to automated test constraints, the scanner assumes a port is open if no response is received within the timeout period, which may lead to false positives.
- **Permission Requirements**: Raw socket creation requires elevated permissions (`sudo`).  
