#ifndef UDP_SCANNER_H
#define UDP_SCANNER_H

#include <string>
#include <vector>
#include <set>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

class UDPScanner {
private:
    int udp_socket;
    int icmp_socket;
    std::string interface_name;
    std::string interface_ip;
    std::string target_ip;
    std::vector<int> ports;
    std::set<int> pending_ports;
    int timeout;

public:
    UDPScanner(const std::string& interface, const std::string& target, 
               const std::vector<int>& ports, int timeout);
    ~UDPScanner();
    void sendPackets();
    void listenForResponses();
};

#endif // UDP_SCANNER_H
