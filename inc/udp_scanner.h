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

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t udp_length;
};

struct pseudo_header6 {
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    uint32_t udp_length;
    uint8_t zero[3];
    uint8_t next_header;
};

class UDPScanner {
private:
    bool is_ipv6;
    int udp_socket;
    int icmp_socket;
    std::string interface_name;
    std::string interface_ip;
    std::string target_ip;
    std::vector<int> ports;
    std::set<int> pending_ports;
    int timeout;
    struct udphdr udp_header;

    void createUDPSocket(int type);
    void createICMPSocket(int type);
    void processUDPResponse();
    void processICMPResponse();
    void setupUDPHeader(int port);
    uint16_t calculateUDP4Checksum();
    uint16_t calculateUDP6Checksum();
public:
    UDPScanner(const std::string& interface, const std::string& target, 
               const std::vector<int>& ports, int timeout);
    ~UDPScanner();
    void sendPackets();
    void listenForResponses();
};

#endif // UDP_SCANNER_H
