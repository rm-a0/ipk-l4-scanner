#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#include <string>
#include <vector>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct pseudohdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;
};

class TCPScanner {
private:
    int raw_socket;
    std::string interface;
    std::string target_ip;
    std::vector<int> ports;
    int timeout;
    struct iphdr ip_header;
    struct tcphdr tcp_header;

    void createRawSocket(int type);
    bool isIPv4(const std::string &str);
    bool isIPv6(const std::string &str);
    std::string stringToIp(const std::string &str);
    void setupIPv4Header(const std::string &source_ip, const std::string &target_ip);
    void setupTCPHeader(int port);
    uint16_t calculateChecksum(uint16_t* data, int length);
    uint16_t calculateTCPChecksum();

public:
    TCPScanner(const std::string& interface, const std::string& target_ip, 
               const std::vector<int>& ports, int timeout);
    ~TCPScanner();
    void sendPackets();
    void listenForResponses();
};

#endif // TCP_SCANNER_H
