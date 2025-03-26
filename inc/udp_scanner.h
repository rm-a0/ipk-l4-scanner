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

    /**
     * @brief Creates UDP socket for scanning
     * @param type Either AF_INET for IPv4 or AF_INET6
     * @return Void
     */
    void createUDPSocket(int type);

    /**
     * @brief Creates ICMP socket for response capture 
     * @param type Either AF_INET for IPv4 or AF_INET6
     * @return Void
     */
    void createICMPSocket(int type);

    /**
     * @brief Sets up UDP header
     * @param port Specific port
     * @return void
     */
    void setupUDPHeader(int port);

    /**
     * @brief Calculates checksum for UDP header (IPv4 version)
     * @return Calculated checksum
     */
    uint16_t calculateUDP4Checksum();

    /**
     * @brief Calculates checksum for UDP header (IPv6 version)
     * @return Calculated checksum
     */
    uint16_t calculateUDP6Checksum();
public:
    /**
     * @brief Constructor for UDPScanner class
     * @param interface Name of the interface
     * @param target Name or IP of the target
     * @param ports Ports to be scanned
     * @param timeout Timeout in ms
     */
    UDPScanner(const std::string& interface, const std::string& target, 
               const std::vector<int>& ports, int timeout);

    /**
     * @brief Destructor for UDPScanner class
     */
    ~UDPScanner();
    /**
     * @brief Sends packets to all ports
     * @return Void
     */
    void sendPackets();

    /**
     * @brief Listens to responses from ports and output their states
     * @return Void
     */
    void listenForResponses();
};

#endif // UDP_SCANNER_H
