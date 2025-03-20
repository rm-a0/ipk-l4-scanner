#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#include <string>
#include <vector>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

/**
 * @struct pseudohdr
 * @brief This structure is used for calculating TCP checksum
 */
struct pseudohdr {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_len;
};

/**
 * @struct pseudohdr6
 * @brief This structure is used for calculating TCP checksum
 */
struct pseudohdr6 {
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    uint32_t tcp_len;
    uint8_t reserved[3];
    uint8_t next_header;
};

/**
 * @class TCPScanner
 * @brief Scans ports and outputs their state
 */
class TCPScanner {
private:
    bool is_ipv6;               ///< Flag for IP address type
    int raw_socket;             ///< Raw socket
    std::string interface_name; ///< Name of the interface (used for IPv6 socket)
    std::string interface_ip;   ///< IP address of interface
    std::string target_ip;      ///< IP address of target
    std::vector<int> ports;     ///< TCP Ports
    int timeout;                ///< Timeout in ms
    struct iphdr ip_header;     ///< IPv4 header
    struct ip6_hdr ip6_header;  ///< IPv6 header
    struct tcphdr tcp_header;   ///< TCP header

    /**
     * @brief Creates raw socket for TCP scanning
     * @param type Either AF_INET for IPv4 or AF_INET6
     * @return Void
     */
    void createRawSocket(int type);

    /**
     * @brief Checks if the stirng is IPv4 address
     * @return True or False
     */
    bool isIPv4(const std::string &str);

    /**
     * @brief Checks if the stirng is IPv6 address
     * @return True or False
     */
    bool isIPv6(const std::string &str);

    /**
     * @brief Converts string to IPv4 address
     * @return IPv4 in string format
     */
    std::string stringToIPv4(const std::string &str);

    /**
     * @brief Converts string to IPv6 address
     * @return IPv6 in string format
     */
    std::string stringToIPv6(const std::string &str);

    /**
     * @brief Sets up IPv4 header
     * @param source_ip IPv4 address of the interface
     * @param target_ip IPv4 address of the target
     * @return void
     */
    void setupIPv4Header(const std::string &source_ip, const std::string &target_ip);

    /**
     * @brief Sets up IPv6 header
     * @param source_ip IPv6 address of the interface
     * @param target_ip IPv6 address of the target
     * @return void
     */
    void setupIPv6Header(const std::string &source_ip, const std::string &target_ip);

    /**
     * @brief Sets up TCP header
     * @param port Specific port
     * @return void
     */
    void setupTCPHeader(int port);

    /**
     * @brief Calculates checksum
     * @param data Pointer to a data (header)
     * @param length Size of passed data
     * @return Calculated checksum
     */
    uint16_t calculateChecksum(uint16_t* data, int length);

    /**
     * @brief Calculates checksum for TCP header
     *
     * Servers as packer function for pseudoheader setup and
     * calculate checksum function.
     *
     * @return Calculated checksum
     */
    uint16_t calculateTCPChecksum();
    uint16_t calculateTCP6Checksum();

public:
    /**
     * @brief Constructor for TCPScanner class
     * @param interface Name of the interface
     * @param target Name or IP of the target
     * @param ports Ports to be scanner
     * @param timeout Timeout in ms
     */
    TCPScanner(const std::string& interface, const std::string& target, 
               const std::vector<int>& ports, int timeout);

    /**
     * @brief Destructor for TCPScanner class
     */
    ~TCPScanner();

    /**
     * @brief Sends packets to all ports
     * @return Void
     */
    void sendPackets();

    /**
     * @brief Listens to responsed from ports and output their states
     * @return Void
     */
    void listenForResponses();
};

#endif // TCP_SCANNER_H
