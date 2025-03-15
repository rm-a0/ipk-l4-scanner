#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#include <vector>
#include <string>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

/**
 * @class TCPScanner
 * @brief Handles TCP port scanning
 */
class TCPScanner {
private:
    std::string interface;      ///< Network interface
    std::string target_ip;      ///< IPv4 or IPv6 of a target
    std::vector<int> ports;     ///< TCP ports
    int timeout;                ///< Timeout in ms
    int raw_socket;             ///< Raw socket
    struct iphdr ip_header;     ///< IPv4 header
    struct tcphdr tcp_header;   ///< TCP header
    struct pseudohdr {          ///< Pseudo header for TCP checksum
        uint32_t src_addr;          ///< Source IP
        uint32_t dst_addr;          ///< Target IP
        uint32_t reserved;          ///< 0
        uint32_t protocol;          ///< Protocol (TCP = 0)
        uint32_t tcp_len;           ///< Segment length og TCP
    };

    /**
     * @brief Creates raw socket
     * @param type Type of the socket (iPv4/iPv6)
     * @return Void
     */
    void createRawSocket(int type);

    /**
     * @brief Checks if string is IPv4 address
     * @param str String to be checked
     * @return True or False
     */
    bool isIPv4(const std::string &str);

    /**
     * @brief Checks if string is IPv6 address
     * @param str String to be checked
     * @return True or False
     */
    bool isIPv6(const std::string &str);

    /**
     * @brief Converts string to ip address
     * @parem str String to be converted
     * @return String containing IP address
     */
    std::string stringToIp(const std::string &str);

    /**
     * @brief Sets up default TCP header
     * @return Void
     */
    void setupTCPHeader();

    /**
     * @brief Sets up default IPv4 header
     * @param source_ip IP address of the source
     * @return Void
     */
    void setupIPv4Header(const std::string &source_ip, const std::string &target_ip);

    uint16_t calculateChecksum(uint16_t* data, int length);
    uint16_t calculateTCPChecksum();
    void sendPacket();

public:
    /**
     * @brief Constructor for TCPScanner
     * @param interface Network interface
     * @param taget_ip IPv4 or IPv6 address
     * @param ports Ports to be scanned
     * @param timeout Timeout in ms
     */
    TCPScanner(const std::string& interface,
               const std::string& target_ip, 
               const std::vector<int>& ports, 
               int timeout);

    /**
     * @brief TCPScanner destructor
     * Closes pcap_handle if its open
     */
    ~TCPScanner();

    /**
     * @brief Performs TCP scan
     * @return Void
     */
    void scan();

};

#endif // TCP_SCANNER_H
