#ifndef TCP_SCANNER_H
#define TCP_SCANNER_H

#include <vector>
#include <string>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/**
 * @class TCPScanner
 * @brief Handles TCP port scanning
 */
class TCPScanner {
private:
    std::string interface;          ///< Network interface
    std::string target_ip;          ///< IPv4 or IPv6 of a targer
    std::vector<int> ports;         ///< TCP ports
    int timeout;                    ///< Timeout in ms
    pcap_t* pcap_handle;            ///< Handle for packet capture
    char errbuff[PCAP_ERRBUF_SIZE]; ///< Error buffer

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
