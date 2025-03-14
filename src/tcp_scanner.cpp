#include "tcp_scanner.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h> 
#include <ifaddrs.h>

TCPScanner::TCPScanner(const std::string& interface, 
                       const std::string& target_ip, 
                       const std::vector<int>& ports, 
                       int timeout)
    : interface(interface),
      target_ip(target_ip),
      ports(ports),
      timeout(timeout)
{
    // Default ipv4 socket
    createRawSocket(AF_INET);
    setupTcpHeader();
    std::string int_ip = stringToIp(interface);
    std::cout << "Interface ip: " << int_ip << std::endl;
    std::string dst_ip = stringToIp(target_ip);
    std::cout << "Target ip: " << dst_ip << std::endl;
    setupIPv4Header(int_ip, dst_ip);
}

TCPScanner::~TCPScanner() {
    close(raw_socket);
}

void TCPScanner::createRawSocket(int type) {
    raw_socket = socket(type, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket < 0) {
        std::cerr << "Error creating raw socket" << std::endl;
        exit(EXIT_FAILURE);
    }
}

bool TCPScanner::isIPv4(const std::string &str) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str.c_str(), &(sa.sin_addr)) != 0;
}

bool TCPScanner::isIPv6(const std::string &str) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, str.c_str(), &(sa.sin6_addr)) != 0;
}

// Source: ChatGPT
std::string TCPScanner::stringToIp(const std::string &str) {
    if (isIPv4(str)) {
        return str;
    }

    struct ifaddrs *addrs, *ifa;
    char *addr_str = nullptr;

    // Get the list of interfaces
    if (getifaddrs(&addrs) == -1) {
        std::cerr << "Error getting interfaces" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Loop through the interfaces
    for (ifa = addrs; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == str) {
            if (ifa->ifa_addr->sa_family == AF_INET) {  // Check if it's IPv4
                struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
                addr_str = inet_ntoa(sockaddr_ipv4->sin_addr); // Convert to string
                break;
            }
        }
    }

    freeifaddrs(addrs);

    if (addr_str != nullptr) {
        return std::string(addr_str);
    }
    else {
        std::cerr << "Error could not find IP address of: " << str << std::endl;
        exit(EXIT_FAILURE);
    }

}

void TCPScanner::setupTcpHeader() {
    memset(&tcp_header, 0, sizeof(tcp_header));
    tcp_header.th_seq = 0;  // Sequence number
    tcp_header.th_ack = 0;  // Acknowledgment number
    tcp_header.th_off = (5 << 4);  // Data offset and reserved (5 words,no options)
    tcp_header.th_flags = TH_SYN;  // TCP SYN flag
    tcp_header.th_win = htons(5840);  // Window size
    tcp_header.th_sum = 0;  // Checksum (will be computed later)
    tcp_header.th_urp = 0;  // Urgent pointer
}

void TCPScanner::setupIPv4Header(const std::string &source_ip, const std::string &target_ip) {
    memset(&ip_header, 0, sizeof(ip_header));
    ip_header.ihl = 5;  // IPv4 header length (in 32-bit words)
    ip_header.version = 4;  // IPv4
    ip_header.tos = 0;  // Type of service
    ip_header.id = htonl(54321);  // Random ID
    ip_header.frag_off = 0;  // Fragment offset
    ip_header.ttl = 255;  // Time to live
    ip_header.protocol = IPPROTO_TCP;  // Protocol (TCP)
    ip_header.check = 0; // Calculate checksum later
    ip_header.saddr = inet_addr(source_ip.c_str());  // Source IP
    ip_header.daddr = inet_addr(target_ip.c_str());  // Target IP
}
