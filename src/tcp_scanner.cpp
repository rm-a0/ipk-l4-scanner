#include "tcp_scanner.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <algorithm>
#include <cerrno>
#include <sys/select.h>

TCPScanner::TCPScanner(const std::string& interface, 
                       const std::string& target, 
                       const std::vector<int>& ports, 
                       int timeout)
                      : ports(ports), timeout(timeout) 
{
    if (isIPv6(target)) {
        std::cout << "IPv6 support not implemendted yet" << std::endl;
        exit(EXIT_FAILURE);
    }
    else {
        // Convert strings to IPv4
        interface_ip = stringToIPv4(interface);
        target_ip = stringToIPv4(target);
        std::cout << "Interface (" << interface << ") IP: " << interface_ip << std::endl;
        std::cout << "Target (" << target << ") IP: " << target_ip << std::endl;

        // Create raw socket for IPv4
        createRawSocket(AF_INET);
        int one = 1;
        if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            std::cerr << "Error setting IP_HDRINCL: " << strerror(errno) << std::endl;
            std::exit(EXIT_FAILURE);
        }
        setupIPv4Header(interface_ip, target_ip);
    }
}

TCPScanner::~TCPScanner() {
    if (raw_socket >= 0) {
        close(raw_socket);
    }
}

void TCPScanner::createRawSocket(int type) {
    raw_socket = socket(type, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket < 0) {
        std::cerr << "Error creating raw socket: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(interface_ip.c_str());
    sin.sin_port = 0;
    if (bind(raw_socket, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        std::cerr << "Error binding socket: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
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

std::string TCPScanner::stringToIPv4(const std::string &str) {
    if (isIPv4(str)) {
        return str;
    }

    struct ifaddrs *addrs, *ifa;
    char *addr_str = nullptr;

    if (getifaddrs(&addrs) == -1) {
        std::cerr << "Error getting interfaces: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    for (ifa = addrs; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == str && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
            addr_str = inet_ntoa(sockaddr_ipv4->sin_addr);
            break;
        }
    }

    freeifaddrs(addrs);

    if (addr_str != nullptr) {
        return std::string(addr_str);
    } else {
        std::cerr << "Error: Could not find IP address for interface " << str << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

void TCPScanner::setupIPv4Header(const std::string &source_ip, const std::string &target_ip) {
    memset(&ip_header, 0, sizeof(ip_header));
    ip_header.ihl = 5;
    ip_header.version = 4;
    ip_header.tos = 0;
    ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_header.id = htonl(54321);
    ip_header.frag_off = 0;
    ip_header.ttl = 255;
    ip_header.protocol = IPPROTO_TCP;
    ip_header.saddr = inet_addr(source_ip.c_str());
    ip_header.daddr = inet_addr(target_ip.c_str());
    ip_header.check = calculateChecksum((uint16_t*)&ip_header, sizeof(struct iphdr));
}

void TCPScanner::setupTCPHeader(int port) {
    memset(&tcp_header, 0, sizeof(tcp_header));
    tcp_header.th_sport = htons(12345);
    tcp_header.th_dport = htons(port);
    tcp_header.th_seq = htonl(rand());
    tcp_header.th_ack = 0;
    tcp_header.th_off = 5;
    tcp_header.th_flags = TH_SYN;
    tcp_header.th_win = htons(5840);
    tcp_header.th_sum = 0;
    tcp_header.th_urp = 0;
    tcp_header.th_sum = calculateTCPChecksum();
}

uint16_t TCPScanner::calculateChecksum(uint16_t* data, int length) {
    uint32_t sum = 0;
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length == 1) {
        sum += *(uint8_t*)data;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

uint16_t TCPScanner::calculateTCPChecksum() {
    pseudohdr p_header;
    p_header.src_addr = ip_header.saddr;
    p_header.dst_addr = ip_header.daddr;
    p_header.reserved = 0;
    p_header.protocol = IPPROTO_TCP;
    p_header.tcp_len = htons(sizeof(struct tcphdr));

    int total_len = sizeof(pseudohdr) + sizeof(struct tcphdr);
    uint8_t* buffer = new uint8_t[total_len];
    memcpy(buffer, &p_header, sizeof(pseudohdr));
    memcpy(buffer + sizeof(pseudohdr), &tcp_header, sizeof(struct tcphdr));

    uint16_t checksum = calculateChecksum((uint16_t*)buffer, total_len);
    delete[] buffer;
    return checksum;
}

void TCPScanner::sendPackets() {
    struct sockaddr_in dest_info;
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = ip_header.daddr;

    for (int port : ports) {
        setupTCPHeader(port);
        int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
        uint8_t *packet = new uint8_t[packet_size];
        memcpy(packet, &ip_header, sizeof(struct iphdr));
        memcpy(packet + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));

        if (sendto(raw_socket, packet, packet_size, 0, 
                   (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
            std::cerr << "Error sending packet to port " << port << ": " << strerror(errno) << std::endl;
        } else {
            std::cout << "Packet sent to " << target_ip << " on port " << port << std::endl;
        }
        delete[] packet;
    }
}

void TCPScanner::listenForResponses() {
    uint8_t buffer[65536];
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);
    struct timeval select_timeout;
    select_timeout.tv_sec = 2;
    select_timeout.tv_usec = 0;

    std::string local_ip = interface_ip;
    int responses_expected = ports.size();
    int responses_received = 0;

    while (responses_received < responses_expected) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(raw_socket, &readfds);

        int activity = select(raw_socket + 1, &readfds, nullptr, nullptr, &select_timeout);
        if (activity < 0) {
            std::cerr << "Select error: " << strerror(errno) << std::endl;
            break;
        }
        if (activity == 0) {
            std::cout << "No response within timeout" << std::endl;
            break;
        }

        ssize_t received = recvfrom(raw_socket, buffer, sizeof(buffer), 0, 
                                   (struct sockaddr*)&sender_addr, &sender_len);
        if (received < 0) {
            std::cerr << "Error receiving packet: " << strerror(errno) << std::endl;
            continue;
        }

        struct iphdr *ip_hdr = (struct iphdr*)buffer;
        int ip_header_len = ip_hdr->ihl * 4;
        struct tcphdr *tcp_hdr = (struct tcphdr*)(buffer + ip_header_len);

        std::string src_ip = inet_ntoa(*(struct in_addr*)&ip_hdr->saddr);
        std::string dst_ip = inet_ntoa(*(struct in_addr*)&ip_hdr->daddr);
        int port = ntohs(tcp_hdr->th_sport);

        std::cout << "Received: " << src_ip << ":" << ntohs(tcp_hdr->th_sport) 
                  << " -> " << dst_ip << ":" << ntohs(tcp_hdr->th_dport) 
                  << " Flags: " << (int)tcp_hdr->th_flags << std::endl;

        if (src_ip == local_ip && dst_ip == target_ip && tcp_hdr->th_flags == TH_SYN) {
            continue;
        }

        if (src_ip == target_ip && dst_ip == local_ip) {
            if (std::find(ports.begin(), ports.end(), port) != ports.end()) {
                if ((tcp_hdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
                    std::cout << "Port " << port << " is OPEN" << std::endl;
                } else if (tcp_hdr->th_flags & TH_RST) {
                    std::cout << "Port " << port << " is CLOSED" << std::endl;
                } else {
                    std::cout << "Port " << port << " is FILTERED" << std::endl;
                }
                responses_received++;
            }
        }
    }
}
