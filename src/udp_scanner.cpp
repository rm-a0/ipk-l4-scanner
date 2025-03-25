#include "udp_scanner.h"
#include "utils.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/if.h>

// Define constant for VM compatibility
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif
#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3
#endif
#ifndef ICMP6_DST_UNREACH_PORT
#define ICMP6_DST_UNREACH_PORT 4
#endif

UDPScanner::UDPScanner(const std::string& interface,
                       const std::string& target,
                       const std::vector<int>& ports,
                       int timeout)
    : interface_name(interface), ports(ports), timeout(timeout)
{
    bool scan_both = !Utils::isIPv6(target) && !Utils::isIPv6(interface) && !Utils::isIPv4(target) && !Utils::isIPv4(interface);
    is_ipv6 = Utils::isIPv6(target) || Utils::isIPv6(interface);
    pending_ports.insert(ports.begin(), ports.end());
    if (scan_both) {
        // Convert interface and target to ipv4
        interface_ip = Utils::stringToIPv4(interface);
        target_ip = Utils::stringToIPv4(target);
        // Create udp socket and icmp for ipv6
        createUDPSocket(AF_INET);
        createICMPSocket(AF_INET);
        sendPackets();
        listenForResponses();

        is_ipv6 = true;
        pending_ports.insert(ports.begin(), ports.end());
        // Convert interface and target to ipv6
        interface_ip = Utils::stringToIPv6(interface);
        target_ip = Utils::stringToIPv6(target);
        // Create udp socket and icmp for ipv6
        createUDPSocket(AF_INET6);
        createICMPSocket(AF_INET6);
        sendPackets();
        listenForResponses();
    }
    else if (is_ipv6 && !scan_both) {
        // Convert interface and target to ipv6
        interface_ip = Utils::stringToIPv6(interface);
        target_ip = Utils::stringToIPv6(target);
        // Create udp socket and icmp for ipv6
        createUDPSocket(AF_INET6);
        createICMPSocket(AF_INET6);
        sendPackets();
        listenForResponses();
    }
    else if (!is_ipv6 && !scan_both) {
        // Convert interface and target to ipv4
        interface_ip = Utils::stringToIPv4(interface);
        target_ip = Utils::stringToIPv4(target);
        // Create udp socket and icmp for ipv6
        createUDPSocket(AF_INET);
        createICMPSocket(AF_INET);
        sendPackets();
        listenForResponses();
    }
}

UDPScanner::~UDPScanner() {
    if (udp_socket >= 0) {
        close(udp_socket);
    }
    if (icmp_socket >= 0) {
        close(icmp_socket);
    }
}

void UDPScanner::createUDPSocket(int type) {
    udp_socket = socket(type, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket < 0) {
        std::cerr << "Error creating UDP socket: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    if (is_ipv6) {
        struct sockaddr_in6 sin6;
        sin6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, interface_ip.c_str(), &sin6.sin6_addr);
        sin6.sin6_port = 0;
        // Check if ipv6 is local
        if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr)) {
            sin6.sin6_scope_id = if_nametoindex(interface_name.c_str());
            if (sin6.sin6_scope_id == 0) {
                std::cerr << "Error getting interface index: " << strerror(errno) << std::endl;
                std::exit(EXIT_FAILURE);
            }
        }
        else {
            sin6.sin6_scope_id = 0;
        }
        if (bind(udp_socket, (struct sockaddr*)&sin6, sizeof(sin6)) < 0) {
            std::cerr << "Error binding UDP socket: " << strerror(errno) << std::endl;
            std::exit(EXIT_FAILURE);
        }
    }
    else {
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = inet_addr(interface_ip.c_str());
        sin.sin_port = 0;
        // Bind uddp socket to interface
        if (bind(udp_socket, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
            std::cerr << "Error binding UDP socket: " << strerror(errno) << std::endl;
            std::exit(EXIT_FAILURE);
        }
    }
}

void UDPScanner::createICMPSocket(int type) {
    icmp_socket = socket(type, SOCK_RAW, is_ipv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    if (icmp_socket < 0) {
        std::cerr << "Error creating ICMP socket: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    if (setsockopt(icmp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "Error setting ICMP socket timeout: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

uint16_t UDPScanner::calculateUDP4Checksum() {
    pseudo_header psh;
    memset(&psh, 0, sizeof(psh));
    inet_pton(AF_INET, interface_ip.c_str(), &psh.src_addr);
    inet_pton(AF_INET, target_ip.c_str(), &psh.dst_addr);
    psh.reserved = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(udp_header));

    // Create a buffer for checksum calculation
    size_t total_length = sizeof(pseudo_header) + sizeof(udp_header);
    char* buffer = new char[total_length];
    memcpy(buffer, &psh, sizeof(pseudo_header));
    memcpy(buffer + sizeof(pseudo_header), &udp_header, sizeof(udp_header));

    uint16_t checksum = Utils::calculateChecksum((uint16_t*)buffer, total_length);
    delete[] buffer;
    return checksum;
}

uint16_t UDPScanner::calculateUDP6Checksum() {
    pseudo_header6 psh;
    memset(&psh, 0, sizeof(psh));
    inet_pton(AF_INET6, interface_ip.c_str(), &psh.src_addr);
    inet_pton(AF_INET6, target_ip.c_str(), &psh.dst_addr);
    psh.udp_length = htonl(sizeof(udp_header));
    psh.next_header = IPPROTO_UDP;

    // Create a buffer for checksum calculation
    size_t total_length = sizeof(pseudo_header6) + sizeof(udp_header);
    char* buffer = new char[total_length];
    memcpy(buffer, &psh, sizeof(pseudo_header6));
    memcpy(buffer + sizeof(pseudo_header6), &udp_header, sizeof(udp_header));

    uint16_t checksum = Utils::calculateChecksum((uint16_t*)buffer, total_length);
    delete[] buffer;
    return checksum;
}

void UDPScanner::setupUDPHeader(int port) {
    memset(&udp_header, 0, sizeof(udp_header));
    udp_header.source = htons(12345);
    udp_header.dest = htons(port);
    udp_header.len = htons(sizeof(udp_header));
    udp_header.check = is_ipv6 ? calculateUDP6Checksum() : calculateUDP4Checksum();
}

void UDPScanner::sendPackets() {
    if (is_ipv6) {
        struct sockaddr_in6 target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin6_family = AF_INET6;
        inet_pton(AF_INET6, target_ip.c_str(), &target_addr.sin6_addr);
        if (IN6_IS_ADDR_LINKLOCAL(&target_addr.sin6_addr)) {
            target_addr.sin6_scope_id = if_nametoindex(interface_name.c_str());
        }

        for (int port : ports) {
            setupUDPHeader(port);
            target_addr.sin6_port = htons(port);

            if (sendto(udp_socket, &udp_header, sizeof(udp_header), 0, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                std::cerr << "Error sending UDP packet to port " << port << ": " << strerror(errno) << std::endl;
                std::exit(EXIT_FAILURE);
            }
        }
    } else {
        struct sockaddr_in target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr);

        for (int port : ports) {
            setupUDPHeader(port);
            target_addr.sin_port = htons(port);

            if (sendto(udp_socket, &udp_header, sizeof(udp_header), 0, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                std::cerr << "Error sending UDP packet to port " << port << ": " << strerror(errno) << std::endl;
                std::exit(EXIT_FAILURE);
            }
        }
    }
}

void UDPScanner::listenForResponses() {
    fd_set read_fds;
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    int max_fd = icmp_socket;

    while (!pending_ports.empty()) {
        FD_ZERO(&read_fds);
        FD_SET(icmp_socket, &read_fds);

        int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, &tv);

        if (activity < 0) {
            std::cerr << "Error with select(): " << strerror(errno) << std::endl;
            break;
        } else if (activity == 0) {
            // Timeout: Assume remaining ports are open
            for (int port : pending_ports) {
                std::cout << target_ip << " " << port << " udp open" << std::endl;
            }
            pending_ports.clear();
            break;
        }

        // ICMP response detected, check if it's "port unreachable"
        char recv_buffer[4096];
        struct sockaddr_storage src_addr;
        socklen_t src_addr_len = sizeof(src_addr);

        int packet_size = recvfrom(icmp_socket, recv_buffer, sizeof(recv_buffer), 0, 
                                   (struct sockaddr*)&src_addr, &src_addr_len);
        if (packet_size < 0) {
            std::cerr << "Error receiving ICMP packet: " << strerror(errno) << std::endl;
            continue;
        }

        if (is_ipv6) {
            struct icmp6_hdr* icmp6_hdr = (struct icmp6_hdr*)recv_buffer;
            if (icmp6_hdr->icmp6_type == ICMP6_DST_UNREACH &&
                icmp6_hdr->icmp6_code == ICMP6_DST_UNREACH_PORT) {
                // Extract port from original UDP header
                struct udphdr* udp_header = (struct udphdr*)(recv_buffer + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr));
                int port = ntohs(udp_header->dest);
                std::cout << target_ip << " " << port << " udp closed" << std::endl;
                pending_ports.erase(port);
            }
        } else {
            struct iphdr* ip_hdr = (struct iphdr*)recv_buffer;
            int ip_hdr_len = ip_hdr->ihl * 4;
            struct icmphdr* icmp_hdr = (struct icmphdr*)(recv_buffer + ip_hdr_len);

            if (icmp_hdr->type == ICMP_DEST_UNREACH && icmp_hdr->code == ICMP_PORT_UNREACH) {
                struct iphdr* orig_ip_hdr = (struct iphdr*)(recv_buffer + ip_hdr_len + sizeof(struct icmphdr));
                struct udphdr* udp_header = (struct udphdr*)(recv_buffer + ip_hdr_len + sizeof(struct icmphdr) + (orig_ip_hdr->ihl * 4));
                int port = ntohs(udp_header->dest);
                std::cout << target_ip << " " << port << " udp closed" << std::endl;
                pending_ports.erase(port);
            }
        }
    }
}
