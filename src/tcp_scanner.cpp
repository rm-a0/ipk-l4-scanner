#include "tcp_scanner.h"
#include "utils.h"
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
#include <net/if.h>
#include <netdb.h>

TCPScanner::TCPScanner(const std::string& interface, 
                       const std::string& target, 
                       const std::vector<int>& ports, 
                       int timeout)
    : interface_name(interface), ports(ports), timeout(timeout) 
{
    is_ipv6 = Utils::isIPv6(target) || Utils::isIPv6(interface);
    pending_ports.insert(ports.begin(), ports.end());
    if (is_ipv6) {
        // Convert interface and target to ipv6
        interface_ip = Utils::stringToIPv6(interface);
        target_ip = Utils::stringToIPv6(target);
        // Create raw socket and header for ipv6
        createRawSocket(AF_INET6);
        setupIPv6Header(interface_ip, target_ip);
    }
    else {
        // Convert interface and target to ipv4
        interface_ip = Utils::stringToIPv4(interface);
        target_ip = Utils::stringToIPv4(target);
        // Create raw socket and header for ipv4
        createRawSocket(AF_INET);
        setupIPv4Header(interface_ip, target_ip);
    }
    sendPackets();
    listenForResponses();
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

    if (is_ipv6) {
        struct sockaddr_in6 sin6;
        sin6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, interface_ip.c_str(), &sin6.sin6_addr);
        sin6.sin6_port = 0;
        // Check if ipv6 is local
        if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr)) {
            sin6.sin6_scope_id = if_nametoindex(interface_name.c_str());
            if (sin6.sin6_scope_id == 0) {
                std::cerr << "Error getting interface index for " << interface_ip << ": " << strerror(errno) << std::endl;
                std::exit(EXIT_FAILURE);
            }
        }
        else {
            sin6.sin6_scope_id = 0;
        }
        // Bind raw socket to interface
        if (bind(raw_socket, (struct sockaddr*)&sin6, sizeof(sin6)) < 0) {
            std::cerr << "Error binding socket: " << strerror(errno) << std::endl;
            std::exit(EXIT_FAILURE);
        }
    }
    else {
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = inet_addr(interface_ip.c_str());
        sin.sin_port = 0;
        // Bind raw socket to interface
        if (bind(raw_socket, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
            std::cerr << "Error binding socket: " << strerror(errno) << std::endl;
            std::exit(EXIT_FAILURE);
        }
    }

    // Set flag for custom headers
    int one = 1;
    if (setsockopt(raw_socket, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cerr << "Error setting IP_HDRINCL: " << strerror(errno) << std::endl;
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
    ip_header.check = Utils::calculateChecksum((uint16_t*)&ip_header, sizeof(struct iphdr));
}

void TCPScanner::setupIPv6Header(const std::string &source_ip, const std::string &target_ip) {
    memset(&ip6_header, 0, sizeof(ip6_header));
    ip6_header.ip6_flow = htonl(0x60000000);
    ip6_header.ip6_plen = htons(sizeof(struct tcphdr));
    ip6_header.ip6_nxt = IPPROTO_TCP;
    ip6_header.ip6_hlim = 255;
    inet_pton(AF_INET6, source_ip.c_str(), &ip6_header.ip6_src);
    inet_pton(AF_INET6, target_ip.c_str(), &ip6_header.ip6_dst);
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
    tcp_header.th_sum = is_ipv6 ? calculateTCP6Checksum() : calculateTCPChecksum();
}

uint16_t TCPScanner::calculateTCPChecksum() {
    tcp_pseudohdr p_header;
    p_header.src_addr = ip_header.saddr;
    p_header.dst_addr = ip_header.daddr;
    p_header.reserved = 0;
    p_header.protocol = IPPROTO_TCP;
    p_header.tcp_len = htons(sizeof(struct tcphdr));

    int total_len = sizeof(tcp_pseudohdr) + sizeof(struct tcphdr);
    uint8_t* buffer = new uint8_t[total_len];
    memcpy(buffer, &p_header, sizeof(tcp_pseudohdr));
    memcpy(buffer + sizeof(tcp_pseudohdr), &tcp_header, sizeof(struct tcphdr));

    uint16_t checksum = Utils::calculateChecksum((uint16_t*)buffer, total_len);
    delete[] buffer;
    return checksum;
}

uint16_t TCPScanner::calculateTCP6Checksum() {
    tcp_pseudohdr6 p_header;
    inet_pton(AF_INET6, interface_ip.c_str(), &p_header.src_addr);
    inet_pton(AF_INET6, target_ip.c_str(), &p_header.dst_addr);
    p_header.tcp_len = htonl(sizeof(struct tcphdr));
    p_header.reserved[0] = p_header.reserved[1] = p_header.reserved[2] = 0;
    p_header.next_header = IPPROTO_TCP;

    int total_len = sizeof(tcp_pseudohdr6) + sizeof(struct tcphdr);
    uint8_t* buffer = new uint8_t[total_len];
    memcpy(buffer, &p_header, sizeof(tcp_pseudohdr6));
    memcpy(buffer + sizeof(tcp_pseudohdr6), &tcp_header, sizeof(struct tcphdr));

    uint16_t checksum = Utils::calculateChecksum((uint16_t*)buffer, total_len);
    delete[] buffer;
    return checksum;
}

void TCPScanner::sendPackets() {
    if (is_ipv6) {
        struct sockaddr_in6 dest_info;
        memset(&dest_info, 0, sizeof(dest_info));
        dest_info.sin6_family = AF_INET6;
        inet_pton(AF_INET6, target_ip.c_str(), &dest_info.sin6_addr);
        dest_info.sin6_port = 0;

        // Send sockets to all ports
        for (int port : ports) {
            setupTCPHeader(port);
            int packet_size = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
            std::vector<uint8_t> packet(packet_size);
            memcpy(packet.data(), &ip6_header, sizeof(struct ip6_hdr));
            memcpy(packet.data() + sizeof(struct ip6_hdr), &tcp_header, sizeof(struct tcphdr));

            if (sendto(raw_socket, packet.data(), packet_size, 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
                std::cerr << "Error sending packet to port " << port << ": " << strerror(errno) << std::endl;
                std::exit(EXIT_FAILURE);
            }
        }
    }
    else {
        struct sockaddr_in dest_info;
        memset(&dest_info, 0, sizeof(dest_info));
        dest_info.sin_family = AF_INET;
        dest_info.sin_addr.s_addr = ip_header.daddr;

        for (int port : ports) {
            setupTCPHeader(port);
            int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
            std::vector<uint8_t> packet(packet_size);
            memcpy(packet.data(), &ip_header, sizeof(struct iphdr));
            memcpy(packet.data() + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));

            if (sendto(raw_socket, packet.data(), packet_size, 0, 
                       (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
                std::cerr << "Error sending packet to port " << port << ": " << strerror(errno) << std::endl;
                std::exit(EXIT_FAILURE);
            }
        }
    }
}

void TCPScanner::listenForResponses() {
    std::vector<uint8_t> buffer(65536);
    struct sockaddr_storage sender_addr;
    socklen_t sender_len = sizeof(sender_addr);
    struct timeval select_timeout;
    select_timeout.tv_sec = timeout / 1000;
    select_timeout.tv_usec = (timeout % 1000) * 1000;

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
            for (int port : pending_ports) {
                std::cout << target_ip << " " << port << " tcp filtered" << std::endl;
            }
            break;
        }

        ssize_t received = recvfrom(raw_socket, buffer.data(), buffer.size(), 0, 
                                   (struct sockaddr*)&sender_addr, &sender_len);
        if (received < 0) {
            std::cerr << "Error receiving packet: " << strerror(errno) << std::endl;
            continue;
        }

        std::string src_ip, dst_ip;
        char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
        if (is_ipv6) {
            struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)buffer.data();
            int ip_header_len = sizeof(struct ip6_hdr);
            struct tcphdr *tcp_hdr = (struct tcphdr*)(buffer.data() + ip_header_len);
            inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src_str, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst_str, INET6_ADDRSTRLEN);
            src_ip = src_str;
            dst_ip = dst_str;

            if (src_ip == local_ip && dst_ip == target_ip && tcp_hdr->th_flags == TH_SYN) {
                continue;
            }

            if (src_ip == target_ip && dst_ip == local_ip) {
                int port = ntohs(tcp_hdr->th_sport);
                if (pending_ports.erase(port)) {
                    if ((tcp_hdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
                        std::cout << target_ip << " " << port << " tcp open" << std::endl;
                    }
                    else if (tcp_hdr->th_flags & TH_RST) {
                        std::cout << target_ip << " " << port << " tcp closed" << std::endl;
                    }
                    else {
                        std::cout << target_ip << " " << port << " tcp filtered" << std::endl;
                    }
                    responses_received++;
                }
            }
        }
        else {
            struct iphdr *ip_hdr = (struct iphdr*)buffer.data();
            int ip_header_len = ip_hdr->ihl * 4;
            struct tcphdr *tcp_hdr = (struct tcphdr*)(buffer.data() + ip_header_len);
            src_ip = inet_ntoa(*(struct in_addr*)&ip_hdr->saddr);
            dst_ip = inet_ntoa(*(struct in_addr*)&ip_hdr->daddr);

            if (src_ip == local_ip && dst_ip == target_ip && tcp_hdr->th_flags == TH_SYN) {
                continue;
            }

            if (src_ip == target_ip && dst_ip == local_ip) {
                int port = ntohs(tcp_hdr->th_sport);
                if (pending_ports.erase(port)) {
                    if ((tcp_hdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
                        std::cout << target_ip << " " << port << " tcp open" << std::endl;
                    }
                    else if (tcp_hdr->th_flags & TH_RST) {
                        std::cout << target_ip << " " << port << " tcp closed" << std::endl;
                    }
                    else {
                        std::cout << target_ip << " " << port << " tcp filtered" << std::endl;
                    }
                    responses_received++;
                }
            }
        }
    }
}
