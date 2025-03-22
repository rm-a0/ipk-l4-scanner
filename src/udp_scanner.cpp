#include "udp_scanner.h"
#include "utils.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>


UDPScanner::UDPScanner(const std::string& interface,
                       const std::string& target,
                       const std::vector<int>& ports,
                       int timeout)
    : interface_name(interface), ports(ports), timeout(timeout)
{
    is_ipv6 = Utils::isIPv6(target);
    if (is_ipv6) {
        interface_ip = Utils::stringToIPv6(interface);
        target_ip = Utils::stringToIPv6(target);
        std::cout << "Interface (" << interface << ") IP: " << interface_ip << std::endl;
        std::cout << "Target (" << target << ") IP: " << target_ip << std::endl;
        createRawSocket(AF_INET6);
        setupIPv6Header(interface_ip, target_ip);
    } else {
        interface_ip = Utils::stringToIPv4(interface);
        target_ip = Utils::stringToIPv4(target);
        std::cout << "Interface (" << interface << ") IP: " << interface_ip << std::endl;
        std::cout << "Target (" << target << ") IP: " << target_ip << std::endl;
        createRawSocket(AF_INET);
        setupIPv4Header(interface_ip, target_ip);
    }
    pending_ports.insert(ports.begin(), ports.end());
}

UDPScanner::~UDPScanner() {
    if (raw_socket >= 0) {
        close(raw_socket);
    }
}

void UDPScanner::createRawSocket(int type) {
    raw_socket = socket(type, SOCK_RAW, IPPROTO_UDP);
    if (raw_socket < 0) {
        std::cerr << "Error creating raw socket: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    if (is_ipv6) {
        struct sockaddr_in6 sin6;
        sin6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, interface_ip.c_str(), &sin6.sin6_addr);
        sin6.sin6_port = 0;
        if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr)) {
            sin6.sin6_scope_id = if_nametoindex(interface_name.c_str());
            if (sin6.sin6_scope_id == 0) {
                std::cerr << "Error getting interface index: " << strerror(errno) << std::endl;
                std::exit(EXIT_FAILURE);
            }
        } else {
            sin6.sin6_scope_id = 0;
        }
        if (bind(raw_socket, (struct sockaddr*)&sin6, sizeof(sin6)) < 0) {
            std::cerr << "Error binding socket: " << strerror(errno) << std::endl;
            std::exit(EXIT_FAILURE);
        }
    } else {
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = inet_addr(interface_ip.c_str());
        sin.sin_port = 0;
        if (bind(raw_socket, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
            std::cerr << "Error binding socket: " << strerror(errno) << std::endl;
            std::exit(EXIT_FAILURE);
        }
    }

    int one = 1;
    if (setsockopt(raw_socket, is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cerr << "Error setting IP_HDRINCL: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

void UDPScanner::setupIPv4Header(const std::string &source_ip, const std::string &target_ip) {
    memset(&ip_header, 0, sizeof(ip_header));
    ip_header.ihl = 5;
    ip_header.version = 4;
    ip_header.tos = 0;
    ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
    ip_header.id = htonl(54321);
    ip_header.frag_off = 0;
    ip_header.ttl = 255;
    ip_header.protocol = IPPROTO_UDP;
    ip_header.saddr = inet_addr(source_ip.c_str());
    ip_header.daddr = inet_addr(target_ip.c_str());
    ip_header.check = Utils::calculateChecksum((uint16_t*)&ip_header, sizeof(struct iphdr));
}

void UDPScanner::setupIPv6Header(const std::string &source_ip, const std::string &target_ip) {
    memset(&ip6_header, 0, sizeof(ip6_header));
    ip6_header.ip6_flow = htonl(0x60000000);
    ip6_header.ip6_plen = htons(sizeof(struct udphdr));
    ip6_header.ip6_nxt = IPPROTO_UDP;
    ip6_header.ip6_hlim = 255;
    inet_pton(AF_INET6, source_ip.c_str(), &ip6_header.ip6_src);
    inet_pton(AF_INET6, target_ip.c_str(), &ip6_header.ip6_dst);
}

void UDPScanner::setupUDPHeader(int port) {
    memset(&udp_header, 0, sizeof(udp_header));
    udp_header.source = htons(12345);
    udp_header.dest = htons(port);
    udp_header.len = htons(sizeof(struct udphdr));
    udp_header.check = is_ipv6 ? calculateUDP6Checksum() : calculateUDPChecksum();
}

uint16_t UDPScanner::calculateUDPChecksum() {
    udp_pseudohdr p_header;
    p_header.src_addr = ip_header.saddr;
    p_header.dst_addr = ip_header.daddr;
    p_header.zero = 0;
    p_header.protocol = IPPROTO_UDP;
    p_header.udp_len = udp_header.len;

    int total_len = sizeof(udp_pseudohdr) + sizeof(struct udphdr);
    std::vector<uint8_t> buffer(total_len);
    memcpy(buffer.data(), &p_header, sizeof(udp_pseudohdr));
    memcpy(buffer.data() + sizeof(udp_pseudohdr), &udp_header, sizeof(struct udphdr));

    return Utils::calculateChecksum((uint16_t*)buffer.data(), total_len);
}

uint16_t UDPScanner::calculateUDP6Checksum() {
    udp_pseudohdr6 p_header;
    inet_pton(AF_INET6, interface_ip.c_str(), &p_header.src_addr);
    inet_pton(AF_INET6, target_ip.c_str(), &p_header.dst_addr);
    p_header.udp_len = htonl(sizeof(struct udphdr));
    p_header.zero[0] = p_header.zero[1] = p_header.zero[2] = 0;
    p_header.next_header = IPPROTO_UDP;

    int total_len = sizeof(udp_pseudohdr6) + sizeof(struct udphdr);
    std::vector<uint8_t> buffer(total_len);
    memcpy(buffer.data(), &p_header, sizeof(udp_pseudohdr6));
    memcpy(buffer.data() + sizeof(udp_pseudohdr6), &udp_header, sizeof(struct udphdr));

    return Utils::calculateChecksum((uint16_t*)buffer.data(), total_len);
}

void UDPScanner::sendPackets() {
    if (is_ipv6) {
        struct sockaddr_in6 dest_info;
        memset(&dest_info, 0, sizeof(dest_info));
        dest_info.sin6_family = AF_INET6;
        inet_pton(AF_INET6, target_ip.c_str(), &dest_info.sin6_addr);
        dest_info.sin6_port = 0;

        for (int port : ports) {
            setupUDPHeader(port);
            int packet_size = sizeof(struct ip6_hdr) + sizeof(struct udphdr);
            std::vector<uint8_t> packet(packet_size);
            memcpy(packet.data(), &ip6_header, sizeof(struct ip6_hdr));
            memcpy(packet.data() + sizeof(struct ip6_hdr), &udp_header, sizeof(struct udphdr));

            if (sendto(raw_socket, packet.data(), packet_size, 0, (struct sockaddr*)&dest_info, sizeof(dest_info)) < 0) {
                std::cerr << "Error sending packet to port " << port << ": " << strerror(errno) << std::endl;
            } else {
                std::cout << "Packet sent to " << target_ip << " on port " << port << std::endl;
            }
        }
    } else {
        struct sockaddr_in dest_info;
        memset(&dest_info, 0, sizeof(dest_info));
        dest_info.sin_family = AF_INET;
        dest_info.sin_addr.s_addr = ip_header.daddr;

        for (int port : ports) {
            setupUDPHeader(port);
            int packet_size = sizeof(struct iphdr) + sizeof(struct udphdr);
            std::vector<uint8_t> packet(packet_size);
            memcpy(packet.data(), &ip_header, sizeof(struct iphdr));
            memcpy(packet.data() + sizeof(struct iphdr), &udp_header, sizeof(struct udphdr));

            if (sendto(raw_socket, packet.data(), packet_size, 0, (struct sockaddr*)&dest_info, sizeof(dest_info)) < 0) {
                std::cerr << "Error sending packet to port " << port << ": " << strerror(errno) << std::endl;
            } else {
                std::cout << "Packet sent to " << target_ip << " on port " << port << std::endl;
            }
        }
    }
}

