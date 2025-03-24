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

// Define missing constants for Nix environment
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
    : interface_name(interface), ports(ports), timeout(timeout), 
      udp_socket(-1), icmp_socket(-1) {
    is_ipv6 = Utils::isIPv6(target);
    if (is_ipv6) {
        // Convert interface and target to ipv6
        interface_ip = Utils::stringToIPv6(interface);
        target_ip = Utils::stringToIPv6(target);
        std::cout << "Interface (" << interface << ") IP: " << interface_ip << std::endl;
        std::cout << "Target (" << target << ") IP: " << target_ip << std::endl;
        // Create udp socket and icmp for ipv6
        createUdpSocket(AF_INET6);
        createIcmpSocket(AF_INET6);
    }
    else {
        // Convert interface and target to ipv4
        interface_ip = Utils::stringToIPv4(interface);
        target_ip = Utils::stringToIPv4(target);
        std::cout << "Interface (" << interface << ") IP: " << interface_ip << std::endl;
        std::cout << "Target (" << target << ") IP: " << target_ip << std::endl;
        // Create udp socket and icmp for ipv6
        createUdpSocket(AF_INET);
        createIcmpSocket(AF_INET);
    }

    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
    if (setsockopt(icmp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "Error setting ICMP socket timeout: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    pending_ports.insert(ports.begin(), ports.end());
}

UDPScanner::~UDPScanner() {
    if (udp_socket >= 0) {
        close(udp_socket);
    }
    if (icmp_socket >= 0) {
        close(icmp_socket);
    }
}

void UDPScanner::createUdpSocket(int type) {
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

void UDPScanner::createIcmpSocket(int type) {
    icmp_socket = socket(type, SOCK_RAW, is_ipv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    if (icmp_socket < 0) {
        std::cerr << "Error creating ICMP socket: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }
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
            target_addr.sin6_port = htons(port);
            char buffer[] = "UDP Probe";
            if (sendto(udp_socket, buffer, sizeof(buffer), 0, 
                       (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                std::cerr << "Error sending UDP packet to port " << port << ": " << strerror(errno) << std::endl;
            } else {
                std::cout << "Packet sent to " << target_ip << " on port " << port << std::endl;
            }
        }
    } else {
        struct sockaddr_in target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr);

        for (int port : ports) {
            target_addr.sin_port = htons(port);
            char buffer[] = "UDP Probe";
            if (sendto(udp_socket, buffer, sizeof(buffer), 0, 
                       (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
                std::cerr << "Error sending UDP packet to port " << port << ": " << strerror(errno) << std::endl;
            } else {
                std::cout << "Packet sent to " << target_ip << " on port " << port << std::endl;
            }
        }
    }
}

void UDPScanner::listenForResponses() {
    char recv_buffer[4096];
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len = sizeof(src_addr);

    int responses_expected = ports.size();
    int responses_received = 0;

    while (responses_received < responses_expected) {
        int packet_size = recvfrom(icmp_socket, recv_buffer, sizeof(recv_buffer), 0, 
                                   (struct sockaddr*)&src_addr, &src_addr_len);
        if (packet_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                for (int port : pending_ports) {
                    std::cout << target_ip << " " << port << " udp open|filtered" << std::endl;
                }
                break;
            } else {
                std::cerr << "Error receiving ICMP packet: " << strerror(errno) << std::endl;
                break;
            }
        }

        if (is_ipv6) {
            struct ip6_hdr* ip6_hdr = (struct ip6_hdr*)recv_buffer;
            if (packet_size < (ssize_t)sizeof(struct ip6_hdr)) continue;
            if (ip6_hdr->ip6_nxt == IPPROTO_ICMPV6) {
                struct icmp6_hdr* icmp6_hdr = (struct icmp6_hdr*)(recv_buffer + sizeof(struct ip6_hdr));
                if (packet_size < (ssize_t)(sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct udphdr))) continue;

                char src_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src_str, INET6_ADDRSTRLEN);
                std::string src_ip = src_str;

                if (src_ip == target_ip && icmp6_hdr->icmp6_type == ICMP6_DST_UNREACH && 
                    icmp6_hdr->icmp6_code == ICMP6_DST_UNREACH_PORT) {
                    struct udphdr* udp_hdr = (struct udphdr*)(recv_buffer + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr));
                    int port = ntohs(udp_hdr->dest);
                    if (pending_ports.erase(port)) {
                        std::cout << target_ip << " " << port << " udp closed" << std::endl;
                        responses_received++;
                    }
                }
            }
        } else {
            struct iphdr* ip_hdr = (struct iphdr*)recv_buffer;
            int ip_hdr_len = ip_hdr->ihl * 4;
            if (packet_size < ip_hdr_len) continue;
            if (ip_hdr->protocol == IPPROTO_ICMP) {
                struct icmphdr* icmp_hdr = (struct icmphdr*)(recv_buffer + ip_hdr_len);
                if (packet_size < (ip_hdr_len + sizeof(struct icmphdr) + sizeof(struct iphdr) + sizeof(struct udphdr))) continue;

                std::string src_ip = inet_ntoa(*(struct in_addr*)&ip_hdr->saddr);
                if (src_ip == target_ip && icmp_hdr->type == ICMP_DEST_UNREACH && 
                    icmp_hdr->code == ICMP_PORT_UNREACH) {
                    struct iphdr* orig_ip_hdr = (struct iphdr*)(recv_buffer + ip_hdr_len + sizeof(struct icmphdr));
                    struct udphdr* udp_hdr = (struct udphdr*)(recv_buffer + ip_hdr_len + sizeof(struct icmphdr) + (orig_ip_hdr->ihl * 4));
                    int port = ntohs(udp_hdr->dest);
                    if (pending_ports.erase(port)) {
                        std::cout << target_ip << " " << port << " udp closed" << std::endl;
                        responses_received++;
                    }
                }
            }
        }
    }
}
