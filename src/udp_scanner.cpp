#include "udp_scanner.h"
#include "utils.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

// Define missing constants for Nix environment
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3  // IPv4 "Destination Unreachable" type
#endif
#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3  // IPv4 "Port Unreachable" code
#endif

UDPScanner::UDPScanner(const std::string& interface,
                       const std::string& target,
                       const std::vector<int>& ports,
                       int timeout)
    : interface_name(interface), ports(ports), timeout(timeout), 
      udp_socket(-1), icmp_socket(-1) {
    interface_ip = Utils::stringToIPv4(interface);
    target_ip = Utils::stringToIPv4(target);
    std::cout << "Interface (" << interface << ") IP: " << interface_ip << std::endl;
    std::cout << "Target (" << target << ") IP: " << target_ip << std::endl;

    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket < 0) {
        std::cerr << "Error creating UDP socket: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_socket < 0) {
        std::cerr << "Error creating ICMP socket: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    // Set timeout for ICMP socket
    struct timeval tv;
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
    if (setsockopt(icmp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "Error setting ICMP socket timeout: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    // Initialize pending ports
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

void UDPScanner::sendPackets() {
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr);

    for (int port : ports) {
        target_addr.sin_port = htons(port);

        // Send a UDP packet to the target port
        char buffer[] = "UDP Probe";
        if (sendto(udp_socket, buffer, sizeof(buffer), 0, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            std::cerr << "Error sending UDP packet to port " << port << ": " << strerror(errno) << std::endl;
        } else {
            std::cout << "Packet sent to " << target_ip << " on port " << port << std::endl;
        }
    }
}

void UDPScanner::listenForResponses() {
    char recv_buffer[4096];
    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);

    int responses_expected = ports.size();
    int responses_received = 0;

    while (responses_received < responses_expected) {
        int packet_size = recvfrom(icmp_socket, recv_buffer, sizeof(recv_buffer), 0, 
                                   (struct sockaddr*)&src_addr, &src_addr_len);
        if (packet_size < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Timeout occurred, report remaining ports as open|filtered
                for (int port : pending_ports) {
                    std::cout << target_ip << " " << port << " udp open|filtered" << std::endl;
                }
                break;
            } else {
                std::cerr << "Error receiving ICMP packet: " << strerror(errno) << std::endl;
                break;
            }
        }

        // Parse ICMP packet
        struct iphdr* ip_hdr = (struct iphdr*)recv_buffer;
        if (ip_hdr->protocol == IPPROTO_ICMP) {
            int ip_hdr_len = ip_hdr->ihl * 4;
            struct icmphdr* icmp_hdr = (struct icmphdr*)(recv_buffer + ip_hdr_len);
            if (packet_size < (ip_hdr_len + sizeof(struct icmphdr) + sizeof(struct udphdr))) {
                continue; // Packet too small
            }

            if (icmp_hdr->type == ICMP_DEST_UNREACH && icmp_hdr->code == ICMP_PORT_UNREACH) {
                // Extract the original UDP header from the ICMP payload
                struct iphdr* orig_ip_hdr = (struct iphdr*)((char*)icmp_hdr + sizeof(struct icmphdr));
                struct udphdr* udp_hdr = (struct udphdr*)((char*)orig_ip_hdr + (orig_ip_hdr->ihl * 4));
                int port = ntohs(udp_hdr->dest);

                if (pending_ports.erase(port)) {
                    std::cout << target_ip << " " << port << " udp closed" << std::endl;
                    responses_received++;
                }
            }
        }
    }
}
