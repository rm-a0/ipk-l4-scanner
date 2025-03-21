#include "utils.h"
#include <cstring>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <iostream>

namespace Utils {

bool isIPv4(const std::string &str) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str.c_str(), &(sa.sin_addr)) != 0;
}

bool isIPv6(const std::string &str) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, str.c_str(), &(sa.sin6_addr)) != 0;
}

std::string stringToIPv4(const std::string &str) {
    if (isIPv4(str)) {
        return str;
    }

    // Hostname (www.fit.vutbr.cz)
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(str.c_str(), nullptr, &hints, &res) == 0) {
        for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
            if (p->ai_family == AF_INET) {
                char ip_str[INET_ADDRSTRLEN];
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
                inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
                freeaddrinfo(res);
                return std::string(ip_str);
            }
        }
        freeaddrinfo(res);
    }

    // Interface name (lo/enp0s3)
    struct ifaddrs *addrs, *ifa;
    char *addr_str = nullptr;
    if (getifaddrs(&addrs) == -1) {
        std::cerr << "Error getting interfaces: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }
    for (ifa = addrs; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == str && ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)ifa->ifa_addr;
            addr_str = inet_ntoa(sockaddr_ipv4->sin_addr);
            break;
        }
    }
    freeifaddrs(addrs);
    if (addr_str) {
        return std::string(addr_str);
    }

    std::cerr << "Error: Could not resolve '" << str << "' to an IPv4 address" << std::endl;
    std::exit(EXIT_FAILURE);
}

std::string stringToIPv6(const std::string &str) {
    if (isIPv6(str)) {
        return str;
    }

    // Hostname (www.fit.vutbr.cz)
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(str.c_str(), nullptr, &hints, &res) == 0) {
        for (struct addrinfo *p = res; p != nullptr; p = p->ai_next) {
            if (p->ai_family == AF_INET6) {
                char ip_str[INET6_ADDRSTRLEN];
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
                inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_str, INET6_ADDRSTRLEN);
                freeaddrinfo(res);
                return std::string(ip_str);
            }
        }
        freeaddrinfo(res);
    }

    // Interface name (lo/enp0s3)
    struct ifaddrs *addrs, *ifa;
    char *addr_str = nullptr;
    if (getifaddrs(&addrs) == -1) {
        std::cerr << "Error getting interfaces: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }
    for (ifa = addrs; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == str && ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
            char ip6_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr, ip6_str, INET6_ADDRSTRLEN);
            addr_str = ip6_str;
            break;
        }
    }
    freeifaddrs(addrs);
    if (addr_str) {
        return std::string(addr_str);
    }

    std::cerr << "Error: Could not resolve '" << str << "' to an IPv6 address" << std::endl;
    std::exit(EXIT_FAILURE);
}

uint16_t calculateChecksum(uint16_t* data, int length) {
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

} // namespace Utils
