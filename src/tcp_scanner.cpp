#include "tcp_scanner.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h> 

TCPScanner::TCPScanner(const std::string& interface, 
                       const std::string& target_ip, 
                       const std::vector<int>& ports, 
                       int timeout)
    : interface(interface),
      target_ip(target_ip), 
      ports(ports),
      timeout(timeout)
{
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket < 0) {
        std::cerr << "Error creating raw socket" << std::endl;
        exit(EXIT_FAILURE);
    }
}

TCPScanner::~TCPScanner() {
    close(raw_socket);
}


