#include "tcp_scanner.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>

TCPScanner::TCPScanner(const std::string& interface, 
                       const std::string& target_ip, 
                       const std::vector<int>& ports, 
                       int timeout)
    : interface(interface),
      target_ip(target_ip), 
      ports(ports),
      timeout(timeout),
      pcap_handle(NULL) {}
      
TCPScanner::~TCPScanner() {
    if (pcap_handle) {
        pcap_close(pcap_handle);
    }
}