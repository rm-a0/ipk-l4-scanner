#include "arg_parser.h"
#include <getopt.h>
#include <cstdlib>

#include <ifaddrs.h>
#include <net/if.h>
#include <cstring>

std::vector<int> ArgParser::parsePorts(const std::string& input) {
    std::vector<int> ports;
    std::string token;
    size_t input_len = input.length();
    size_t idx = 0;

    // Iterate over input
    while (idx < input_len) {
        // Find comma index
        size_t comma_idx = input.find(',', idx);
        if (comma_idx == std::string::npos) {
            comma_idx = input_len;
        }
        token = input.substr(idx, comma_idx - idx);

        // Find dash index (if it exists append all ports in range, otherwise append token)
        size_t dash_idx = input.find('-'); // token.find if duplicates are allowed
        if (dash_idx != std::string::npos) {
            int start = std::stoi(token.substr(0, dash_idx));
            int end = std::stoi(token.substr(dash_idx + 1));

            for (int i = start; i <= end; i++) {
                ports.push_back(i);
            }
        }
        else {
            ports.push_back(std::stoi(token));
        }
        idx = comma_idx + 1;
    }

    return ports;
}

ArgParser::ArgParser(int argc, char* argv[]) {
    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"interface", required_argument, NULL, 'i'},
        {"pt", required_argument, NULL, 't'},
        {"pu", required_argument, NULL, 'u'},
        {"wait", required_argument, NULL, 'w'},
        {NULL, 0, NULL, 0}
    };

    // Source: https://stackoverflow.com/questions/7489093/getopt-long-proper-way-to-use-it
    int c;
    while ((c = getopt_long(argc, argv, "hi:t:u:w:", long_options, NULL)) != -1) {
        switch (c) {
            case 'h':
                displayHelp();
                break;
            case 'i': 
                interface = optarg;
                break;
            case 't':
                tcp_ports = parsePorts(optarg);
                break;
            case 'u':
                udp_ports = parsePorts(optarg);
                break;
            case 'w':
                timeout = std::stoi(optarg);
                break;
            default:
                displayHelp();
                std::exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        target = argv[optind];
    }
}

void ArgParser::displayHelp() {
     std::cout << "Usage: ipk-l4-scan [options]\n"
              << "\nOptions:\n"
              << "  -h, --help           Show this help message\n"
              << "  -i, --interface      Network interface\n"
              << "  -t, --pt             TCP port(s) (e.g. 21,22,23 or 20-23)\n"
              << "  -u, --pu             UDP port(s) (e.g. 21,22,23 or 21-23)\n"
              << "  -w, --wait           Timeout in milliseconds (default: 5000)\n";
    std::exit(EXIT_SUCCESS);
}

void ArgParser::printArgs() {
    std::cout << "Interface: " << (interface.empty() ? "None" : interface) << std::endl;
    std::cout << "TCP Ports: ";
    for (int port : tcp_ports) {
        std::cout << port << " ";
    }
    std::cout << std::endl;
    std::cout << "UDP Ports: ";
    for (int port : udp_ports) {
        std::cout << port << " ";
    }
    std::cout << std::endl;
    std::cout << "Timeout: " << timeout << " ms" << std::endl;
    std::cout << "Target: " << (target.empty() ? "None" : target) << std::endl;
}

// Source: https://lindevs.com/get-all-network-interfaces-on-linux-using-cpp
void listActiveInterfaces() {
    struct ifaddrs *addrs;
    if (getifaddrs(&addrs) == -1) {
        std::cerr << "Error getting interfaces: " << strerror(errno) << std::endl;
        std::exit(EXIT_FAILURE);
    }

    for (struct ifaddrs *addr = addrs; addr != nullptr; addr = addr->ifa_next) {
        if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_PACKET) {
            // Check if interface is avaliable (IFF_UP)
            if (addr->ifa_flags & IFF_UP) {
                std::cout << addr->ifa_name << std::endl;
            }
        }
    }

    freeifaddrs(addrs);
}

void ArgParser::validateArgs() {
    if (interface.empty() && tcp_ports.empty() && udp_ports.empty() && target.empty()) {
        listActiveInterfaces();
    }
}

std::string ArgParser::getInterface() {
    return interface;
}

std::vector<int>  ArgParser::getTcpPorts() {
    return tcp_ports;
}

std::vector<int>  ArgParser::getUdpPorts() {
    return udp_ports;
}

int  ArgParser::getTimeout() {
    return timeout;
}

std::string  ArgParser::getTarget() {
    return target;
}
