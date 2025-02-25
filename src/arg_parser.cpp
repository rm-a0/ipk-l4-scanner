#include "arg_parser.h"
#include <getopt.h>
#include <cstdlib>

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
        size_t dash_idx = input.find('-'); // token.find if duplicated are allowed
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
    
    int c;
    /* Source: https://stackoverflow.com/questions/7489093/getopt-long-proper-way-to-use-it*/
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
