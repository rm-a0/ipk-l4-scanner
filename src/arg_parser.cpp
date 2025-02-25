#include "arg_parser.h"
#include <stdio.h>
#include <getopt.h>
#include <stdexcept>
#include <cstdlib>

std::vector<int> parsePorts(const std::string& input) {
    std::vector<int> ports;

    return ports;
}

ArgParser::ArgParser(int argc, char* argv[]) {
    static struct option long_options[] = {
        {"interface", required_argument, NULL, 'i'},
        {"pt", required_argument, NULL, 't'},
        {"pu", required_argument, NULL, 'u'},
        {"wait", required_argument, NULL, 'w'},
        {NULL, 0, NULL, 0}
    };
    
    int c;
    /* Source: https://stackoverflow.com/questions/7489093/getopt-long-proper-way-to-use-it*/
    while ((c = getopt_long(argc, argv, "i:t:u:w:", long_options, NULL)) != -1) {
        switch (c) {
            case 'i': 
                interface = optarg;
                break;
            case 't':
                // tcp_ports = parsePorts(optarg);
                break;
            case 'u':
                // udp_ports = parsePorts(optarg);
                break;
            case 'w':
                if (optarg) {
                    timeout = std::stoi(optarg);
                }
                else {
                    std::cerr << "Argument -w | --wait expects numerical value" << std::endl;
                    std::exit(EXIT_FAILURE);
                }
                break;
            default:
                std::cerr << "Unexpected argument" << std::endl;
                std::exit(EXIT_FAILURE);
        }
    }
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