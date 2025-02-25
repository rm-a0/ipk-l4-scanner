#include "arg_parser.h"
#include <stdio.h>
#include <getopt.h>
#include <stdexcept>

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
    while ((c = getopt_long(argc, argv, "i:t:u:w", long_options, NULL) != -1)) {
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
                timeout = std::stoi(optarg);
                break;
        }
    }
}