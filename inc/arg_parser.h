#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <string>
#include <vector>
#include <iostream>

/**
 * @class ArgParser
 * @brief A class to parse and store command line arguments
 */
class ArgParser {
private:
    std::string interface;      ///< Network interface
    std::vector<int> tcp_ports; ///< TCP ports
    std::vector<int> udp_ports; ///< UDP ports
    int timeout = 5000;         ///< Timeout in ms (5000 is default)
    std::string target;         ///< Domain name or IP address

public:
    /**
     * @brief Constructor for ArgParser class
     * @param argc Argument count
     * @param argv List of arguments
     */
    ArgParser(int argc, char* argv[]);
};

#endif // ARG_PARSER_H