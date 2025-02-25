#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <string>
#include <vector>
#include <iostream>

/**
 * @class ArgParser
 * @brief Parses and stores command line arguments
 */
class ArgParser {
private:
    std::string interface;      ///< Network interface
    std::vector<int> tcp_ports; ///< TCP ports
    std::vector<int> udp_ports; ///< UDP ports
    int timeout = 5000;         ///< Timeout in ms (5000 is default)
    std::string target;         ///< Domain name or IP address

    /**
     * @brief Parser for port ranges
     * 
     * This function iterrates over input string and based on the delimeter (either ',' or '-')
     * appends integer values to a vector.
     * 
     * @param input String containing port ranges
     * @return Vector of parsed integers
     */
    std::vector<int> parsePorts(const std::string& input);

    void displayHelp();

public:
    /**
     * @brief Constructor for ArgParser class
     * @param argc Argument count
     * @param argv List of arguments
     */
    ArgParser(int argc, char* argv[]);

    /**
     * @brief Prints all parsed arguments
     * @return Void
     */
    void printArgs();

    /**
     * @brief Getters for better encapsulation and sefety
     */
    std::string getInterface();
    std::vector<int> getTcpPorts();
    std::vector<int> getUdpPorts();
    int getTimeout();
    std::string getTarget();
};

#endif // ARG_PARSER_H