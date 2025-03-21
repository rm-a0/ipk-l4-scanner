#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <netinet/in.h>

namespace Utils {
    /**
     * @brief Checks if the stirng is IPv4 address
     * @return True or False
     */
    bool isIPv4(const std::string &str);

    /**
     * @brief Checks if the stirng is IPv6 address
     * @return True or False
     */
    bool isIPv6(const std::string &str);

    /**
     * @brief Converts string to IPv4 address
     * @return IPv4 in string format
     */
    std::string stringToIPv4(const std::string &str);

    /**
     * @brief Converts string to IPv6 address
     * @return IPv6 in string format
     */
    std::string stringToIPv6(const std::string &str);

    /**
     * @brief Calculates checksum
     * @param data Pointer to a data (header)
     * @param length Size of passed data
     * @return Calculated checksum
     */
    uint16_t calculateChecksum(uint16_t* data, int length);
}

#endif // UTILS_H
