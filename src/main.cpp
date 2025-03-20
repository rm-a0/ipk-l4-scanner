#include "arg_parser.h"
#include "tcp_scanner.h"

int main(int argc, char* argv[]) {
    // Initialize argparser, parse arguments and validate them
    ArgParser parser(argc, argv);
    parser.validateArgs();

    // Initialize tcp scanner
    TCPScanner tcp_scanner( parser.getInterface(),
                            parser.getTarget(),
                            parser.getTcpPorts(),
                            parser.getTimeout());

    tcp_scanner.sendPackets();
    tcp_scanner.listenForResponses();
    return 0;
}
