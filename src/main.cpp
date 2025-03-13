#include "arg_parser.h"
#include "tcp_scanner.h"

int main(int argc, char* argv[]) {
    ArgParser parser(argc, argv);
    //parser.printArgs();
    parser.validateArgs();
    return 0;
}
