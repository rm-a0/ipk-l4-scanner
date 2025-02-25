#include "arg_parser.h"

int main(int argc, char* argv[]) {
    ArgParser parser(argc, argv);
    parser.printArgs();
    return 0;
}