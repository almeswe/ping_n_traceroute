#include "c_ping.h"

int main(int argc, char** argv) {
    if (argc != 2) {
        printerr("%s\n", "Incorrect argument count passed.");
        return 1;
    }
    struct c_ping_in in = {
        .attempts = 4,
        .ip = inet_addr(argv[1]),
        .hostip = get_hostip()
    };
    c_ping_to(in);
    return 0;
}