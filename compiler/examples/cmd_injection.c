#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void build_command(char *user, char *out) {
    strcpy(out, "ping -c 1 ");
    strcat(out, user);
}

int main(int argc, char **argv) {
    char host[64];
    char cmd[256];

    if (argc < 2) {
        return 1;
    }
    strcpy(host, argv[1]);
    build_command(host, cmd);
    system(cmd);
    return 0;
}
