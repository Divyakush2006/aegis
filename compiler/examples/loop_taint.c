#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int handle_request(void) {
    char buf[128];
    char cmd[256];
    int i;
    int total;

    total = 0;
    for (i = 0; i < 10; i++) {
        if (i % 2 == 0) {
            total = total + i;
        } else {
            total = total - i;
        }
    }

    fgets(buf, 128, stdin);
    sprintf(cmd, "echo %s", buf);
    system(cmd);
    printf(buf);
    return total;
}
