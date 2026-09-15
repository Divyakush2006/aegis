/* Format string selected through a pointer assignment. */
#include <stdio.h>

void bad(void) {
    char data[64];
    char *fmt;
    fgets(data, 64, stdin);
    fmt = data;
    printf(fmt);
}

void goodG2B(void) {
    char *fmt;
    fmt = "%s\n";
    printf(fmt, "safe");
}
