/* Taint stored in a struct field, read back from another field.
 * The memory model is field-insensitive, so this is over-approximated. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct req { char cmd[64]; char host[64]; };

void bad(void) {
    struct req r;
    fgets(r.host, 64, stdin);
    system(r.host);
}

void goodG2B(void) {
    struct req r;
    strcpy(r.host, "localhost");
    system(r.host);
}
