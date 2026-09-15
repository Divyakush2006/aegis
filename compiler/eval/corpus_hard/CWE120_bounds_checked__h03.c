/* An explicit length check makes the copy safe, but sizeof is not evaluated,
 * so the guard is not connected to the destination capacity. Expected FP. */
#include <stdio.h>
#include <string.h>

void goodB2G(void) {
    char dest[64];
    char data[64];
    fgets(data, 64, stdin);
    if (strlen(data) < 64) {
        strcpy(dest, data);
    }
}

void bad(void) {
    char dest[16];
    char data[64];
    fgets(data, 64, stdin);
    strcpy(dest, data);
}
