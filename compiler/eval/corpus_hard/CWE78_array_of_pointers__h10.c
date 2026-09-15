/* Taint through an array of pointers - requires points-to analysis. */
#include <stdio.h>
#include <stdlib.h>

void bad(void) {
    char *slots[4];
    char data[64];
    fgets(data, 64, stdin);
    slots[0] = data;
    system(slots[0]);
}

void goodG2B(void) {
    char *slots[4];
    slots[0] = "ls";
    system(slots[0]);
}
