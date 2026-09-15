/* Ownership transferred to a helper that frees it. Passing a pointer to any
 * function is treated as an escape, so no leak is reported - correct here. */
#include <stdlib.h>

static void release(char *p) { free(p); }

void goodB2G(void) {
    char *p;
    p = (char *) malloc(32);
    if (p == 0) { return; }
    release(p);
}

void bad(void) {
    char *p;
    p = (char *) malloc(32);
    if (p == 0) { return; }
    p[0] = 'a';
}
