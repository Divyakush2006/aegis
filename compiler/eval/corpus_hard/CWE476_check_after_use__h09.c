/* The NULL check happens after the dereference, which is still a defect. */
#include <stdlib.h>

void bad(void) {
    char *p;
    p = (char *) malloc(32);
    p[0] = 'a';
    if (p == 0) { return; }
    free(p);
}

void goodG2B(void) {
    char *p;
    p = (char *) malloc(32);
    if (p == 0) { return; }
    p[0] = 'a';
    free(p);
}
