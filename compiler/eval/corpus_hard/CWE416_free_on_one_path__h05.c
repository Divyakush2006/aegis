/* Freed on one path only, then used unconditionally.
 * The join takes FREED, so this is detected. */
#include <stdlib.h>
extern int cond;

void bad(void) {
    char *p;
    p = (char *) malloc(32);
    if (p == 0) { return; }
    if (cond) { free(p); }
    p[0] = 'a';
    free(p);
}

void goodG2B(void) {
    char *p;
    p = (char *) malloc(32);
    if (p == 0) { return; }
    p[0] = 'a';
    free(p);
}
