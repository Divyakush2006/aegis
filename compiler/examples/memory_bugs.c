#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int leaky(int n) {
    char *p;
    p = (char *) malloc(64);
    p[0] = 'a';
    return n;
}

int use_after_free(void) {
    char *q;
    q = (char *) malloc(32);
    if (q == 0) {
        return 1;
    }
    free(q);
    q[0] = 'x';
    return 0;
}

char *owned(void) {
    char *r;
    r = (char *) malloc(16);
    if (r == 0) {
        return 0;
    }
    return r;
}
