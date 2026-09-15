/* Taint flows out through three levels of return values. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *level3(void) { char *b; b = (char *) malloc(64); fgets(b, 64, stdin); return b; }
static char *level2(void) { return level3(); }
static char *level1(void) { return level2(); }

void bad(void) { system(level1()); }

void goodG2B(void) { system("ls -l"); }
