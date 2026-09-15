/* Taint laundered through a file-scope global.
 * Globals are not SSA-renamed and carry no interprocedural summary. */
#include <stdio.h>
#include <stdlib.h>
char g_buf[128];

void load(void) { fgets(g_buf, 128, stdin); }

void bad(void) { load(); system(g_buf); }

void goodG2B(void) { strcpy(g_buf, "ls"); system(g_buf); }
