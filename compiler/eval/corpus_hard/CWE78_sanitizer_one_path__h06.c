/* Sanitised on one path only. The union join keeps taint from the unsanitised
 * path, so this must still be reported - a "may" analysis is the right choice
 * for security. */
#include <stdio.h>
#include <stdlib.h>
extern int cond;
char *escape_shell(char *s);

void bad(void) {
    char data[64];
    char *use;
    fgets(data, 64, stdin);
    if (cond) { use = escape_shell(data); } else { use = data; }
    system(use);
}

void goodB2G(void) {
    char data[64];
    char *use;
    fgets(data, 64, stdin);
    if (cond) { use = escape_shell(data); } else { use = escape_shell(data); }
    system(use);
}
