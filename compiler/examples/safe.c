#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Declared, not defined: Aegis treats it as a sanitizer via the spec table. */
char *escape_shell(char *s);

/* Bounded copy of a constant: no taint, no unbounded write. */
void greet(void) {
    char banner[32];
    strcpy(banner, "hello");
    printf("%s\n", banner);
}

/* Tainted input, but neutralised before it reaches the sink. */
void run_checked(void) {
    char raw[128];
    char *clean;

    fgets(raw, 128, stdin);
    clean = escape_shell(raw);
    system(clean);
}

/* Allocation is checked, used, and released on every path. */
int allocate_and_release(int n) {
    char *buffer;

    buffer = (char *) malloc(n);
    if (buffer == 0) {
        return -1;
    }
    buffer[0] = 0;
    free(buffer);
    return 0;
}
