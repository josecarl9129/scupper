/* Scratch-only Q-PROC main-image and exec-bracket oracle. */
#define _DARWIN_C_SOURCE 1
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifndef IMAGE_VARIANT
#define IMAGE_VARIANT 1
#endif
int main(int argc, char **argv) {
    alarm(120);
    /* Force distinct LC_UUIDs for the two otherwise identical builds. */
    printf("ready-%d\n", IMAGE_VARIANT);
    fflush(stdout);
    if (argc == 3) {
        while (access(argv[2], F_OK) != 0) usleep(100);
        char *args[] = {argv[1], NULL};
        execv(argv[1], args);
        return 3;
    }
    if (argc != 1) return 2;
    for (;;) pause();
}
