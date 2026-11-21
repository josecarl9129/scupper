/* Harmless R4 fixture. Every long-lived mode has a 120-second hard lifetime. */
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    alarm(120);
    if (argc == 3 && strcmp(argv[1], "bootstrap") == 0) {
        char gate;
        if (read(12, &gate, 1) != 1 || gate != 'G') return 8;
        close(12);
        execl("/bin/launchctl", "launchctl", "bootstrap", "system", argv[2], (char *)NULL);
        return 9;
    }
    if (argc > 1 && strcmp(argv[1], "exit0") == 0) return 0;
    if (argc > 1 && strcmp(argv[1], "signals") == 0) {
        sigset_t mask;
        if (sigprocmask(SIG_SETMASK, NULL, &mask) != 0) return 2;
        printf("{\"signals\":[");
        int comma = 0;
        for (int n = 1; n < NSIG; ++n) {
            if (n == SIGKILL || n == SIGSTOP) continue;
            struct sigaction action;
            if (sigaction(n, NULL, &action) != 0) return 3;
            printf("%s{\"signal\":%d,\"blocked\":%d,\"default\":%s}",
                   comma++ ? "," : "", n, sigismember(&mask, n),
                   action.sa_handler == SIG_DFL ? "true" : "false");
        }
        printf("]}\n");
        return fflush(stdout) == 0 ? 0 : 4;
    }
    if (argc > 1 && strcmp(argv[1], "cap") == 0) {
        char buffer[4096]; memset(buffer, 'x', sizeof(buffer));
        for (int i = 0; i < 256; ++i) {
            if (write(STDOUT_FILENO, buffer, sizeof(buffer)) != sizeof(buffer)) return 5;
            if (write(STDERR_FILENO, buffer, sizeof(buffer)) != sizeof(buffer)) return 5;
        }
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "handoff") == 0) {
        char buffer[8] = {0};
        if (read(12, buffer, 7) != 7 || memcmp(buffer, "handoff", 7) != 0) return 6;
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "stall") == 0) {
        if (signal(SIGTERM, SIG_IGN) == SIG_ERR) return 7;
        /* Do not read stdin; keep stdout open until death. */
    }
    if (argc > 1 && strcmp(argv[1], "late") == 0) {
        close(STDIN_FILENO);
        sleep(1); close(STDOUT_FILENO);
        sleep(1); return 0;
    }
    /* Includes provisional -f utun: native spawn identity without creating utun. */
    sleep(110);
    return 0;
}
