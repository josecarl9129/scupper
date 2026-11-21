/* Read-only qualification load: fork/exit/reap at a target of 200 per second. */
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t) != 0) _exit(2);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char *end = NULL;
    long seconds = strtol(argv[1], &end, 10);
    if (!end || *end || seconds < 1 || seconds > 180) return 2;
    double start = now();
    unsigned count = 0;
    while (now() - start < (double)seconds) {
        pid_t pid = fork();
        if (pid < 0) return 3;
        if (pid == 0) _exit(0);
        int status;
        pid_t reaped;
        do { reaped = waitpid(pid, &status, 0); } while (reaped < 0 && errno == EINTR);
        if (reaped != pid || !WIFEXITED(status) || WEXITSTATUS(status)) return 4;
        count++;
        double delay = start + (double)count / 200.0 - now();
        if (delay > 0) {
            struct timespec rest = { (time_t)delay, (long)((delay - (double)(time_t)delay) * 1e9) };
            while (nanosleep(&rest, &rest) != 0 && errno == EINTR) {}
        }
    }
    printf("{\"forks\":%u,\"elapsed_seconds\":%.6f,\"target_per_second\":200}\n", count, now() - start);
    return ferror(stdout) ? 5 : 0;
}
