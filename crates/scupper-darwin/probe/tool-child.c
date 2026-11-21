/* Harmless R4 fixture. Every long-lived mode has a 120-second hard lifetime. */
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef CREATE_UTUN_NO_SOCKET
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/un.h>
#include <net/if.h>
#endif

int main(int argc, char **argv) {
    alarm(120);
    if (argc == 3 && strcmp(argv[1], "bootstrap") == 0) {
        char gate;
        if (read(12, &gate, 1) != 1 || gate != 'G') return 8;
        close(12);
        execl("/bin/launchctl", "launchctl", "bootstrap", "system", argv[2], (char *)NULL);
        return 9;
    }
    if (argc > 1 && strcmp(argv[1], "hold-fds") == 0) {
        printf("[");
        int comma = 0;
        for (int fd = 0; fd < 4096; ++fd) {
            if (fcntl(fd, F_GETFD) >= 0) printf("%s%d", comma++ ? "," : "", fd);
        }
        printf("]\n");
        if (fflush(stdout) != 0) return 10;
        sleep(1);
        return 0;
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
#ifdef CREATE_UTUN_NO_SOCKET
    if (argc > 1 && strcmp(argv[1], "-f") == 0) {
        int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) return 11;
        struct ctl_info info = {0};
        strlcpy(info.ctl_name, "com.apple.net.utun_control", sizeof(info.ctl_name));
        if (ioctl(fd, CTLIOCGINFO, &info) != 0) return 12;
        struct sockaddr_ctl address = {0};
        address.sc_len = sizeof(address);
        address.sc_family = AF_SYSTEM;
        address.ss_sysaddr = AF_SYS_CONTROL;
        address.sc_id = info.ctl_id;
        address.sc_unit = 0;
        if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) return 13;
#ifdef CREATE_UTUN_STALE_SOCKET
        char name[IFNAMSIZ] = {0};
        socklen_t size = sizeof(name);
        if (getsockopt(fd, SYSPROTO_CONTROL, 2 /* UTUN_OPT_IFNAME */, name, &size) != 0) return 14;
        struct sockaddr_un address_un = {0};
        address_un.sun_family = AF_UNIX;
        address_un.sun_len = sizeof(address_un);
        if (snprintf(address_un.sun_path, sizeof(address_un.sun_path),
                     "/var/run/wireguard/%s.sock", name) >= (int)sizeof(address_un.sun_path)) return 15;
        int listener = socket(AF_UNIX, SOCK_STREAM, 0);
        if (listener < 0 || bind(listener, (struct sockaddr *)&address_un, sizeof(address_un)) != 0) return 16;
        /* Bind without ever listening: even a fleeting listen/close interval
         * could legitimately satisfy a concurrent observation. Leave a root-
         * owned, single-link stale inode and a live utun. Journaled by R4. */
        close(listener);
#endif
        /* Neither fixture keeps a UAPI listener. The native adapter must refuse
         * this unit-derived name without provisional listener corroboration.
         * Closing/killing this journaled child destroys its kernel interface. */
        sleep(110);
        close(fd);
        return 0;
    }
#endif
    /* Includes provisional -f utun: native spawn identity without creating utun. */
    sleep(110);
    return 0;
}
