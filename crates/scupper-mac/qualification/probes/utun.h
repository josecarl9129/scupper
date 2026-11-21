#ifndef SCUPPER_QUAL_UTUN_H
#define SCUPPER_QUAL_UTUN_H
#include "probe.h"
#include "spawn.h"
#include <net/if.h>
#include <spawn.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/un.h>
/* UTUN_OPT_IFNAME from XNU bsd/net/if_utun.h (not in all public SDKs). */
#define QUAL_UTUN_OPT_IFNAME 2
static inline int utun(unsigned unit, char name[IFNAMSIZ]) {
  errno = 0;
  int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  int socket_error = errno;
  struct ctl_info ci = {0};
  strcpy(ci.ctl_name, "com.apple.net.utun_control");
  errno = fd < 0 ? socket_error : 0;
  int rc = fd < 0 ? -1 : ioctl(fd, CTLIOCGINFO, &ci);
  struct sockaddr_ctl sa = {.sc_len = sizeof(sa),
                            .sc_family = AF_SYSTEM,
                            .ss_sysaddr = AF_SYS_CONTROL,
                            .sc_id = ci.ctl_id,
                            .sc_unit = unit};
  if (!rc)
    rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
  socklen_t len = IFNAMSIZ;
  if (!rc)
    rc = getsockopt(fd, SYSPROTO_CONTROL, QUAL_UTUN_OPT_IFNAME, name, &len);
  int error = errno;
  event("utun-create");
  printf(",\"requested_unit\":%u,\"rc\":%d,\"errno\":%d,\"name\":", unit, rc,
         error);
  string(rc ? "" : name);
  putchar('}');
  if (rc) {
    if (fd >= 0)
      close(fd);
    errno = error;
    return -1;
  }
  if (fcntl(fd, F_SETFD, FD_CLOEXEC))
    _exit(2);
  return fd;
}
static inline pid_t wireguard(const char *path, int fd, const char *name) {
  char socket_path[128];
  snprintf(socket_path, sizeof(socket_path), "/var/run/wireguard/%s.sock",
           name);
  struct stat old;
  if (!lstat(socket_path, &old) || errno != ENOENT)
    return -1;
  resource("socket", socket_path);
  char name_env[PATH_MAX + 64];
  snprintf(name_env, sizeof(name_env), "WG_TUN_NAME_FILE=%s/wg-name-%d",
           qual_out, getpid());
  char *env[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "WG_TUN_FD=3",
                 "LOG_LEVEL=error", name_env, NULL};
  char *args[] = {(char *)qual_self, "--handoff-child", (char *)qual_out,
                  (char *)path,      (char *)name,      NULL};
  return spawn_with_env(args, fd, env);
}
static inline int handoff_child(char **argv) {
  await_gate();
  if (fcntl(3, F_SETFD, 0))
    return 2;
  char *args[] = {argv[3], "-f", argv[4], NULL};
  execv(args[0], args);
  return 127;
}

static inline void kill_child(pid_t pid) {
  if (pid <= 1)
    return;
  kill(pid, SIGKILL);
  uint64_t until = millis() + 1000;
  while (waitpid(pid, NULL, WNOHANG) == 0 && millis() < until)
    pause_ms(5);
}
static inline int uapi(const char *name) {
  char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  snprintf(path, sizeof(path), "/var/run/wireguard/%s.sock", name);
  resource("socket", path);
  uint64_t until = millis() + 3000;
  struct sockaddr_un sa = {.sun_len = sizeof(sa), .sun_family = AF_UNIX};
  strcpy(sa.sun_path, path);
  int fd = -1, connect_error = 0;
  unsigned attempts = 0;
  do {
    ++attempts;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd >= 0 && !connect(fd, (struct sockaddr *)&sa, sizeof(sa)))
      break;
    connect_error = errno;
    if (fd >= 0)
      close(fd);
    fd = -1;
    pause_ms(10);
  } while (millis() < until);
  event("uapi-connect");
  printf(",\"fd\":%d,\"errno\":%d,\"attempts\":%u}", fd,
         fd < 0 ? connect_error : 0, attempts);
  if (fd < 0)
    return -1;
  struct timeval timeout = {.tv_sec = 1};
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
    _exit(2);
  errno = 0;
  ssize_t sent = write(fd, "get=1\n\n", 7);
  int write_error = errno;
  event("uapi-write");
  printf(",\"returned\":%zd,\"errno\":%d}", sent, write_error);
  if (sent != 7) {
    close(fd);
    return -1;
  }
  char reply[16384] = {0};
  size_t used = 0;
  ssize_t last_read = 0;
  int read_error = 0;
  while (used < sizeof(reply) - 1) {
    errno = 0;
    ssize_t n = read(fd, reply + used, sizeof(reply) - used - 1);
    last_read = n;
    read_error = errno;
    if (n <= 0)
      break;
    used += (size_t)n;
    if (strstr(reply, "\n\n"))
      break;
  }
  int ok = strstr(reply, "errno=0\n\n") != NULL;
  event("uapi-read");
  printf(",\"bytes\":%zu,\"last_read\":%zd,\"errno\":%d}", used, last_read,
         read_error);
  event("uapi-get");
  fputs(",\"socket\":", stdout);
  string(path);
  fputs(",\"reply\":", stdout);
  string(reply);
  putchar('}');
  close(fd);
  return last_read < 0 && !used ? -1 : ok;
}
#endif
