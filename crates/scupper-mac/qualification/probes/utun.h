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
#include <sys/un.h> /* Darwin SOL_LOCAL, LOCAL_PEERPID */
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
  int high = high_fd(fd);
  close(fd);
  return high;
}
static int wg_streams[2] = {-1, -1};
static pid_t wg_pid = -1;
static char wg_stdout[65536], wg_stderr[65536];
static size_t wg_out_used, wg_err_used;
static inline void wg_drain(void) {
  if (wg_streams[0] >= 0)
    drain(wg_streams[0], wg_stdout, &wg_out_used);
  if (wg_streams[1] >= 0)
    drain(wg_streams[1], wg_stderr, &wg_err_used);
}
static inline pid_t wireguard(const char *path, int fd, const char *name) {
  char socket_path[128];
  snprintf(socket_path, sizeof(socket_path), "/var/run/wireguard/%s.sock",
           name);
  struct stat old;
  if (!lstat(socket_path, &old) || errno != ENOENT)
    return -1;
  resource("socket", socket_path);
  char *env[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "WG_TUN_FD=3",
                 "LOG_LEVEL=verbose", NULL};
  char *args[] = {(char *)qual_self, "--handoff-child", (char *)qual_out,
                  (char *)path,      (char *)name,      NULL};
  wg_pid = spawn_with_streams(args, fd, env, wg_streams);
  return wg_pid;
}
static inline int handoff_child(char **argv) {
  await_gate();
  errno = 0;
  int flags = fcntl(3, F_GETFD);
  int error = errno;
  dprintf(2, "handoff-trampoline fd=3 F_GETFD=%d errno=%d\n", flags, error);
  if (flags < 0 || fcntl(3, F_SETFD, 0))
    return 2;
  char *args[] = {argv[3], "-f", argv[4], NULL};
  execv(args[0], args);
  return 127;
}

static inline bool kill_child(pid_t pid) {
  if (pid <= 1)
    return false;
  errno = 0;
  int killed = kill(pid, SIGKILL), kill_error = errno;
  uint64_t until = millis() + 1000;
  int status = 0;
  pid_t reaped;
  do {
    if (pid == wg_pid)
      wg_drain();
    reaped = waitpid(pid, &status, WNOHANG);
    if (reaped != 0)
      break;
    pause_ms(5);
  } while (millis() < until);
  event("child-wait");
  printf(",\"pid\":%d,\"kill_rc\":%d,\"kill_errno\":%d,\"wait_returned\":%d,"
         "\"wait_status\":%d,\"exit_code\":%d,\"signal\":%d}",
         pid, killed, kill_error, reaped, status,
         reaped == pid && WIFEXITED(status) ? WEXITSTATUS(status) : -1,
         reaped == pid && WIFSIGNALED(status) ? WTERMSIG(status) : 0);
  if (pid == wg_pid) {
    wg_drain();
    event("wireguard-output");
    fputs(",\"stdout\":", stdout);
    string(wg_stdout);
    fputs(",\"stderr\":", stdout);
    string(wg_stderr);
    putchar('}');
    close(wg_streams[0]);
    close(wg_streams[1]);
    wg_streams[0] = wg_streams[1] = -1;
  }
  return reaped == pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
}

static inline int uapi(const char *name, pid_t expected_pid) {
  char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  snprintf(path, sizeof(path), "/var/run/wireguard/%s.sock", name);
  resource("socket", path);
  uint64_t until = millis() + 3000;
  struct sockaddr_un sa = {.sun_len = sizeof(sa), .sun_family = AF_UNIX};
  strcpy(sa.sun_path, path);
  int fd = -1, connect_error = 0;
  unsigned attempts = 0;
  do {
    wg_drain();
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
  pid_t peer = -1;
  socklen_t peer_len = sizeof(peer);
  errno = 0;
  int peer_rc = getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &peer, &peer_len);
  int peer_error = errno;
  bool peer_ok = !peer_rc && peer_len == sizeof(peer) && peer == expected_pid;
  event("uapi-peer");
  printf(",\"rc\":%d,\"errno\":%d,\"peer_pid\":%d,\"expected_pid\":%d,"
         "\"matches\":%s}",
         peer_rc, peer_error, peer, expected_pid, peer_ok ? "true" : "false");
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
  return last_read < 0 && !used ? -1 : ok && peer_ok;
}
#endif
