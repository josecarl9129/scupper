#include "utun.h"
static bool socket_info(pid_t pid, int fd, struct socket_fdinfo *p) {
  errno = 0;
  int n = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, p, sizeof(*p));
  int e = errno;
  event("socket-info");
  printf(",\"pid\":%d,\"fd\":%d,\"returned\":%d,\"errno\":%d,\"family\":%d,"
         "\"kind\":%d,\"soi_so\":%" PRIu64 ",\"kcsi_unit\":%u,\"kcsi_name\":",
         pid, fd, n, e, p->psi.soi_family, p->psi.soi_kind, p->psi.soi_so,
         p->psi.soi_proto.pri_kern_ctl.kcsi_unit);
  char name[MAX_KCTL_NAME + 1];
  memcpy(name, p->psi.soi_proto.pri_kern_ctl.kcsi_name, MAX_KCTL_NAME);
  name[MAX_KCTL_NAME] = 0;
  string(name);
  putchar('}');
  return n == (int)sizeof(*p) && p->psi.soi_kind == SOCKINFO_KERN_CTL &&
         p->psi.soi_family == AF_SYSTEM;
}
int main(int argc, char **argv) {
  if (argc == 5 && !strcmp(argv[1], "--handoff-child"))
    return handoff_child(argv);
  begin(argc, argv);
  if (argc != 3)
    _exit(2);
  char name[IFNAMSIZ] = {0};
  int fd = utun(0, name);
  if (fd < 0) {
    question("Q-UTUN-HANDOFF", -1, 0);
    return end();
  }
  struct socket_fdinfo helper = {0}, child = {0};
  bool h = socket_info(getpid(), fd, &helper);
  pid_t pid = wireguard(argv[2], fd, name);
  int get = pid < 0 ? -1 : uapi(name, pid);
  bool c = pid > 1 && socket_info(pid, 3, &child);
  struct proc_fdinfo list[512] = {0};
  errno = 0;
  int n =
      pid > 1 ? proc_pidinfo(pid, PROC_PIDLISTFDS, 0, list, sizeof(list)) : -1;
  event("child-fds");
  printf(",\"returned\":%d,\"errno\":%d,\"fds\":[", n, errno);
  for (int i = 0; i < n / (int)sizeof(list[0]); ++i)
    printf("%s{\"fd\":%d,\"type\":%u}", i ? "," : "", list[i].proc_fd,
           list[i].proc_fdtype);
  fputs("]}", stdout);
  /* Pinned upstream only writes WG_TUN_NAME_FILE from CreateTUN("utun").
     WG_TUN_FD calls CreateTUNFromFile directly: identity uses helper name. */
  unsigned unit = (unsigned)strtoul(name + 4, NULL, 10) + 1;
  /* A different process attempts the exact occupied unit. */
  int gate[2], result_pipe[2];
  if (pipe(gate) || pipe(result_pipe))
    _exit(2);
  struct attempt {
    int rc, error;
    char name[IFNAMSIZ];
  } attempt = {0};
  pid_t contender = fork();
  if (!contender) {
    close(result_pipe[0]);
    close(gate[1]);
    char go;
    if (read(gate[0], &go, 1) != 1)
      _exit(2);
    close(gate[0]);
    int nullfd = open("/dev/null", O_WRONLY);
    if (nullfd < 0 || dup2(nullfd, 1) < 0)
      _exit(2);
    close(nullfd);
    close(fd);
    char other[IFNAMSIZ] = {0};
    int test = utun(unit, other);
    attempt.rc = test;
    attempt.error = errno;
    memcpy(attempt.name, other, sizeof(other));
    if (write(result_pipe[1], &attempt, sizeof(attempt)) !=
        (ssize_t)sizeof(attempt))
      _exit(2);
    close(result_pipe[1]);
    if (test >= 0)
      close(test);
    _exit(test >= 0 ? 1 : 0);
  }
  if (contender < 0)
    _exit(2);
  close(gate[0]);
  close(result_pipe[1]);
  journal_child(contender, "child");
  if (write(gate[1], "x", 1) != 1)
    _exit(2);
  close(gate[1]);
  /* Contender output cannot be interleaved into the parent's JSON. It inherits
     stdout, so disable its event output using a dedicated null descriptor. */
  int status = 0;
  if (waitpid(contender, &status, 0) != contender)
    _exit(2);
  if (read(result_pipe[0], &attempt, sizeof(attempt)) !=
      (ssize_t)sizeof(attempt))
    _exit(2);
  close(result_pipe[0]);
  event("same-unit-contender");
  printf(",\"rc\":%d,\"errno\":%d,\"name\":", attempt.rc, attempt.error);
  string(attempt.name);
  putchar('}');
  bool occupied = WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                  attempt.rc < 0 && attempt.error == EBUSY;
  bool killed = kill_child(pid);
  bool held = if_nametoindex(name) != 0;
  close(fd);
  uint64_t until = millis() + 2000;
  while (if_nametoindex(name) && millis() < until)
    pause_ms(10);
  bool gone = !if_nametoindex(name);
  event("lifetime");
  printf(",\"held_after_child_death\":%s,\"gone_after_close\":%s,\"contender_"
         "status\":%d}",
         held ? "true" : "false", gone ? "true" : "false", status);
  bool identity = h && c && helper.psi.soi_so != 0 &&
                  helper.psi.soi_so == child.psi.soi_so &&
                  helper.psi.soi_proto.pri_kern_ctl.kcsi_unit ==
                      child.psi.soi_proto.pri_kern_ctl.kcsi_unit &&
                  child.psi.soi_proto.pri_kern_ctl.kcsi_unit == unit &&
                  !strcmp(child.psi.soi_proto.pri_kern_ctl.kcsi_name,
                          "com.apple.net.utun_control");
  event("handoff-identity");
  printf(",\"same_socket_and_unit\":%s,\"child_killed_by_sigkill\":%s}",
         identity ? "true" : "false", killed ? "true" : "false");
  question("Q-UTUN-HANDOFF",
           pid < 0 || get < 0
               ? -1
               : identity && get && killed && held && gone && occupied,
           1);
  return end();
}
