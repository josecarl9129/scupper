#ifndef SCUPPER_QUAL_SPAWN_H
#define SCUPPER_QUAL_SPAWN_H
#include "probe.h"
#include <spawn.h>
/* Darwin <fcntl.h>: F_DUPFD_CLOEXEC. Keep every spawn source above the
   fixed child targets (0..4): self-dup2 does not clear FD_CLOEXEC on Darwin. */
static inline int high_fd(int fd) {
  int high = fcntl(fd, F_DUPFD_CLOEXEC, 10);
  if (high < 0)
    _exit(2);
  return high;
}
static inline void high_pipe(int p[2]) {
  int low[2];
  if (pipe(low))
    _exit(2);
  p[0] = high_fd(low[0]);
  p[1] = high_fd(low[1]);
  close(low[0]);
  close(low[1]);
}
/* The exec sentinel waits for a one-byte grant. If its parent dies before the
   journal commits, EOF closes inherited resources and the sentinel exits. */
static inline void await_gate(void) {
  char grant;
  if (read(4, &grant, 1) != 1)
    _exit(2);
  close(4);
}
static inline pid_t spawn_with_streams(char *const args[], int fd3,
                                       char *const env[], int streams[2]) {
  int gate[2], out[2] = {-1, -1}, err[2] = {-1, -1};
  high_pipe(gate);
  int source = fd3 >= 0 ? high_fd(fd3) : -1;
  if (streams) {
    high_pipe(out);
    high_pipe(err);
  }
  posix_spawnattr_t attr;
  posix_spawn_file_actions_t actions;
  if (posix_spawnattr_init(&attr) || posix_spawn_file_actions_init(&actions))
    _exit(2);
  if (posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT))
    _exit(2);
  if (source >= 0 && posix_spawn_file_actions_adddup2(&actions, source, 3))
    _exit(2);
  if (posix_spawn_file_actions_adddup2(&actions, gate[0], 4))
    _exit(2);
  for (int fd = 0; fd <= 2; ++fd) {
    if (streams && fd > 0) {
      if (posix_spawn_file_actions_adddup2(&actions, fd == 1 ? out[1] : err[1],
                                           fd))
        _exit(2);
    } else if (posix_spawn_file_actions_addopen(&actions, fd, "/dev/null",
                                                fd ? O_WRONLY : O_RDONLY, 0))
      _exit(2);
  }
  pid_t pid = -1;
  int rc = posix_spawn(&pid, args[0], &actions, &attr, args, env);
  posix_spawn_file_actions_destroy(&actions);
  posix_spawnattr_destroy(&attr);
  close(gate[0]);
  if (source >= 0)
    close(source);
  if (streams) {
    close(out[1]);
    close(err[1]);
    streams[0] = out[0];
    streams[1] = err[0];
    if (fcntl(out[0], F_SETFL, O_NONBLOCK) ||
        fcntl(err[0], F_SETFL, O_NONBLOCK))
      _exit(2);
  }
  event("posix-spawn");
  printf(",\"rc\":%d,\"pid\":%d,\"fd3_source\":%d}", rc, pid, source);
  if (rc) {
    close(gate[1]);
    if (streams) {
      close(streams[0]);
      close(streams[1]);
      streams[0] = streams[1] = -1;
    }
    return -1;
  }
  journal_child(pid, "child");
  if (write(gate[1], "x", 1) != 1)
    _exit(2);
  close(gate[1]);
  return pid;
}
static inline pid_t spawn_with_env(char *const args[], int fd3,
                                   char *const env[]) {
  return spawn_with_streams(args, fd3, env, NULL);
}
static inline pid_t spawn_self(char *const args[], int marker) {
  char *env[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};
  pid_t pid = spawn_with_env(args, marker, env);
  if (pid < 0)
    _exit(2);
  return pid;
}
#endif
