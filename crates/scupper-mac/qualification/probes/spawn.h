#ifndef SCUPPER_QUAL_SPAWN_H
#define SCUPPER_QUAL_SPAWN_H
#include "probe.h"
#include <spawn.h>
/* The exec sentinel waits for a one-byte grant. If its parent dies before the
   journal commits, EOF closes inherited resources and the sentinel exits. */
static inline void await_gate(void) {
  char grant;
  if (read(4, &grant, 1) != 1)
    _exit(2);
  close(4);
}
static inline pid_t spawn_with_env(char *const args[], int fd3,
                                   char *const env[]) {
  int gate[2];
  if (pipe(gate))
    _exit(2);
  posix_spawnattr_t attr;
  posix_spawn_file_actions_t actions;
  if (posix_spawnattr_init(&attr) || posix_spawn_file_actions_init(&actions))
    _exit(2);
  if (posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT))
    _exit(2);
  if (fd3 >= 0 && posix_spawn_file_actions_adddup2(&actions, fd3, 3))
    _exit(2);
  if (posix_spawn_file_actions_adddup2(&actions, gate[0], 4))
    _exit(2);
  for (int fd = 0; fd <= 2; ++fd)
    if (posix_spawn_file_actions_addopen(&actions, fd, "/dev/null",
                                         fd ? O_WRONLY : O_RDONLY, 0))
      _exit(2);
  pid_t pid = -1;
  int rc = posix_spawn(&pid, args[0], &actions, &attr, args, env);
  posix_spawn_file_actions_destroy(&actions);
  posix_spawnattr_destroy(&attr);
  close(gate[0]);
  event("posix-spawn");
  printf(",\"rc\":%d,\"pid\":%d}", rc, pid);
  if (rc) {
    close(gate[1]);
    return -1;
  }
  journal_child(pid, "child");
  if (write(gate[1], "x", 1) != 1)
    _exit(2);
  close(gate[1]);
  return pid;
}
static inline pid_t spawn_self(char *const args[], int marker) {
  char *env[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};
  pid_t pid = spawn_with_env(args, marker, env);
  if (pid < 0)
    _exit(2);
  return pid;
}
#endif
