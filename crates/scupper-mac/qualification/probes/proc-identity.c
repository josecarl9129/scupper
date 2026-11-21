#include "utun.h"
#include <strings.h> /* Darwin strcasecmp */
/* XNU bsd/sys/proc_info_private.h; unavailable in the public SDK. */
struct qual_unique {
  uint8_t p_uuid[16];
  uint64_t p_uniqueid, p_puniqueid;
  int32_t p_idversion, p_orig_ppidversion;
  uint64_t p_reserve2, p_reserve3;
};
_Static_assert(sizeof(struct qual_unique) == 56, "unique identity layout");
static const char *file_uuids;
static bool identity_matches_file;
static bool identity_matches_r2_pin;
static uint64_t identify(pid_t pid, const char *phase) {
  char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
  errno = 0;
  int n = proc_pidpath(pid, path, sizeof(path));
  int pe = errno;
  struct qual_unique u = {0};
  errno = 0;
  int r =
      proc_pidinfo(pid, 17 /* PROC_PIDUNIQIDENTIFIERINFO */, 0, &u, sizeof(u));
  int ue = errno;
  event(phase);
  printf(",\"pid\":%d,\"path_returned\":%d,\"path_errno\":%d,\"path\":", pid, n,
         pe);
  string(path);
  printf(",\"unique_returned\":%d,\"unique_errno\":%d,\"p_uniqueid\":%" PRIu64
         ",\"p_puniqueid\":%" PRIu64 ",\"p_uuid\":\"",
         r, ue, u.p_uniqueid, u.p_puniqueid);
  for (int i = 0; i < 16; ++i)
    printf("%02x", u.p_uuid[i]);
  fputs("\"}", stdout);
  char uuid[37];
  snprintf(
      uuid, sizeof(uuid),
      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      u.p_uuid[0], u.p_uuid[1], u.p_uuid[2], u.p_uuid[3], u.p_uuid[4],
      u.p_uuid[5], u.p_uuid[6], u.p_uuid[7], u.p_uuid[8], u.p_uuid[9],
      u.p_uuid[10], u.p_uuid[11], u.p_uuid[12], u.p_uuid[13], u.p_uuid[14],
      u.p_uuid[15]);
  identity_matches_file =
      r == (int)sizeof(u) && file_uuids && strcasestr(file_uuids, uuid);
  identity_matches_r2_pin =
      r == (int)sizeof(u) &&
      !strcasecmp(uuid, "D4946FC0-C4E2-3F64-A76D-F48900B81CE7");
  event("uuid-comparison");
  fputs(",\"phase\":", stdout);
  string(phase);
  printf(",\"info_complete\":%s,\"file_has_lc_uuid\":%s,\"p_uuid_matches_file_"
         "slice\":%s}",
         r == (int)sizeof(u) ? "true" : "false",
         file_uuids && strstr(file_uuids, "UUID:") ? "true" : "false",
         file_uuids && strcasestr(file_uuids, uuid) ? "true" : "false");
  return r == (int)sizeof(u) ? u.p_uniqueid : 0;
}
static pid_t sleeper(const char *path) {
  char *args[] = {(char *)qual_self, "--sleep-child", (char *)path, NULL};
  pid_t pid = spawn_self(args, -1);
  pause_ms(30);
  return pid;
}

int main(int argc, char **argv) {
  if (argc == 3 && !strcmp(argv[1], "--sleep-child")) {
    await_gate();
    char *args[] = {argv[2], "30", NULL};
    execv(args[0], args);
    return 127;
  }
  if (argc == 5 && !strcmp(argv[1], "--handoff-child"))
    return handoff_child(argv);
  begin(argc, argv);
  if (argc != 3)
    _exit(2);
  char path[PATH_MAX], moved[PATH_MAX], hard[PATH_MAX];
  snprintf(path, sizeof(path), "%s/scratch-sleep", qual_out);
  snprintf(moved, sizeof(moved), "%s/renamed-sleep", qual_out);
  snprintf(hard, sizeof(hard), "%s/hard-sleep", qual_out);
  (void)RUN("/usr/bin/ditto", "/bin/sleep", path);
  (void)RUN("/usr/bin/otool", "-l", path);
  struct output sleep_uuids = RUN("/usr/bin/dwarfdump", "--uuid", path);
  file_uuids = sleep_uuids.out;
  pid_t p = sleeper(path);
  uint64_t one = identify(p, "before-unlink");
  int rc = unlink(path);
  event("unlink");
  printf(",\"rc\":%d,\"errno\":%d}", rc, rc ? errno : 0);
  (void)identify(p, "after-unlink");
  kill_child(p);
  (void)RUN("/usr/bin/ditto", "/bin/sleep", path);
  p = sleeper(path);
  uint64_t two = identify(p, "before-rename");
  rc = rename(path, moved);
  event("rename");
  printf(",\"rc\":%d,\"errno\":%d}", rc, rc ? errno : 0);
  (void)identify(p, "after-rename");
  kill_child(p);
  (void)RUN("/usr/bin/ditto", "/bin/sleep", path);
  p = sleeper(path);
  (void)identify(p, "before-hardlink");
  rc = link(path, hard);
  event("link");
  printf(",\"rc\":%d,\"errno\":%d}", rc, rc ? errno : 0);
  if (!rc) {
    rc = unlink(path);
    event("unlink-original");
    printf(",\"rc\":%d,\"errno\":%d}", rc, rc ? errno : 0);
  }
  (void)identify(p, "after-hardlink-unlink");
  kill_child(p);
  event("unique-comparison");
  printf(",\"first\":%" PRIu64 ",\"second\":%" PRIu64
         ",\"distinct\":%s,\"increasing\":%s}",
         one, two, one && two && one != two ? "true" : "false",
         one && two > one ? "true" : "false");
  (void)RUN("/usr/bin/otool", "-l", argv[2]);
  struct output wg_uuids = RUN("/usr/bin/dwarfdump", "--uuid", argv[2]);
  file_uuids = wg_uuids.out;
  question("Q-PROC-WG-LC-UUID",
           wg_uuids.status || wg_uuids.timeout
               ? -1
               : strstr(wg_uuids.out, "UUID:") != NULL,
           1);
  int wg_identity = -1;
  char name[IFNAMSIZ] = {0};
  int fd = utun(0, name);
  if (fd >= 0) {
    p = wireguard(argv[2], fd, name);
    if (p > 1) {
      int get = uapi(name, p);
      uint64_t unique = identify(p, "wireguard-go");
      event("wireguard-r2-pin-comparison");
      printf(",\"matches_file\":%s,\"matches_r2_uuid\":%s}",
             identity_matches_file ? "true" : "false",
             identity_matches_r2_pin ? "true" : "false");
      if (unique && get >= 0 && !wg_uuids.status && !wg_uuids.timeout)
        wg_identity = identity_matches_file && identity_matches_r2_pin && get;
      kill_child(p);
    }
    close(fd);
  }
  question("Q-PROC-WG-P-UUID", wg_identity, wg_identity < 0 ? 0 : 1);
  unlink(path);
  unlink(moved);
  unlink(hard);
  return end();
}
