#include "probe.h"
#include <sys/mount.h>
static void sync_fd(int fd, const char *label) {
  errno = 0;
  int rc = fcntl(fd, F_FULLFSYNC);
  int e = errno;
  event(label);
  printf(",\"rc\":%d,\"errno\":%d}", rc, e);
}
static void basics(const char *dir, const char *volume) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/store-file", dir);
  int fd = open(path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  event(volume);
  printf(",\"open_fd\":%d,\"errno\":%d}", fd, fd < 0 ? errno : 0);
  if (fd < 0)
    return;
  errno = 0;
  fstore_t store = {.fst_flags = F_ALLOCATEALL,
                    .fst_posmode = F_PEOFPOSMODE,
                    .fst_length = 16384};
  int rc = fcntl(fd, F_PREALLOCATE, &store);
  int e = errno;
  struct stat st = {0};
  int sr = fstat(fd, &st);
  event("preallocate");
  printf(",\"rc\":%d,\"errno\":%d,\"bytes_allocated\":%lld,\"fstat_rc\":%d,"
         "\"logical_size\":%lld}",
         rc, e, (long long)store.fst_bytesalloc, sr, (long long)st.st_size);
  char bytes[16384] = {0};
  errno = 0;
  ssize_t n = write(fd, bytes, sizeof(bytes));
  event("initial-write");
  printf(",\"returned\":%zd,\"errno\":%d}", n, errno);
  sync_fd(fd, "file-fullfsync");
  close(fd);
  int d = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (d >= 0) {
    sync_fd(d, "directory-fullfsync");
    close(d);
  }
  unlink(path);
}
static bool detach_image(const char *mount_path) {
  /* The argv helper takes non-const strings; detach never writes through it. */
  char *mount = (char *)mount_path;
  struct output detach = RUN_FOR(30000, "/usr/bin/hdiutil", "detach", mount);
  if (detach.status || detach.timeout)
    detach = RUN_FOR(30000, "/usr/bin/hdiutil", "detach", "-force", mount);
  return !detach.status && !detach.timeout;
}
int main(int argc, char **argv) {
  begin(argc, argv);
  basics(qual_out, "boot-volume");
  char image[PATH_MAX], mount[PATH_MAX];
  snprintf(image, sizeof(image), "%s/storage.dmg", qual_out);
  snprintf(mount, sizeof(mount), "%s/storage-mount", qual_out);
  if (mkdir(mount, 0700) && errno != EEXIST)
    _exit(2);
  resource("image", image);
  resource("mount", mount);
  bool attached = false;
  for (unsigned i = 0; i < 4; ++i) {
    char size[16];
    snprintf(size, sizeof(size), "%um", 4U << i);
    struct output create =
        RUN("/usr/bin/hdiutil", "create", "-fs", "APFS", "-size", size,
            "-volname", "scupper-qual", "-ov", image);
    if (create.status || create.timeout)
      continue;
    struct output attach = RUN("/usr/bin/hdiutil", "attach", "-nobrowse",
                               "-noverify", "-mountpoint", mount, image);
    if (!attach.status && !attach.timeout) {
      attached = true;
      event("minimum-image");
      printf(",\"mib\":%u}", 4U << i);
      break;
    }
    /* Failed attach can still leave a device; stop and let restore inspect
       hdiutil's image-path inventory rather than overwriting a live image. */
    if (!detach_image(mount)) {
      question("Q-STORE-image", -1, 0);
      return end();
    }
  }
  if (!attached) {
    question("Q-STORE-image", -1, 0);
    return end();
  }
  basics(mount, "image-volume");
  char existing[PATH_MAX], filler[PATH_MAX], exclusive[PATH_MAX];
  snprintf(existing, sizeof(existing), "%s/existing", mount);
  snprintf(filler, sizeof(filler), "%s/filler", mount);
  snprintf(exclusive, sizeof(exclusive), "%s/exclusive", mount);
  char data[16384] = {0};
  int old = open(existing, O_CREAT | O_EXCL | O_RDWR, 0600);
  if (old < 0 || write(old, data, sizeof(data)) != (ssize_t)sizeof(data))
    _exit(2);
  sync_fd(old, "existing-before-fill");
  int fill = open(filler, O_CREAT | O_EXCL | O_RDWR, 0600);
  if (fill < 0)
    _exit(2);
  uint64_t until = millis() + 15000, written = 0;
  ssize_t n = 0;
  int we = 0;
  while (millis() < until) {
    errno = 0;
    n = write(fill, data, sizeof(data));
    we = errno;
    if (n <= 0)
      break;
    written += (uint64_t)n;
  }
  event("fill");
  printf(",\"bytes\":%" PRIu64 ",\"last_write\":%zd,\"errno\":%d}", written, n,
         we);
  sync_fd(fill, "filler-fullfsync");
  /* Try one-byte writes to consume space remaining below the large write. */
  unsigned top_up = 0;
  ssize_t top_last = 0;
  int top_error = 0;
  while (top_up < 16384 && millis() < until) {
    errno = 0;
    top_last = write(fill, data, 1);
    top_error = errno;
    if (top_last != 1)
      break;
    ++top_up;
  }
  event("fill-top-up");
  printf(",\"bytes\":%u,\"last_write\":%zd,\"errno\":%d}", top_up, top_last,
         top_error);
  /* A new block at EOF, after the fill and top-up, is the full criterion.
     APFS can retain free metadata/reserved blocks after refusing user data. */
  errno = 0;
  ssize_t full_write = write(fill, data, 4096);
  int full_error = errno;
  event("full-fresh-block");
  printf(",\"requested\":4096,\"returned\":%zd,\"errno\":%d}", full_write,
         full_error);
  struct statfs fs = {0};
  errno = 0;
  int sr = statfs(mount, &fs);
  int se = errno;
  event("free-space");
  printf(",\"rc\":%d,\"errno\":%d,\"free_blocks\":%llu,\"available_blocks\":%"
         "llu,\"block_size\":%u}",
         sr, se, (unsigned long long)fs.f_bfree,
         (unsigned long long)fs.f_bavail, (unsigned)fs.f_bsize);
  errno = 0;
  n = pwrite(old, data, sizeof(data), 0);
  we = errno;
  event("full-overwrite");
  printf(",\"returned\":%zd,\"errno\":%d}", n, we);
  sync_fd(old, "overwrite-fullfsync");
  errno = 0;
  int ex = open(exclusive, O_CREAT | O_EXCL | O_RDWR, 0600);
  int ee = errno;
  event("full-exclusive-create");
  printf(",\"fd\":%d,\"errno\":%d}", ex, ee);
  if (ex >= 0) {
    errno = 0;
    n = write(ex, data, sizeof(data));
    we = errno;
    event("exclusive-write");
    printf(",\"returned\":%zd,\"errno\":%d}", n, we);
    sync_fd(ex, "exclusive-fullfsync");
    close(ex);
  }
  question("Q-STORE-full",
           full_write < 0 && full_error != ENOSPC
               ? -1
               : full_write == -1 && full_error == ENOSPC,
           1);
  close(fill);
  close(old);
  detach_image(mount);
  return end();
}
