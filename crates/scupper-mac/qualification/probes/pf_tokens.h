#ifndef SCUPPER_QUAL_PF_TOKENS_H
#define SCUPPER_QUAL_PF_TOKENS_H
#include "probe.h"
#include <sys/ioctl.h>
/* XNU bsd/net/pfvar.h: private ABI, deliberately local to measurement code. */
struct qual_token {
  uint64_t token_value, timestamp;
  pid_t pid;
  char proc_name[64];
} __attribute__((packed));
struct qual_tokens {
  int size;
  union {
    void *pgt_buf;
    struct qual_token *pgt_tokens;
  } __attribute__((aligned(8)));
};
#define QUAL_GETSTARTERS _IOWR('D', 5, struct qual_tokens)
_Static_assert(QUAL_GETSTARTERS == 0xC0104405UL, "pf starters ioctl");
_Static_assert(sizeof(struct qual_token) == 84, "pf token stride");
_Static_assert(sizeof(struct qual_tokens) == 16, "pf request size");
static inline int pf_open(void) {
  errno = 0;
  int fd = open("/dev/pf", O_RDONLY | O_CLOEXEC);
  int e = errno;
  event("open");
  printf(",\"mode\":\"rdonly\",\"fd\":%d,\"errno\":%d}", fd, e);
  return fd;
}
static inline int token_read(int fd, int capacity, const char *label) {
  unsigned char bytes[84 * 128];
  memset(bytes, 0xa5, sizeof(bytes));
  if (capacity < 0 || capacity > (int)sizeof(bytes))
    _exit(2);
  struct qual_tokens p = {.size = capacity, .pgt_buf = bytes};
  errno = 0;
  int rc = ioctl(fd, QUAL_GETSTARTERS, &p);
  int e = errno;
  event(label);
  printf(",\"operation\":\"%s\",\"capacity\":%d,\"returned_size\":%d,"
         "\"rc\":%d,\"errno\":%d,"
         "\"tokens\":[",
         capacity == 0 ? "size-query" : "copy", capacity, p.size, rc, e);
  bool first = true;
  /* Only inspect whole slots within the caller's buffer. Sentinel detection
     records copies even if a failing ioctl did not copy its size field out. */
  for (int i = 0; i + 84 <= capacity; i += 84) {
    struct qual_token t;
    memcpy(&t, bytes + i, sizeof(t));
    if (t.token_value == UINT64_C(0xa5a5a5a5a5a5a5a5))
      break;
    if (!first)
      putchar(',');
    first = false;
    printf("{\"token\":%" PRIu64 ",\"timestamp\":%" PRIu64
           ",\"pid\":%d,\"proc_name\":",
           t.token_value, t.timestamp, t.pid);
    char name[65];
    memcpy(name, t.proc_name, 64);
    name[64] = 0;
    string(name);
    putchar('}');
  }
  fputs("]}", stdout);
  return rc == 0 ? 0 : e;
}
#endif
