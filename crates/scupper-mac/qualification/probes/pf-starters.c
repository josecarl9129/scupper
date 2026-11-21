#include "pf_tokens.h"
int main(int argc, char **argv) {
  begin(argc, argv);
  event("layout");
  printf(",\"token_size\":%zu,\"request_size\":%zu,\"ioctl\":%lu}",
         sizeof(struct qual_token), sizeof(struct qual_tokens),
         (unsigned long)QUAL_GETSTARTERS);
  int fd = pf_open();
  int empty = fd < 0 ? errno : token_read(fd, 0, "empty");
  bool readonly = fd >= 0 && (empty == 0 || empty == ENOENT);
  if (!readonly) {
    if (fd >= 0)
      close(fd);
    errno = 0;
    fd = open("/dev/pf", O_RDWR | O_CLOEXEC);
    int e = errno;
    event("open");
    printf(",\"mode\":\"rdwr\",\"fd\":%d,\"errno\":%d}", fd, e);
    empty = fd < 0 ? e : token_read(fd, 0, "empty-rdwr");
  }
  if (argc == 3 && !strcmp(argv[2], "--inventory")) {
    if (fd >= 0) {
      (void)token_read(fd, 84 * 128, "inventory");
      close(fd);
    }
    return end();
  }
  question("Q-REFS-readonly",
           readonly                                     ? 1
           : fd >= 0 && (empty == 0 || empty == ENOENT) ? 0
                                                        : -1,
           1);
  if (fd < 0) {
    question("Q-REFS-empty", -1, 0);
    return end();
  }
  question("Q-REFS-empty", empty == ENOENT, 1);
  for (int j = 0; j < 4; ++j) {
    int n = (int[]){1, 2, 3, 8}[j];
    uint64_t tokens[8];
    for (int i = 0; i < n; ++i)
      tokens[i] = acquire();
    struct output text = refs();
    bool matched = text.status == 0 && !text.timeout;
    for (int i = 0; i < n; ++i) {
      char decimal[32];
      snprintf(decimal, sizeof(decimal), "%" PRIu64, tokens[i]);
      bool present = strstr(text.out, decimal) || strstr(text.err, decimal);
      event("text-crosscheck");
      printf(",\"n\":%d,\"token\":%" PRIu64 ",\"present_as_decimal\":%s}", n,
             tokens[i], present ? "true" : "false");
      matched = matched && present;
    }
    event("text-crosscheck-summary");
    printf(",\"n\":%d,\"all_acquired_tokens_in_text\":%s}", n,
           matched ? "true" : "false");
    int caps[] = {0, 83, 84, 85, 167, 168, n * 84, (n + 1) * 84};
    for (size_t c = 0; c < sizeof(caps) / sizeof(caps[0]); ++c) {
      event("series");
      printf(",\"acquired_count\":%d,\"acquisition_order\":[", n);
      for (int i = 0; i < n; ++i)
        printf("%s%" PRIu64, i ? "," : "", tokens[i]);
      fputs("]}", stdout);
      (void)token_read(fd, caps[c],
                       caps[c] == 0 ? "size-query" : "getstarters");
    }
    for (int i = 0; i < n; ++i) {
      if (!release(tokens[i])) {
        question("Q-REFS-release", -1, (unsigned)i);
        close(fd);
        return end();
      }
    }
  }
  (void)refs();
  close(fd);
  return end();
}
