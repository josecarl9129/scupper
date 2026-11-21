#include "pf_tokens.h"
int main(int argc, char **argv) {
  begin(argc, argv);
  if (enabled() != 0) {
    question("Q-EEXIST", -1, 0);
    return end();
  }
  uint64_t t = acquire();
  struct output a = pf("-e");
  bool release_a = release(t);
  int a_on = enabled();
  (void)pf("-d");
  t = acquire();
  bool release_control = release(t);
  int control = enabled();
  (void)pf("-d");
  struct output first = pf("-e"), second = pf("-e");
  t = acquire();
  bool release_anonymous = release(t);
  int anonymous = enabled();
  (void)pf("-d");
  t = acquire();
  bool release_cleared = release(t);
  int cleared = enabled();
  t = acquire();
  (void)pf("-d");
  int fd = pf_open();
  if (fd >= 0) {
    int error = token_read(fd, 84 * 128, "after-disable-live-token");
    close(fd);
    if (error && error != ENOENT) {
      errno = 0;
      fd = open("/dev/pf", O_RDWR | O_CLOEXEC);
      int e = errno;
      event("open-rdwr");
      printf(",\"fd\":%d,\"errno\":%d}", fd, e);
      if (fd >= 0) {
        (void)token_read(fd, 84 * 128, "after-disable-live-token-rdwr");
        close(fd);
      }
    }
  }
  (void)refs();
  release(t);
  (void)refs();
  bool complete = release_a && release_control && release_anonymous &&
                  release_cleared && !a.timeout && !first.timeout &&
                  !second.timeout && a_on >= 0 && control >= 0 &&
                  anonymous >= 0 && cleared >= 0;
  question("Q-EEXIST",
           !complete ? -1
                     : (a.status != 0 && a_on == 1 && control == 0 &&
                        first.status == 0 && second.status != 0 &&
                        anonymous == 1 && cleared == 0),
           1);
  (void)pf("-d");
  return end();
}
