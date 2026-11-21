#include "sc.h"
#include "spawn.h"
#include <pthread.h>
static const char *self_path;
struct burst_result {
  uint64_t start, end;
  unsigned successes;
};
struct sample {
  char key[160];
  uint64_t killed, absent;
  bool seen, reappeared;
};
struct snapshot {
  uint64_t at;
  unsigned count;
  char bits[51];
};
struct census {
  pthread_mutex_t mutex;
  struct sample samples[200];
  struct snapshot polls[2048];
  unsigned count, poll_count;
  uint64_t done;
  bool failed;
};
static void *lister(void *context) {
  struct census *c = context;
  SCDynamicStoreRef store = session();
  for (;;) {
    uint64_t start = millis();
    CFArrayRef keys = SCDynamicStoreCopyKeyList(
        store, CFSTR("^State:/Network/Service/scupper-qual-[0-9]+/DNS$"));
    pthread_mutex_lock(&c->mutex);
    if (!keys || c->poll_count == 2048) {
      c->failed = true;
      pthread_mutex_unlock(&c->mutex);
      if (keys)
        CFRelease(keys);
      break;
    }
    struct snapshot *poll = &c->polls[c->poll_count++];
    poll->at = start;
    poll->count = c->count;
    unsigned bits = 0;
    for (unsigned i = 0; i < c->count; ++i) {
      CFStringRef key = cfstr(c->samples[i].key);
      bool present = CFArrayContainsValue(
          keys, CFRangeMake(0, CFArrayGetCount(keys)), key);
      CFRelease(key);
      if (present)
        bits |= 1U << (i % 4);
      if (i % 4 == 3 || i + 1 == c->count) {
        poll->bits[i / 4] = "0123456789abcdef"[bits];
        bits = 0;
      }
      if (c->samples[i].killed > start)
        continue;
      if (present) {
        c->samples[i].seen = true;
        if (c->samples[i].absent)
          c->samples[i].reappeared = true;
      } else if (!c->samples[i].absent)
        c->samples[i].absent = millis();
    }
    bool done = c->done && start >= c->done + 10000;
    pthread_mutex_unlock(&c->mutex);
    CFRelease(keys);
    if (done)
      break;
    uint64_t elapsed = millis() - start;
    if (elapsed < 50)
      pause_ms((unsigned)(50 - elapsed));
  }
  CFRelease(store);
  return NULL;
}
/* Markers bound observation delays, not configd request ordering. */
static pid_t writer(const char *text, bool temporary, bool preadd,
                    int *marker) {
  int ready[2];
  if (pipe(ready))
    _exit(2);
  resource("key", text);
  char *args[] = {(char *)self_path,
                  "--writer",
                  (char *)text,
                  temporary ? "temporary" : "plain",
                  preadd ? "pre-add" : "ready",
                  NULL};
  pid_t pid = spawn_self(args, ready[1]);
  close(ready[1]);
  *marker = ready[0];
  return pid;
}
static int writer_main(char **argv) {
  await_gate();
  alarm(85);
  SCDynamicStoreRef s = session();
  CFStringRef key = cfstr(argv[2]);
  bool preadd = !strcmp(argv[4], "pre-add");
  if (preadd && write(3, "p", 1) != 1)
    return 2;
  Boolean ok = !strcmp(argv[3], "temporary")
                   ? SCDynamicStoreAddTemporaryValue(s, key, CFSTR("fixture"))
                   : SCDynamicStoreSetValue(s, key, CFSTR("fixture"));
  if (!ok)
    return 2;
  if (!preadd && write(3, "r", 1) != 1)
    return 2;
  for (;;)
    pause();
}
static void await_marker(int fd) {
  struct pollfd p = {.fd = fd, .events = POLLIN};
  char c;
  if (poll(&p, 1, 1000) != 1 || read(fd, &c, 1) != 1)
    _exit(2);
  close(fd);
}
int main(int argc, char **argv) {
  if (argc == 5 && !strcmp(argv[1], "--writer"))
    return writer_main(argv);
  if (argc == 2 && !strcmp(argv[1], "--burst")) {
    await_gate();
    alarm(10);
    SCDynamicStoreRef b = session();
    struct burst_result result = {.start = millis()};
    if (write(3, "b", 1) != 1)
      return 2;
    for (unsigned i = 0; i < 1000; ++i)
      if (SCDynamicStoreNotifyValue(
              b, CFSTR("State:/Network/Service/scupper-qual-burst/DNS")))
        ++result.successes;
    result.end = millis();
    if (write(3, &result, sizeof(result)) != (ssize_t)sizeof(result))
      return 2;
    CFRelease(b);
    return 0;
  }
  begin(argc, argv);
  self_path = argv[0];
  SCDynamicStoreRef s = session();
  struct census *c = calloc(1, sizeof(*c));
  if (!c || pthread_mutex_init(&c->mutex, NULL))
    _exit(2);
  struct sample *samples = c->samples;
  for (unsigned i = 0; i < 200; ++i)
    snprintf(samples[i].key, sizeof(samples[i].key),
             "State:/Network/Service/scupper-qual-%u/DNS", i);
  pthread_t thread;
  if (pthread_create(&thread, NULL, lister, c))
    _exit(2);
  for (unsigned i = 0; i < 200; ++i) {
    int marker;
    bool preadd = i >= 100;
    pid_t p = writer(samples[i].key, true, preadd, &marker);
    await_marker(marker);
    unsigned delay = arc4random_uniform(preadd ? 6 : 51);
    pause_ms(delay);
    kill(p, SIGKILL);
    pthread_mutex_lock(&c->mutex);
    samples[i].killed = millis();
    c->count = i + 1;
    pthread_mutex_unlock(&c->mutex);
    uint64_t reap = millis() + 1000;
    while (waitpid(p, NULL, WNOHANG) == 0 && millis() < reap)
      pause_ms(1);
    event("kill");
    printf(",\"iteration\":%u,\"phase\":\"%s\",\"delay_ms\":%u,\"killed_ms\":"
           "%" PRIu64 "}",
           i, preadd ? "pre-add" : "ready", delay, samples[i].killed);
  }
  pthread_mutex_lock(&c->mutex);
  c->done = millis();
  pthread_mutex_unlock(&c->mutex);
  if (pthread_join(thread, NULL))
    _exit(2);
  for (unsigned i = 0; i < c->poll_count; ++i) {
    event("key-poll");
    printf(",\"at_ms\":%" PRIu64 ",\"key_count\":%u,\"present_bits\":",
           c->polls[i].at, c->polls[i].count);
    string(c->polls[i].bits);
    putchar('}');
  }
  bool clean = true;
  for (unsigned i = 0; i < 200; ++i) {
    event("teardown");
    printf(",\"iteration\":%u,\"killed_ms\":%" PRIu64
           ",\"first_absent_ms\":%" PRIu64
           ",\"seen_after_kill\":%s,\"reappeared\":%s}",
           i, samples[i].killed, samples[i].absent,
           samples[i].seen ? "true" : "false",
           samples[i].reappeared ? "true" : "false");
    clean = clean && samples[i].absent &&
            samples[i].absent - samples[i].killed <= 10000 &&
            !samples[i].reappeared;
    remove_key(s, samples[i].key);
  }
  question("Q-SC-TEMPORARY-TEARDOWN", c->failed ? -1 : clean, 200);
  pthread_mutex_destroy(&c->mutex);
  free(c);
  const char *plain = "State:/Network/Service/scupper-qual-plain/DNS";
  int marker;
  pid_t p = writer(plain, false, false, &marker);
  await_marker(marker);
  kill(p, SIGKILL);
  waitpid(p, NULL, 0);
  pause_ms(50);
  CFStringRef key = cfstr(plain);
  question("Q-SC-PLAIN-PERSISTS", exists(s, key), 1);
  CFRelease(key);
  remove_key(s, plain);
  /* A separate session sends 1000 notifications while the parent times
     synchronous SetValue calls. Reply/FIFO proof remains a source review. */
  char *burst_args[] = {(char *)self_path, "--burst", NULL};
  int ready[2];
  if (pipe(ready))
    _exit(2);
  pid_t burst = spawn_self(burst_args, ready[1]);
  close(ready[1]);
  struct pollfd pollfd = {.fd = ready[0], .events = POLLIN};
  char marker_byte;
  if (poll(&pollfd, 1, 1000) != 1 || read(ready[0], &marker_byte, 1) != 1)
    _exit(2);
  for (unsigned i = 0; i < 20; ++i)
    (void)set_key(s, plain, CFSTR("timed"));
  struct burst_result burst_data = {0};
  if (poll(&pollfd, 1, 2000) != 1 ||
      read(ready[0], &burst_data, sizeof(burst_data)) !=
          (ssize_t)sizeof(burst_data))
    _exit(2);
  close(ready[0]);
  waitpid(burst, NULL, 0);
  event("notification-burst");
  printf(",\"requested\":1000,\"successes\":%u,\"started_ms\":%" PRIu64
         ",\"ended_ms\":%" PRIu64 "}",
         burst_data.successes, burst_data.start, burst_data.end);
  remove_key(s, plain);
  CFRelease(s);
  return end();
}
