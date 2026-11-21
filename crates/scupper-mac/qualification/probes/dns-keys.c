#include "sc.h"
int main(int argc, char **argv) {
  begin(argc, argv);
  SCDynamicStoreRef s = session();
  const char *key = "State:/Network/Service/scupper-qual-dns/DNS";
  struct output before = RUN("/usr/sbin/scutil", "--dns");
  CFDictionaryRef value = dns_value(true);
  resource("cloned-route", "127.0.0.53");
  bool ok = set_key(s, key, value);
  CFRelease(value);
  pause_ms(250);
  (void)RUN("/usr/sbin/scutil", "--dns");
  remove_key(s, key);
  pause_ms(250);
  struct output after = RUN("/usr/sbin/scutil", "--dns");
  question(
      "Q-DNS-SUPPLEMENTAL-RESTORED",
      !ok || before.status || after.status || before.timeout || after.timeout
          ? -1
          : !strcmp(before.out, after.out) && !strcmp(before.err, after.err),
      1);
  CFRelease(s);
  return end();
}
