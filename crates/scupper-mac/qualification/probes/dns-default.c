#include "sc.h"
#include "spawn.h"
#include "utun.h"
static const char *self_path;
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
struct lookup_result {
  int rc, error;
};
static unsigned resolve_test(int udp, unsigned phase) {
  char *args[] = {(char *)self_path, "--resolve", NULL};
  int reply[2];
  if (pipe(reply))
    _exit(2);
  pid_t p = spawn_self(args, reply[1]);
  close(reply[1]);
  uint64_t until = millis() + 1000;
  unsigned queries = 0;
  int status = -1;
  bool reaped = false;
  while (millis() < until) {
    struct pollfd pollfd = {.fd = udp, .events = POLLIN};
    if (poll(&pollfd, 1, 20) > 0) {
      unsigned char packet[1500];
      struct sockaddr_in peer = {0};
      socklen_t len = sizeof(peer);
      ssize_t n = recvfrom(udp, packet, sizeof(packet), 0,
                           (struct sockaddr *)&peer, &len);
      if (n > 12) {
        static const unsigned char qname[] = {
            4,   'q', 'u', 'a', 'l', 7,   's', 'c', 'u', 'p', 'p',
            'e', 'r', 7,   'i', 'n', 'v', 'a', 'l', 'i', 'd', 0};
        bool ours = n >= (ssize_t)(12 + sizeof(qname) + 4) &&
                    !memcmp(packet + 12, qname, sizeof(qname));
        if (ours)
          ++queries;
        event("dns-query");
        printf(",\"phase\":%u,\"bytes\":%zd,\"packet_hex\":\"", phase, n);
        if (ours)
          for (ssize_t i = 0; i < n; ++i)
            printf("%02x", packet[i]);
        fputs("\"}", stdout);
        /* A positive loopback answer with TTL zero avoids carrying a negative
           result from the first phase into the next resolver experiment. */
        packet[2] = 0x81;
        packet[3] = ours ? 0x80 : 0x83;
        memset(packet + 6, 0, 6);
        if (ours && packet[12 + sizeof(qname)] == 0 &&
            packet[13 + sizeof(qname)] == 1) {
          size_t qend = 12 + sizeof(qname) + 4;
          static const unsigned char answer[] = {
              0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1};
          memcpy(packet + qend, answer, sizeof(answer));
          n = (ssize_t)(qend + sizeof(answer));
          packet[7] = 1;
        }
        (void)sendto(udp, packet, (size_t)n, 0, (struct sockaddr *)&peer, len);
      }
    }
    if (!reaped && waitpid(p, &status, WNOHANG) == p)
      reaped = true;
  }
  if (!reaped)
    kill_child(p);
  struct lookup_result result = {.rc = INT_MIN, .error = 0};
  struct pollfd result_fd = {.fd = reply[0], .events = POLLIN};
  if (poll(&result_fd, 1, 100) > 0) {
    if (read(reply[0], &result, sizeof(result)) != (ssize_t)sizeof(result))
      result.rc = INT_MIN;
  }
  close(reply[0]);
  event("effective-resolution");
  printf(",\"phase\":%u,\"queries_at_loopback_responder\":%u,\"getaddrinfo_"
         "wait_status\":%d,\"reaped\":%s,\"getaddrinfo_rc\":%d,\"getaddrinfo_"
         "errno\":%d}",
         phase, queries, status, reaped ? "true" : "false", result.rc,
         result.error);
  return queries;
}
static int resolver_one(const char *text) {
  const char *start = strstr(text, "resolver #1\n");
  if (!start)
    return -1;
  const char *end = strstr(start + 1, "resolver #");
  const char *ours = strstr(start, "127.0.0.53");
  return ours && (!end || ours < end);
}
static bool temporary_key(SCDynamicStoreRef s, const char *text,
                          CFPropertyListRef value) {
  resource("key", text);
  CFStringRef key = cfstr(text);
  Boolean ok = SCDynamicStoreAddTemporaryValue(s, key, value);
  int e = SCError();
  event("add-temporary-key");
  fputs(",\"key\":", stdout);
  string(text);
  value_json(value);
  printf(",\"ok\":%s,\"sc_error\":%d}", ok ? "true" : "false", e);
  CFRelease(key);
  return ok;
}
int main(int argc, char **argv) {
  if (argc == 2 && !strcmp(argv[1], "--resolve")) {
    await_gate();
    alarm(2);
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_DGRAM},
                    *result = NULL;
    errno = 0;
    int rc = getaddrinfo("qual.scupper.invalid", NULL, &hints, &result);
    struct lookup_result reply = {.rc = rc, .error = errno};
    if (write(3, &reply, sizeof(reply)) != (ssize_t)sizeof(reply))
      return 2;
    if (result)
      freeaddrinfo(result);
    return rc ? 1 : 0;
  }
  begin(argc, argv);
  self_path = argv[0];
  alarm(9); /* whole hijack, including optional utun phase, <10 s */
  SCDynamicStoreRef s = session();
  const char *dns = "State:/Network/Service/scupper-qual-dns/DNS",
             *ipv4 = "State:/Network/Service/scupper-qual-dns/IPv4";
  int udp = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp < 0)
    _exit(2);
  struct sockaddr_in addr = {
      .sin_len = sizeof(addr), .sin_family = AF_INET, .sin_port = htons(53)};
  if (inet_pton(AF_INET, "127.0.0.53", &addr.sin_addr) != 1)
    _exit(2);
  errno = 0;
  int rc = bind(udp, (struct sockaddr *)&addr, sizeof(addr));
  int be = errno;
  event("responder-bind");
  printf(",\"rc\":%d,\"errno\":%d}", rc, be);
  if (rc && be == EADDRNOTAVAIL) {
    resource("loopback-alias", "127.0.0.53");
    (void)RUN("/sbin/ifconfig", "lo0", "alias", "127.0.0.53", "netmask",
              "255.255.255.255");
    rc = bind(udp, (struct sockaddr *)&addr, sizeof(addr));
  }
  if (rc) {
    question("Q-DNS-DEFAULT", -1, 0);
    close(udp);
    CFRelease(s);
    return end();
  }
  (void)RUN("/usr/sbin/scutil", "--dns");
  CFDictionaryRef dict = dns_value(false);
  bool ok = temporary_key(s, dns, dict);
  CFRelease(dict);
  pause_ms(200);
  struct output only = RUN("/usr/sbin/scutil", "--dns");
  unsigned queries = resolve_test(udp, 1);
  question("Q-DNS-KEY-ALONE-EFFECT", queries ? 1 : -1, 1);
  int one = resolver_one(only.out);
  question("Q-DNS-KEY-ALONE-DEFAULT",
           !ok || only.status || only.timeout ? -1 : one, 1);
  int override = 1;
  CFNumberRef number = CFNumberCreate(NULL, kCFNumberIntType, &override);
  const void *override_keys[] = {CFSTR("OverridePrimary")},
             *override_values[] = {number};
  dict = CFDictionaryCreate(NULL, override_keys, override_values, 1,
                            &kCFTypeDictionaryKeyCallBacks,
                            &kCFTypeDictionaryValueCallBacks);
  bool base_ok = temporary_key(s, ipv4, dict);
  CFRelease(dict);
  pause_ms(200);
  struct output base = RUN("/usr/sbin/scutil", "--dns");
  int two = resolver_one(base.out);
  queries = resolve_test(udp, 2);
  question("Q-DNS-IPV4-OVERRIDE-DEFAULT",
           !base_ok || base.status || base.timeout ? -1 : two, 1);
  question("Q-DNS-IPV4-OVERRIDE-EFFECT", queries ? 1 : -1, 1);
  char name[IFNAMSIZ] = {0};
  int fd = two == 1 ? -1 : utun(0, name);
  if (fd >= 0) {
    CFStringRef iface = cfstr(name);
    const void *address[] = {CFSTR("198.51.100.1")},
               *mask[] = {CFSTR("255.255.255.255")};
    CFArrayRef addresses =
                   CFArrayCreate(NULL, address, 1, &kCFTypeArrayCallBacks),
               masks = CFArrayCreate(NULL, mask, 1, &kCFTypeArrayCallBacks);
    const void *keys[] = {CFSTR("OverridePrimary"), kSCPropInterfaceName,
                          kSCPropNetIPv4Addresses, kSCPropNetIPv4SubnetMasks,
                          kSCPropNetIPv4Router};
    const void *values[] = {number, iface, addresses, masks,
                            CFSTR("198.51.100.2")};
    dict = CFDictionaryCreate(NULL, keys, values, 5,
                              &kCFTypeDictionaryKeyCallBacks,
                              &kCFTypeDictionaryValueCallBacks);
    struct output setup =
        RUN("/sbin/ifconfig", name, "inet", "198.51.100.1", "198.51.100.2",
            "netmask", "255.255.255.255", "up");
    bool ip_ok =
        base_ok && !setup.status && !setup.timeout && set_key(s, ipv4, dict);
    CFRelease(dict);
    CFRelease(iface);
    CFRelease(addresses);
    CFRelease(masks);
    pause_ms(200);
    struct output both = RUN("/usr/sbin/scutil", "--dns");
    queries = resolve_test(udp, 3);
    question("Q-DNS-IPV4-UTUN-EFFECT", queries ? 1 : -1, 1);
    int three = resolver_one(both.out);
    question("Q-DNS-IPV4-UTUN-DEFAULT",
             !ip_ok || both.status || both.timeout ? -1 : three, 1);
    close(fd);
  } else if (two != 1)
    question("Q-DNS-IPV4-UTUN-DEFAULT", -1, 0);
  CFRelease(number);
  remove_key(s, ipv4);
  remove_key(s, dns);
  close(udp);
  CFRelease(s);
  return end();
}
