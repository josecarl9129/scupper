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
static int resolve_test(int udp, unsigned phase) {
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
  return queries ? 1 : result.rc == INT_MIN ? -1 : 0;
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
static const char *dns_key = "State:/Network/Service/scupper-qual-dns/DNS";
static const char *ipv4_key = "State:/Network/Service/scupper-qual-dns/IPv4";
static volatile sig_atomic_t undo_fd = -1;
/* Only async-signal-safe operations in the handler. The gated undo sentinel
   has its own SC session and removes both keys on alarm or unexpected EOF. */
static void hijack_alarm(int signal_number) {
  (void)signal_number;
  if (undo_fd >= 0)
    (void)write((int)undo_fd, "u", 1);
  _exit(124); /* also tears down the temporary owning SC session and utun */
}
static int undo_main(const char *out) {
  await_gate();
  alarm(12);
  struct pollfd p = {.fd = 3, .events = POLLIN};
  char command = 0;
  int ready = poll(&p, 1, 8500);
  if (ready > 0 && read(3, &command, 1) == 1 && command == 'd')
    return 0;
  SCDynamicStoreRef s = session();
  CFStringRef dns = cfstr(dns_key), ip = cfstr(ipv4_key);
  Boolean ip_removed = SCDynamicStoreRemoveValue(s, ip);
  int ip_error = SCError();
  Boolean dns_removed = SCDynamicStoreRemoveValue(s, dns);
  int dns_error = SCError();
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/dns-alarm-undo.json", out);
  int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd >= 0) {
    dprintf(fd,
            "{\"ipv4_removed\":%s,\"ipv4_sc_error\":%d,\"dns_removed\":%s,"
            "\"dns_sc_error\":%d}\n",
            ip_removed ? "true" : "false", ip_error,
            dns_removed ? "true" : "false", dns_error);
    fsync(fd);
    close(fd);
  }
  CFRelease(dns);
  CFRelease(ip);
  CFRelease(s);
  return 0;
}
static void network_phase(SCDynamicStoreRef s, unsigned phase) {
  event("phase-network");
  printf(",\"phase\":%u,\"key\":\"State:/Network/Global/IPv4\"", phase);
  CFPropertyListRef global =
      SCDynamicStoreCopyValue(s, CFSTR("State:/Network/Global/IPv4"));
  int error = global ? 0 : SCError();
  printf(",\"present\":%s,\"sc_error\":%d", global ? "true" : "false", error);
  if (global) {
    value_json(global);
    CFRelease(global);
  }
  putchar('}');
  (void)RUN("/usr/sbin/netstat", "-rn");
  (void)RUN("/usr/sbin/scutil", "--nwi");
}
static void measure_phase(SCDynamicStoreRef s, int udp, unsigned phase,
                          bool setup_ok, const char *default_question,
                          const char *effect_question) {
  pause_ms(200);
  network_phase(s, phase);
  struct output dns = RUN("/usr/sbin/scutil", "--dns");
  int effect = resolve_test(udp, phase);
  question(effect_question, setup_ok ? effect : -1, 1);
  question(default_question,
           !setup_ok || dns.status || dns.timeout ? -1 : resolver_one(dns.out),
           1);
}
static CFDictionaryRef ipv4_value(const char *name, bool router,
                                  bool override) {
  CFStringRef iface = cfstr(name);
  const void *address[] = {CFSTR("198.51.100.1")},
             *mask[] = {CFSTR("255.255.255.255")};
  CFArrayRef addresses =
                 CFArrayCreate(NULL, address, 1, &kCFTypeArrayCallBacks),
             masks = CFArrayCreate(NULL, mask, 1, &kCFTypeArrayCallBacks);
  int one = 1;
  CFNumberRef number = CFNumberCreate(NULL, kCFNumberIntType, &one);
  const void *keys[] = {kSCPropInterfaceName, kSCPropNetIPv4Addresses,
                        kSCPropNetIPv4SubnetMasks, NULL, NULL};
  const void *values[] = {iface, addresses, masks, NULL, NULL};
  CFIndex count = 3;
  if (router) {
    keys[count] = kSCPropNetIPv4Router;
    values[count++] = CFSTR("198.51.100.2");
  }
  if (override) {
    keys[count] = CFSTR("OverridePrimary");
    values[count++] = number;
  }
  CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, values, count,
                                            &kCFTypeDictionaryKeyCallBacks,
                                            &kCFTypeDictionaryValueCallBacks);
  CFRelease(iface);
  CFRelease(addresses);
  CFRelease(masks);
  CFRelease(number);
  return dict;
}
int main(int argc, char **argv) {
  if (argc == 3 && !strcmp(argv[1], "--dns-undo-child"))
    return undo_main(argv[2]);
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
  SCDynamicStoreRef s = session();
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
  network_phase(s, 0);
  (void)RUN("/usr/sbin/scutil", "--dns");
  int undo[2];
  high_pipe(undo);
  char *undo_args[] = {(char *)self_path, "--dns-undo-child", (char *)qual_out,
                       NULL};
  pid_t undo_pid = spawn_self(undo_args, undo[0]);
  close(undo[0]);
  undo_fd = undo[1];
  struct sigaction action = {0};
  action.sa_handler = hijack_alarm;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGALRM, &action, NULL))
    _exit(2);
  alarm(
      9); /* bound the active hijack; independent recovery covers the harness */
  CFDictionaryRef dict = dns_value(false);
  bool dns_ok = temporary_key(s, dns_key, dict);
  CFRelease(dict);
#ifndef QUAL_DNS_MINIMAL
  measure_phase(s, udp, 1, dns_ok, "Q-DNS-KEY-ALONE-DEFAULT",
                "Q-DNS-KEY-ALONE-EFFECT");
  int one = 1;
  CFNumberRef number = CFNumberCreate(NULL, kCFNumberIntType, &one);
  const void *keys[] = {CFSTR("OverridePrimary")}, *values[] = {number};
  dict =
      CFDictionaryCreate(NULL, keys, values, 1, &kCFTypeDictionaryKeyCallBacks,
                         &kCFTypeDictionaryValueCallBacks);
  bool base_ok = temporary_key(s, ipv4_key, dict);
  CFRelease(dict);
  CFRelease(number);
  measure_phase(s, udp, 2, dns_ok && base_ok, "Q-DNS-IPV4-OVERRIDE-DEFAULT",
                "Q-DNS-IPV4-OVERRIDE-EFFECT");
#endif
  char name[IFNAMSIZ] = {0};
  int fd = utun(0, name);
  if (fd >= 0) {
    struct output setup =
        RUN("/sbin/ifconfig", name, "inet", "198.51.100.1", "198.51.100.2",
            "netmask", "255.255.255.255", "up");
    bool configured = dns_ok && !setup.status && !setup.timeout;
#ifdef QUAL_DNS_MINIMAL
    /* Separate process/alarm budget for the two minimal dictionaries. Both
       replace the whole value so neither inherits fields from the prior phase.
     */
    dict = ipv4_value(name, false, true);
    bool no_router = temporary_key(s, ipv4_key, dict);
    CFRelease(dict);
    measure_phase(s, udp, 4, configured && no_router,
                  "Q-DNS-IPV4-NO-ROUTER-DEFAULT",
                  "Q-DNS-IPV4-NO-ROUTER-EFFECT");
    dict = ipv4_value(name, true, false);
    bool no_override = set_key(s, ipv4_key, dict);
    CFRelease(dict);
    measure_phase(s, udp, 5, configured && no_override,
                  "Q-DNS-IPV4-NO-OVERRIDE-DEFAULT",
                  "Q-DNS-IPV4-NO-OVERRIDE-EFFECT");
#else
    dict = ipv4_value(name, true, true);
    bool full = base_ok && set_key(s, ipv4_key, dict);
    CFRelease(dict);
    measure_phase(s, udp, 3, configured && full, "Q-DNS-IPV4-UTUN-DEFAULT",
                  "Q-DNS-IPV4-UTUN-EFFECT");
#endif
  } else {
#ifdef QUAL_DNS_MINIMAL
    question("Q-DNS-IPV4-NO-ROUTER-DEFAULT", -1, 0);
    question("Q-DNS-IPV4-NO-OVERRIDE-DEFAULT", -1, 0);
#else
    question("Q-DNS-IPV4-UTUN-DEFAULT", -1, 0);
#endif
  }
  remove_key(s, ipv4_key);
  remove_key(s, dns_key);
  if (fd >= 0)
    close(fd);
  alarm(0);
  if (write((int)undo_fd, "d", 1) != 1)
    _exit(2);
  close((int)undo_fd);
  undo_fd = -1;
  waitpid(undo_pid, NULL, 0);
  close(udp);
  CFRelease(s);
  return end();
}
