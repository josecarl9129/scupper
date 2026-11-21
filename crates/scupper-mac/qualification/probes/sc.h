#ifndef SCUPPER_QUAL_SC_H
#define SCUPPER_QUAL_SC_H
#include "probe.h"
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
static inline CFStringRef cfstr(const char *text) {
  CFStringRef s = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
  if (!s)
    _exit(2);
  return s;
}
static inline SCDynamicStoreRef session(void) {
  SCDynamicStoreRef s =
      SCDynamicStoreCreate(NULL, CFSTR("scupper-qual"), NULL, NULL);
  if (!s)
    _exit(2);
  return s;
}
static inline bool exists(SCDynamicStoreRef s, CFStringRef key) {
  CFPropertyListRef v = SCDynamicStoreCopyValue(s, key);
  if (v) {
    CFRelease(v);
    return true;
  }
  if (SCError() != kSCStatusNoKey)
    _exit(2);
  return false;
}
static inline CFDictionaryRef dns_value(bool supplemental) {
  const void *server[] = {CFSTR("127.0.0.53")},
             *domain[] = {CFSTR("scupper-qual.invalid")};
  CFArrayRef servers = CFArrayCreate(NULL, server, 1, &kCFTypeArrayCallBacks),
             domains = CFArrayCreate(NULL, domain, 1, &kCFTypeArrayCallBacks);
  const void *keys[] = {kSCPropNetDNSServerAddresses,
                        kSCPropNetDNSSupplementalMatchDomains};
  const void *values[] = {servers, domains};
  CFDictionaryRef dict = CFDictionaryCreate(
      NULL, keys, values, supplemental ? 2 : 1, &kCFTypeDictionaryKeyCallBacks,
      &kCFTypeDictionaryValueCallBacks);
  CFRelease(servers);
  CFRelease(domains);
  if (!dict)
    _exit(2);
  return dict;
}
static inline void remove_key(SCDynamicStoreRef s, const char *text) {
  CFStringRef key = cfstr(text);
  Boolean rc = SCDynamicStoreRemoveValue(s, key);
  int e = SCError();
  event("remove-key");
  fputs(",\"key\":", stdout);
  string(text);
  printf(",\"ok\":%s,\"sc_error\":%d}", rc ? "true" : "false", e);
  CFRelease(key);
}
static inline void value_json(CFPropertyListRef value) {
  CFDataRef data = CFPropertyListCreateData(
      NULL, value, kCFPropertyListXMLFormat_v1_0, 0, NULL);
  if (!data)
    _exit(2);
  size_t n = (size_t)CFDataGetLength(data);
  if (n > 65536)
    _exit(2);
  char *text = calloc(n + 1, 1);
  if (!text)
    _exit(2);
  memcpy(text, CFDataGetBytePtr(data), n);
  fputs(",\"value_xml\":", stdout);
  string(text);
  free(text);
  CFRelease(data);
}
static inline bool set_key(SCDynamicStoreRef s, const char *text,
                           CFPropertyListRef value) {
  resource("key", text);
  CFStringRef key = cfstr(text);
  uint64_t start_ns = nanoseconds();
  uint64_t start = start_ns / 1000000;
  Boolean rc = SCDynamicStoreSetValue(s, key, value);
  int e = SCError();
  uint64_t elapsed_ns = nanoseconds() - start_ns;
  event("set-key");
  fputs(",\"key\":", stdout);
  string(text);
  value_json(value);
  printf(",\"ok\":%s,\"sc_error\":%d,\"elapsed_ms\":%" PRIu64
         ",\"started_ms\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 "}",
         rc ? "true" : "false", e, elapsed_ns / 1000000, start, elapsed_ns);
  CFRelease(key);
  return rc;
}
#endif
