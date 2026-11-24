/* Compare net/pfvar.h with XNU-published layout/ioctl constants.
 * Public SDKs may omit the private header; then this is only an in-tree layout pin.
 * Source: apple-oss-distributions/xnu bsd/net/pfvar.h, pfioc_ruleset and ioctls. */
#include <sys/param.h>
#if __has_include(<net/pfvar.h>)
#define SCUPPER_RULESET_FROM_SDK "true"
#define SCUPPER_RULESET_LAYOUT_SOURCE "sdk-header"
#pragma message("ruleset ABI probe: net/pfvar.h present; checking XNU-published layout pins")
/* Keep the starter-layout mirror independent of SDK starter types. */
#define pfioc_token sdk_pfioc_token
#define pfioc_tokens sdk_pfioc_tokens
#include <net/pfvar.h>
#undef pfioc_token
#undef pfioc_tokens
#undef DIOCGETSTARTERS
#if !defined(DIOCGETRULESETS) || !defined(DIOCGETRULESET)
#error "net/pfvar.h lacks ruleset ioctls; ruleset ABI verification unavailable"
#endif
#else
#pragma message("ruleset ABI probe: net/pfvar.h absent; XNU-published layout pin, not SDK-verified")
#define SCUPPER_RULESET_FROM_SDK "false"
#define SCUPPER_RULESET_LAYOUT_SOURCE "xnu-published-pin"
struct pfioc_ruleset {
    uint32_t nr;
    char path[1024];
    char name[64];
};
#define DIOCGETRULESETS _IOWR('D', 58, struct pfioc_ruleset)
#define DIOCGETRULESET _IOWR('D', 59, struct pfioc_ruleset)
#endif
_Static_assert(sizeof(struct pfioc_ruleset) == 1092, "XNU ruleset size pin");
_Static_assert(_Alignof(struct pfioc_ruleset) == 4, "XNU ruleset alignment pin");
_Static_assert(offsetof(struct pfioc_ruleset, nr) == 0, "XNU ruleset nr pin");
_Static_assert(offsetof(struct pfioc_ruleset, path) == 4, "XNU ruleset path pin");
_Static_assert(offsetof(struct pfioc_ruleset, name) == 1028, "XNU ruleset name pin");
_Static_assert(DIOCGETRULESETS == 0xC444443AUL, "XNU getrulesets ioctl pin");
_Static_assert(DIOCGETRULESET == 0xC444443BUL, "XNU getruleset ioctl pin");
static void ruleset_layout(void) {
    printf("\"pfioc_ruleset\":{\"from_sdk_header\":%s,\"layout_source\":\"%s\",\"size\":%zu,"
           "\"fields\":{\"nr\":%zu,\"path\":%zu,\"name\":%zu}},"
           "\"DIOCGETRULESETS\":%lu,\"DIOCGETRULESET\":%lu,",
           SCUPPER_RULESET_FROM_SDK, SCUPPER_RULESET_LAYOUT_SOURCE,
           sizeof(struct pfioc_ruleset),
           offsetof(struct pfioc_ruleset, nr),
           offsetof(struct pfioc_ruleset, path),
           offsetof(struct pfioc_ruleset, name),
           (unsigned long)DIOCGETRULESETS, (unsigned long)DIOCGETRULESET);
}
