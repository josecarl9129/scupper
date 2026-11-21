/* SDK layout evidence. Rust layout comparisons follow with each binding. */
#define _DARWIN_C_SOURCE 1
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/kern_control.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <net/route.h>

/* Public SDKs do not ship proc_info_private.h. This API wire declaration
   is pinned to XNU bsd/sys/proc_info_private.h, proc_uniqidentifierinfo.
   Neither proc_bsdinfo nor extern_proc exposes p_idversion. */
struct proc_uniqidentifierinfo {
    uint8_t p_uuid[16];
    uint64_t p_uniqueid, p_puniqueid;
    int32_t p_idversion, p_orig_ppidversion;
    uint64_t p_reserve2, p_reserve3;
};
_Static_assert(sizeof(struct proc_uniqidentifierinfo) == 56, "identifier size");
_Static_assert(offsetof(struct proc_uniqidentifierinfo, p_idversion) == 32, "exec version offset");

#define BEGIN(type) printf("\"" #type "\":{\"size\":%zu,\"fields\":{", sizeof(struct type))
#define FIELD(type, field) printf("\"" #field "\":%zu", offsetof(struct type, field))
#define NEXT_FIELD(type, field) do { printf(",\"" #field "\":%zu", offsetof(struct type, field)); } while (0)
#define END() printf("}}")

/* Harness-only identity lookup. This keeps bootstrap restore signalling bound
   to microsecond process starts without introducing adapter process bindings. */
static int process_identity(const char *text) {
    char *end = NULL;
    errno = 0;
    long number = strtol(text, &end, 10);
    if (errno || !end || *end || number <= 1 || number > INT_MAX) {
        fprintf(stderr, "invalid process id\n");
        return 2;
    }
    struct proc_bsdinfo info = {0};
    int size = proc_pidinfo((int)number, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (size != (int)sizeof(info) || info.pbi_pid != (uint32_t)number) {
        int error = errno;
        printf("{\"error\":%d,\"returned\":%d}\n", error, size);
        fprintf(stderr, "proc_pidinfo(%ld): returned %d, expected %zu: %s\n",
                number, size, sizeof(info), strerror(error));
        return 3;
    }
    printf("{\"pid\":%u,\"ppid\":%u,\"pgid\":%u,\"status\":%u,\"start\":\"%" PRIu64 ":%" PRIu64 "\"}\n",
           info.pbi_pid, info.pbi_ppid, info.pbi_pgid, info.pbi_status,
           (uint64_t)info.pbi_start_tvsec, (uint64_t)info.pbi_start_tvusec);
    return ferror(stdout) ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--process-identity") == 0)
        return process_identity(argv[2]);
    if (argc != 1) {
        fprintf(stderr, "usage: abi-probe [--process-identity PID]\n");
        return 2;
    }
    printf("{");
    BEGIN(kinfo_proc);
    FIELD(kinfo_proc, kp_proc); NEXT_FIELD(kinfo_proc, kp_eproc);
    NEXT_FIELD(kinfo_proc, kp_proc.p_pid); NEXT_FIELD(kinfo_proc, kp_proc.p_stat);
    NEXT_FIELD(kinfo_proc, kp_proc.p_starttime);
    NEXT_FIELD(kinfo_proc, kp_proc.p_starttime.tv_sec);
    NEXT_FIELD(kinfo_proc, kp_proc.p_starttime.tv_usec);
    NEXT_FIELD(kinfo_proc, kp_proc.p_comm);
    NEXT_FIELD(kinfo_proc, kp_eproc.e_ppid); NEXT_FIELD(kinfo_proc, kp_eproc.e_pgid); END();
    printf(",\"MAXCOMLEN\":%d", MAXCOMLEN);
    printf(","); BEGIN(proc_bsdinfo);
    FIELD(proc_bsdinfo, pbi_uid); NEXT_FIELD(proc_bsdinfo, pbi_pid); NEXT_FIELD(proc_bsdinfo, pbi_ppid);
    NEXT_FIELD(proc_bsdinfo, pbi_pgid); NEXT_FIELD(proc_bsdinfo, pbi_comm);
    NEXT_FIELD(proc_bsdinfo, pbi_start_tvsec); NEXT_FIELD(proc_bsdinfo, pbi_start_tvusec); END();
    printf(","); BEGIN(proc_uniqidentifierinfo);
    FIELD(proc_uniqidentifierinfo, p_uuid);
    NEXT_FIELD(proc_uniqidentifierinfo, p_uniqueid);
    NEXT_FIELD(proc_uniqidentifierinfo, p_idversion); END();
    printf(","); BEGIN(proc_fdinfo);
    FIELD(proc_fdinfo, proc_fd); NEXT_FIELD(proc_fdinfo, proc_fdtype); END();
    printf(","); BEGIN(socket_fdinfo);
    FIELD(socket_fdinfo, pfi); NEXT_FIELD(socket_fdinfo, psi); END();
    printf(","); BEGIN(rt_msghdr2);
    FIELD(rt_msghdr2, rtm_msglen); NEXT_FIELD(rt_msghdr2, rtm_version);
    NEXT_FIELD(rt_msghdr2, rtm_addrs); NEXT_FIELD(rt_msghdr2, rtm_index); END();
    printf(","); BEGIN(kern_ctl_info);
    FIELD(kern_ctl_info, kcsi_id); NEXT_FIELD(kern_ctl_info, kcsi_reg_unit);
    NEXT_FIELD(kern_ctl_info, kcsi_unit); NEXT_FIELD(kern_ctl_info, kcsi_name); END();
    printf(","); BEGIN(vnode_info_path);
    FIELD(vnode_info_path, vip_vi); NEXT_FIELD(vnode_info_path, vip_path); END();
    printf("}\n");
    return ferror(stdout) ? 1 : 0;
}
