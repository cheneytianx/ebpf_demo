#include <bpf/bpf.h>
#include <net/if.h>
#include <signal.h>
#include <sys/resource.h>

#include "tc.skel.h"
#include "common.h"

static volatile short exits = 0;

static void sig_handler(int sig)
{
    exits = 1;
    return;
}

int bump_memlock_rlimit()
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

int main()
{
    if (bump_memlock_rlimit() != 0) {
        printf("Fail to Unlock the resources limit. Are you root?\n");
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);  // make sure the attached prog exit properly

    struct tc_bpf *skel = tc_bpf__open_and_load();

    // -------------- tc 相关 ---------------
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, ops);

    u_int32_t eth_idx = if_nametoindex("eth0");

    hook.ifindex = eth_idx;
    hook.attach_point = BPF_TC_INGRESS;

    ops.prog_fd = bpf_program__fd(skel->progs.tc_ingress);
    ops.flags = BPF_TC_F_REPLACE;
    
    bpf_tc_hook_create(&hook);

    int err = bpf_tc_attach(&hook, &ops);
    if (err) {
        printf("Cannot attach\n");
        goto cleanup;
    }

    while (!exits) {

    }

cleanup:
    tc_bpf__destroy(skel);
    bpf_tc_hook_destroy(&hook);

    return 0;
}
