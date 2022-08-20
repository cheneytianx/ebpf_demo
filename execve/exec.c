#include <bpf/bpf.h>
#include <sys/resource.h>
#include <unistd.h>

#include "exec.skel.h"

#include "common.h"

int bump_memlock_rlimit()
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct event *e = data;
    char c;
    printf("pid: %d\n", e->pid);
    printf("exe: %s\n", e->fname);
    printf("args: ");
    for (int i = 0; i < e->args_len; ++i) {
        c = e->args[i];
        if (c == '\0') {
            c = ' ';
        }
        putchar(c);
    }
    putchar('\n');

    printf("\n");
    return;
}

int main()
{
    if (bump_memlock_rlimit() != 0) {
        printf("[err] Failed to increase RLIMIT_MEMLOCK limit\n");
        exit(1);
    }

    struct exec_bpf *skel = exec_bpf__open();
    exec_bpf__load(skel);
    exec_bpf__attach(skel);

    int pb_fd = bpf_map__fd(skel->maps.event_buf);
    if (pb_fd < 0) {
        printf("[err] fail to open perf buffer\n");
        exit(1);
    }
    struct perf_buffer *pb = perf_buffer__new(pb_fd, 8, handle_event, NULL, NULL, NULL);

    while (1) {
        perf_buffer__poll(pb, 100);
    }
    return 0;
}