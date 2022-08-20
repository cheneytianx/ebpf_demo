#include "../vmlinux.h"
#include "common.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, u32);
    __type(value, u32);
} event_buf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, struct event);
    __uint(max_entries, 1);
} heap SEC(".maps");



static void args_builder(struct task_struct *t, struct event *e)
{
    e->args_len = 0;

    struct mm_struct *mm = BPF_CORE_READ(t, mm);
    if (!mm) {
        return;
    }
    u64 arg_start, arg_end;
    bpf_core_read(&arg_start, sizeof(arg_start), &mm->arg_start);
    bpf_core_read(&arg_end, sizeof(arg_end), &mm->arg_end);
    
    if (!arg_start || !arg_end) {
        return;
    }

    int len = (arg_end-arg_start < MAX_ARGS_LEN) ? arg_end-arg_start : MAX_ARGS_LEN;
    bpf_core_read_user(e->args, len, arg_start);  // args
    e->args_len = len;
	bpf_printk("[%d]\n", len);
}


SEC("tp/sched/sched_process_exec")
int execve_lite(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event *e;
    int zero = 0;
    e = bpf_map_lookup_elem(&heap, &zero);
    if (!e) {
        return 0;
    }

    e->args_len = 0;

    // filename
    // https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.bpf.c
    u32 off = ctx->__data_loc_filename & 0xffff;  // ??
    int len = bpf_core_read_str(e->fname, FILENAME_LEN, (char *)ctx + off);
    if (len < 0) {
        e->fname[0] = '\0';
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    args_builder(task, e);
    e->pid = bpf_get_current_pid_tgid() >> 32;

    bpf_perf_event_output(ctx, &event_buf, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}