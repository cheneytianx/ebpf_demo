//go:build ignore

#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[16]);  // name
    __type(value, u32);
    __uint(max_entries, 128);
} counter SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int syscall_count(void *ctx)
{
    char name[16] = {0};
    u32 cnt = 1;
    bpf_get_current_comm(&name, sizeof(name));


    u32 *exist = NULL;
    exist = bpf_map_lookup_elem(&counter, name);
    if (exist) {
        cnt = *exist + 1;
    }
    
    bpf_map_update_elem(&counter, name, &cnt, BPF_ANY);

    return 0;
}
