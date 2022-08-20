#include "../vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct iphdr* get_ipv4_hdr(struct ethhdr *eth, void *data_end) 
{
    struct iphdr *iph = NULL;
    if (!eth || !data_end) {
        return NULL;
    }
    if ((void*)eth + sizeof(*eth) + sizeof(*iph) > data_end) {
        return NULL;
    }
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {  // ipv4
        iph = (struct iphdr*)((void*)eth + sizeof(*eth));
    }
    return iph;
}

struct tcphdr* get_tcp_hdr(struct iphdr *iph, void *data_end)
{
    struct tcphdr *tcph = NULL;
    if ((void*)iph + sizeof(*iph) + sizeof(*tcph) > data_end) {
        return NULL;
    }
    if (iph->protocol != IPPROTO_TCP) {
        return NULL;
    }
    tcph = (struct tcphdr*)((void*)iph + sizeof(*iph));
    return tcph;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    void *data_end = (void*)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr*)(void*)(long)skb->data;

    struct iphdr *iph = get_ipv4_hdr(eth, data_end);
    if (!iph) {
        return TC_ACT_UNSPEC;  // pass, not ipv4
    }

    struct tcphdr *tcph = get_tcp_hdr(iph, data_end);
    if (!tcph) {
        return TC_ACT_UNSPEC;  // pass, not tcp
    }

    char payload[PAYLOAD_PREFIX_LEN] = {0};
    u16 offset = sizeof(*eth) + sizeof(*iph) + (tcph->doff << 2);
    bpf_skb_load_bytes(skb, offset, payload, PAYLOAD_PREFIX_LEN);

    // check whether it is a http response packet
    if (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P') {
        return TC_ACT_SHOT;
    }
    return TC_ACT_UNSPEC;
}
