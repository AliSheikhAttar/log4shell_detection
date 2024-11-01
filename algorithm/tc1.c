#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/// @tchook {"ifindex":1, "attach_point":"BPF_TC_INGRESS"}
/// @tcopts {"handle":1, "priority":1}
SEC("tc")
int tc_ingress(struct __sk_buff *ctx)
{
    void *data_end = (void *)(__u64)ctx->data_end;
    void *data = (void *)(__u64)ctx->data;
    struct ethhdr *l2;
    struct iphdr *l3;
    struct tcphdr *l4_tcp;
    struct udphdr *l4_udp;

    // Check if the packet is an IP packet
    if (ctx->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    l2 = data;
    if ((void *)(l2 + 1) > data_end)
        return TC_ACT_OK;

    l3 = (struct iphdr *)(l2 + 1);
    if ((void *)(l3 + 1) > data_end)
        return TC_ACT_OK;

    // Check if the packet is TCP or UDP
    if (l3->protocol == IPPROTO_TCP) {
        l4_tcp = (struct tcphdr *)(l3 + 1);
        if ((void *)(l4_tcp + 1) > data_end)
            return TC_ACT_OK;

        // Print source and destination ports for TCP
        bpf_printk("TCP packet: src_port: %d, dst_port: %d", bpf_ntohs(l4_tcp->source), bpf_ntohs(l4_tcp->dest));

    } else if (l3->protocol == IPPROTO_UDP) {
        l4_udp = (struct udphdr *)(l3 + 1);
        if ((void *)(l4_udp + 1) > data_end)
            return TC_ACT_OK;

        // Print source and destination ports for UDP
        bpf_printk("UDP packet: src_port: %d, dst_port: %d", bpf_ntohs(l4_udp->source), bpf_ntohs(l4_udp->dest));
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";



