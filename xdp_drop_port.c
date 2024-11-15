#include <stdio.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *e = data;
    struct iphdr *i;
    struct tcphdr *t;
    __u16 h_proto;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    h_proto = ntohs(e->h_proto);
    if (h_proto != ETH_P_IP)
        return XDP_PASS;

    i = data + sizeof (struct ethhdr);
    if (i + 1 > (struct iphdr *)data_end)
        return XDP_PASS;

    if (i->protocol != IPPROTO_TCP)
        return XDP_PASS;

    t = data + sizeof(struct ethhdr) + (i->ihl * 4);

    if (t + 1 > (struct tcphdr *)data_end)
        return XDP_PASS;

    if (t->source == htons(4420) || t->dest == htons(4420))
	return XDP_DROP;
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
