/*
 * xdp_drop_port.c
 *
 * Drop packets for port '4420' on localhost.
 *
 * Load with:
 * ip link set dev lo xdpgeneric obj xdp_drop_port.o sec xdp_drop
 */
#include <stdio.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp_drop")
int xdp_drop_port(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *e = data;
    struct iphdr *i;
    struct tcphdr *t;
    __u16 h_proto;
    __u16 t_dest, t_source;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    h_proto = bpf_ntohs(e->h_proto);
    if (h_proto != ETH_P_IP)
        return XDP_PASS;

    i = data + sizeof (struct ethhdr);
    if (i + 1 > (struct iphdr *)data_end)
        return XDP_DROP;

    if (i->protocol != IPPROTO_TCP)
        return XDP_PASS;

    t = data + sizeof(struct ethhdr) + (i->ihl * 4);

    if (t + 1 > (struct tcphdr *)data_end)
        return XDP_DROP;

    /* Filter out SQE PDUs */
    t_dest = bpf_ntohs(t->dest);
    if (t_dest == 4420)
	    return XDP_DROP;
    /* Filter out CQE PDUs */
    t_source = bpf_ntohs(t->source);
    if (t_source == 4420)
	    return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
