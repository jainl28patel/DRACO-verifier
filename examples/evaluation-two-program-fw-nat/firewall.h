#ifndef __XDP_PROG_1
#define __XDP_PROG_1

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common_maps.h"

// Tests for update in array map
SEC("xdp_first")
int xdp_fw(struct xdp_md *ctx) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	struct ethhdr *eth;
	struct iphdr *ip;

	uint64_t nh_off = 0;
	__u32 *value;

	eth = data;
	nh_off = sizeof(*eth);

	// Check if enough space for ethernet header
	if (data + nh_off > data_end)
		return XDP_DROP;

	// Check if ethernet protocol is IP
	if(eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_DROP;

	ip = data + nh_off;
	nh_off += sizeof(*ip);
	// Check if enough space for IP Header
	if (data + nh_off > data_end)
		return XDP_DROP;

	value = bpf_map_lookup_elem(&whitelist_addresses, &ip->saddr);
	if (!value)
		return XDP_DROP;

	return XDP_PASS;
}

#endif // XDP_MAP_H
