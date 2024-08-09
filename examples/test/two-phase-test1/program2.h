#ifndef __XDP_PROG_2
#define __XDP_PROG_2



#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common_maps.h"

// Tests for update in array map
SEC("xdp_second")
int xdp_second_prog(struct xdp_md *ctx) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	struct ethhdr *eth;
	struct iphdr *ip;

	uint64_t nh_off = 0;
	__u32 *value;
	__u32 updateKey;
	__u32 updateValue = 229;

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

	// value = bpf_map_lookup_elem(&blacklist, &ip->saddr);
	updateKey = ip->saddr - 1;
	if (bpf_map_update_elem(&blacklist, &updateKey, &updateValue, 0) < 0)
		return XDP_DROP;

	return XDP_PASS;
}

#endif // XDP_MAP_H
