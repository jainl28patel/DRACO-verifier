#ifndef __XDP_PROG_1
#define __XDP_PROG_1

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common_maps.h"

// Tests for update in array map
SEC("xdp_first")
int xdp_first_prog(struct xdp_md *ctx) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	struct ethhdr *eth;
	struct iphdr *ip;
	uint64_t nh_off = 0;
	__u32 *value;
	__u32 new_value = 0;
	__u32 array_key;
	void *target;
	eth = data;
	nh_off = sizeof(*eth);

	// Check if enough space for ethernet header
	if (data + nh_off > data_end)
		return XDP_DROP;

	// Check if ethernet protocol is IP
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		ip = data + nh_off;
		nh_off += sizeof(*ip);
		// Check if enough space for IP Header
		if (data + nh_off > data_end)
			return XDP_DROP;

		target = bpf_map_lookup_elem(&macs, &ip->daddr);
		if (!target)
			return XDP_DROP;
		__builtin_memcpy(eth->h_dest, target, sizeof(eth->h_dest));
		return XDP_PASS;
	}

	return XDP_PASS;
}

#endif // XDP_MAP_H
