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
	uint64_t nh_off = 0;
	__u32 *value;
	eth = data;
	nh_off = sizeof(*eth);
	void *target;

	// Check if enough space for ethernet header
	if (data + nh_off > data_end)
		return XDP_DROP;

	target = eth->h_source;

	// Check if ethernet protocol is IP
	if (eth->h_proto == bpf_htons(ETH_P_IP))
		return XDP_PASS;

	if (!memcmp(eth->h_dest, target, sizeof(eth->h_dest))) {
		return XDP_PASS;
	}

	return XDP_PASS;
}

#endif // XDP_MAP_H
