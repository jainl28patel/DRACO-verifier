#ifndef __XDP_PROG_2
#define __XDP_PROG_2

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common_maps.h"

static __always_inline __u16 calculate_csum(struct iphdr *ip) {
	return ip->check;
}

__u32 getNextAvailableIPAddress() {
	return 1;
}

// Tests for update in array map
SEC("xdp_second")
int xdp_nat(struct xdp_md *ctx) {
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

	value = bpf_map_lookup_elem(&outer2inner, &ip->saddr);
	if (!value) {
		__u32 newIP = getNextAvailableIPAddress();
		if (bpf_map_update_elem(&outer2inner, &ip->saddr, &newIP, 0) < 0)
			return XDP_DROP;
		if (bpf_map_update_elem(&inner2outer, &newIP, &ip->saddr, 0) < 0)
			return XDP_DROP;
		ip->saddr = newIP;
	} else {
		ip->saddr = *value;
	}

	ip->check = calculate_csum(ip);

	return XDP_PASS;
}

#endif // XDP_MAP_H
