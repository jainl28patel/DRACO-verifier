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
	struct simple_struct hash_key;
	klee_make_symbolic(&hash_key, sizeof(struct simple_struct), "simple_struct1");
	uint64_t nh_off = 0;
	__u32 *value;
	__u32 new_value = 0;
	__u32 array_key;
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

	hash_key.x = 42;
	hash_key.y = 10;
	// leave hash_key.c symbolic
	value = bpf_map_lookup_elem(&hash_map, &hash_key);
	if (!value)
		return XDP_DROP;

	array_key = 4;
  value = bpf_map_lookup_elem(&array_map, &array_key);
	if (!value)
		return XDP_DROP;

	array_key += 1;
	if (bpf_map_update_elem(&array_map, &array_key, &new_value, 0) < 0)
		return XDP_DROP;
	
	return XDP_PASS;
}

#endif // XDP_MAP_H
