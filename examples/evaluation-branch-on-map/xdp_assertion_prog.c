#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

// #ifndef USES_BPF_MAP_UPDATE_ELEM
// #define USES_BPF_MAP_UPDATE_ELEM
// #endif

#include <linux/in.h>
#include <linux/if_ether.h>
#include "xdp_assertion_prog.h"
#include <stdint.h>
#include "../../verification_tools/verification_helpers.h"


// Tests for lookup in array map, and then compare returned value
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	struct ethhdr *eth;
	struct iphdr *ip;

	uint64_t nh_off = 0;
	struct addressInfo *saddr_info;
	__u32 value;
	__u32 MAX_VALUE = 1024;

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

	saddr_info = bpf_map_lookup_elem(&sourceAddressInfo, &ip->saddr);
	if (!saddr_info)
		return XDP_DROP;

	value = saddr_info->count;

	if (value > MAX_VALUE)
		assert(0);

	return XDP_PASS;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
int main(int argc, char** argv) {
	// int key = 5;
	// int count = 1555;
	BPF_MAP_INIT(&sourceAddressInfo, "sourceAddressInfo", "", "");

	// if (bpf_map_update_elem(&sourceAddressInfo, &key, &count, 0) < 0)
	// 	return XDP_DROP;

	struct pkt *pkt = malloc(sizeof(struct pkt));
	klee_make_symbolic(pkt, sizeof(struct pkt), "user_pkt");
	pkt->ether.h_proto = bpf_htons(ETH_P_IP);
	// pkt->ipv4.saddr = key;
	assume_map_does_not_contain_key(&sourceAddressInfo, &pkt->ipv4.saddr);
	struct xdp_md test;
  test.data = (long)(&(pkt->ether));
  test.data_end = (long)(pkt + 1);
  test.data_meta = 0;
  test.ingress_ifindex = 0;

	if (xdp_prog(&test))
		return 1;
	return 0;
}

#endif