#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#include <linux/in.h>
#include <linux/if_ether.h>
#include "xdp_fw_kern.h"
#include <stdint.h>


// Tests for map correlation with computation in between
SEC("xdp_fw")
int xdp_fw_prog(struct xdp_md *ctx) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	struct ethhdr *eth;
	struct iphdr *ip;

	uint64_t nh_off = 0;
	__u32 check;
	__u32 *value;
	__u32 *otherValue;

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

	value = bpf_map_lookup_elem(&blacklist, &ip->saddr);
	if (!value)
		return XDP_DROP;

	check = *value;
	check *= ip->saddr;
	check -= 2;
	otherValue = bpf_map_lookup_elem(&otherlist, &check);

	if (!otherValue)
		return XDP_DROP;

	return XDP_PASS;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
int main(int argc, char** argv) {
	BPF_MAP_INIT(&blacklist, "blacklist_map", "", "");
	BPF_MAP_INIT(&otherlist, "otherlist_map", "", "");

	__u32 key = 3;
	
	struct pkt *pkt = malloc(sizeof(struct pkt));
	klee_make_symbolic(pkt, sizeof(struct pkt), "user_pkt");
	pkt->ether.h_proto = bpf_htons(ETH_P_IP);
	pkt->ipv4.saddr = key;

	struct xdp_md test;
  test.data = (long)(&(pkt->ether));
  test.data_end = (long)(pkt + 1);
  test.data_meta = 0;
  test.ingress_ifindex = 0;

	if (xdp_fw_prog(&test))
		return 1;
	return 0;
}

#endif