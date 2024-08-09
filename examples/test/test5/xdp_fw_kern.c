#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

#include <linux/in.h>
#include <linux/if_ether.h>
#include "xdp_fw_kern.h"
#include <stdint.h>


// Tests for update in hash map
SEC("xdp_fw")
int xdp_fw_prog(struct xdp_md *ctx) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	struct ethhdr *eth;
	struct iphdr *ip;
	__u32 updateKey = 5;
	__u32 updateValue = 10;

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

	if (bpf_map_update_elem(&blacklist, &updateKey, &updateValue, BPF_ANY) < 0) {
		return XDP_DROP;
	}
	
	return XDP_PASS;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
int main(int argc, char** argv) {
	BPF_MAP_INIT(&blacklist, "blacklist_map", "", "");

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