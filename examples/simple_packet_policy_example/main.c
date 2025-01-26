#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

// #ifndef USES_BPF_MAP_LOOKUP_ELEM
// #define USES_BPF_MAP_LOOKUP_ELEM
// #endif

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

struct bpf_map_def SEC("maps") read_write = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 100,
};


SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	void* data     = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr  *ip;
	struct tcphdr *tcp;
	// char		  *payload;
	uint64_t nh_off = 0;

	eth = data;
	nh_off = sizeof(*eth);
	if (data  + nh_off  > data_end)
		return XDP_PASS;

	ip = data + nh_off;
	nh_off += sizeof(*ip);
	if (data + nh_off  > data_end)
		return XDP_PASS;

	if(ip->protocol != IPPROTO_TCP){
		return XDP_PASS;
	}

	tcp = data + nh_off;
	nh_off += sizeof(*tcp);
	if (data + nh_off  > data_end)
	 	goto EOP;

	// payload = data + nh_off;
	nh_off += 3;
	if (data + nh_off  > data_end)
		return XDP_PASS;

	int key = 1;
	int value = 42;

	// Valid map operations - read and write allowed
	bpf_map_update_elem(&read_write, &key, &value, BPF_ANY);

    // if(tcp->dest == htons(80)) {
    //     return XDP_PASS;
    // }

	return XDP_PASS;

    EOP:
        return XDP_DROP;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
int main() {
	// init maps
	BPF_MAP_INIT(&read_write, "read_write", "", "");

	// init the ctx
	struct pkt *pkt = malloc(sizeof(struct pkt));
	klee_make_symbolic(pkt, sizeof(struct pkt), "user_pkt");
	pkt->ether.h_proto = htons(ETH_P_IP);
	struct xdp_md test;
	test.data = (long)(&(pkt->ether));
	test.data_end = (long)(pkt + 1);
	test.data_meta = 0;
	test.ingress_ifindex = 0;

	// execute
	xdp_main(&test);
	return 0;
}
#endif