#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

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

struct bpf_map_def SEC("maps") read_only = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") write_only = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") read_write = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") no_access = {
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
		goto EOP;

	ip = data + nh_off;
	nh_off += sizeof(*ip);
	if (data + nh_off  > data_end)
		goto EOP;

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
		goto EOP;

	int key = 1;
	int value = 42;
	int *result;

	// Valid map operations - read and write allowed
	bpf_map_update_elem(&read_write, &key, &value, BPF_ANY);
	result = bpf_map_lookup_elem(&read_write, &key);

	// // Invalid map operations - attempt write to read-only map
	key = 2;
	value = 100;
	bpf_map_update_elem(&no_access, &key, &value, BPF_ANY); // This should fail verification
	
	// Valid map operations - read from read-only map
	key = 1;
	result = bpf_map_lookup_elem(&read_only, &key);
	if (result && *result == 100) { // This should pass verification since read is allowed
		return XDP_DROP;
	}

	return XDP_PASS;
	EOP:
		return XDP_DROP;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
int main() {
	// init maps
	BPF_MAP_INIT(&read_only, "read_only", "", "");
	BPF_MAP_INIT(&read_write, "read_write", "", "");
	BPF_MAP_INIT(&no_access, "no_access", "", "");
	BPF_MAP_INIT(&write_only, "write_only", "", "");

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