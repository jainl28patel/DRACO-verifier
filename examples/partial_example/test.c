#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <netinet/in.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#include <bpf/bpf_helpers.h>
#include "../../verification_tools/weak_partial_spec.h"

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

// struct {
// __uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key, int);
// 	__type(value, int);
// 	__uint(max_entries, 8);
// } example_table SEC(".maps");

struct bpf_map_def SEC("maps") example_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 8,
};


SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	void* data     = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr  *ip;
	struct tcphdr *tcp;
	char		  *payload;
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
		BPF_RETURN(XDP_PASS);
	}

	tcp = data + nh_off;
	nh_off += sizeof(*tcp);
	if (data + nh_off  > data_end)
	 	goto EOP;

	payload = data + nh_off;
	nh_off += 3;
	if (data + nh_off  > data_end)
		goto EOP;

	if (payload[0] == '\0') {
		if (payload[1] == '\0') {
			payload[2] = '\0';
			BPF_RETURN(XDP_PASS);
		}
		BPF_RETURN(XDP_TX);
	}

	BPF_RETURN(XDP_PASS);
	EOP:
		BPF_RETURN(XDP_DROP);

	END_BPF();
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
int xdp_spec(struct xdp_md *ctx) {
	struct pkt *packet = (void *)(long)(ctx->data);
	struct iphdr *ip = (void*)&(packet->ipv4);
	char *payload = (void *)&(packet->payload);

	// if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

	if (payload[0] == '\0') {
		if (payload[1] == '\0') {
			return XDP_DROP_IGNORE_STATE;
		}
		return XDP_TX;
	}

	return XDP_ANY;
}

int main() {
	struct pkt *packet = create_packet(sizeof(struct pkt));
	struct xdp_md *ctx = create_ctx(packet, sizeof(struct pkt), 0);

	functional_verify_weak(xdp_main, xdp_spec, ctx, sizeof(struct pkt), 0);
	return 0;
}
#endif