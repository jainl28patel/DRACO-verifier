#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
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

#include <bpf/bpf_helpers.h>

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
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(char),
	.value_size = sizeof(char),
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
		return XDP_PASS;
	}

	tcp = data + nh_off;
	nh_off += sizeof(*tcp);
	if (data + nh_off  > data_end)
	 	goto EOP;

	payload = data + nh_off;
	nh_off += 3;
	if (data + nh_off  > data_end)
		goto EOP;

	char key = '\0';
	// bpf_map_lookup_elem(&example_table, &key);
	
	char* lookuped_value = bpf_map_lookup_elem(&example_table, &key);
	if (!lookuped_value) return XDP_DROP;
	// if (*lookuped_value == '\0') return XDP_TX;
	return XDP_PASS;
	// payload[0] = *lookuped_value;

	// if (payload[1] == '\0') {
	// 	int value = 1;
	// 	bpf_map_update_elem(&example_table, &key, &value, 0);
	// }

	// lookuped_value = bpf_map_lookup_elem(&example_table, &key);
	// if (!lookuped_value) return XDP_DROP;
	// payload[2] = *lookuped_value;
	// return XDP_PASS;

	EOP:
		return XDP_DROP;
}

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
#include "../../verification_tools/partial_spec.h"
int xdp_spec(struct xdp_md *ctx) {
	struct pkt *packet = (void *)(long)(ctx->data);
	struct iphdr *ip = (void*)&(packet->ipv4);
	char *payload = (void *)&(packet->payload);

	if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
	// bpf_map_lookup_elem(&example_table, '\1');
	char key = '\0';
	char* lookuped_value = bpf_map_lookup_elem(&example_table, &key);
	char key1 = '\1';
	char* lookuped_value1 = bpf_map_lookup_elem(&example_table, &key1);
	if (!lookuped_value) return XDP_DROP;
	// if (*lookuped_value == '\0') return XDP_TX;
	return XDP_PASS;
	// int key = 0;

	// int* lookuped_value = bpf_map_lookup_elem(&example_table, &key);
	// payload[0] = *lookuped_value;

	// if (payload[1] == '\0') {
	// 	int value = 1;
	// 	bpf_map_update_elem(&example_table, &key, &value, 0);
	// }

	// lookuped_value = bpf_map_lookup_elem(&example_table, &key);
	// payload[2] = *lookuped_value;
	// return XDP_PASS;
}


int main() {
	struct pkt *packet = create_packet(sizeof(struct pkt));
	struct xdp_md *ctx = create_ctx(packet, sizeof(struct pkt), 0);
  	BPF_MAP_INIT(&example_table, "example_table", "example_key", "example_value");
	// char key = '\0';
	// char* key = (char*)packet;
	// void* value = malloc(example_table.value_size);
	// assert(value);
  	// klee_make_symbolic(value, example_table.value_size, "context_map_inserted_value");
  	// if(bpf_map_update_elem(&example_table, &packet->ether.h_dest, value, 0) < 0)
    // 	return -1;
	functional_verify(xdp_main, xdp_spec, ctx, sizeof(struct pkt), 0);
	return 0;
}
#endif