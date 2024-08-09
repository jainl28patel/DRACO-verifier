#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <netinet/in.h>

#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif


#include <bpf/bpf_helpers.h>
#include "../../verification_tools/assert_spec.h"

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[1500];
};

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = 4,
	.value_size = 4,
	.max_entries = 10,
};

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
	int one = 1;
	int *val = bpf_map_lookup_elem(&my_map, &one);
	assert(*val == 2);

	BPF_ASSERT_NOT_RETURN(XDP_ABORTED);
	BPF_ASSERT_NOT_RETURN(XDP_REDIRECT);
	// BPF_ASSERT_NOT_RETURN(XDP_DROP);

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
	if (data + nh_off  > data_end) {
	 	goto EOP;
	}

	payload = data + nh_off;
	BPF_ASSERT_IF_THEN_EQ(payload[0] != '\0', &payload[1], char, '\0');
	BPF_ASSERT_IF_THEN_NEQ(payload[0] != '\0', &payload[0], char, '\0');
	BPF_ASSERT_IF_THEN_EQ(payload[0] == '\0', &payload[2], char, '\1');

	BPF_ASSERT_LEADS_TO_ACTION(payload[0] != '\0', XDP_PASS);
	BPF_ASSERT_LEADS_TO_ACTION(payload[0] == '\0', XDP_TX);

	BPF_ASSERT_IF_ACTION_THEN_EQ(XDP_PASS, &payload[1], char, '\0');
	BPF_ASSERT_IF_ACTION_THEN_NEQ(XDP_PASS, &payload[0], char, '\0');
	BPF_ASSERT_IF_ACTION_THEN_EQ(XDP_TX, &payload[2], char, '\1');

	nh_off += 3;
	if (data + nh_off  > data_end)
		goto EOP;

	char value = '\0';
	
	if (payload[0] == value) {
		BPF_ASSERT_RETURN(XDP_TX);

		value = '\1';
		if (payload[2] != value)
			payload[2] = value;
		
		BPF_ASSERT("", payload[2]=='\1');
		BPF_RETURN(XDP_TX);
	}
	BPF_ASSERT("", payload[0]!=0);
	BPF_ASSERT_RETURN(XDP_PASS);
	BPF_ASSERT_CONSTANT(&value, sizeof(value));

	payload[1] = value;
	BPF_RETURN(XDP_PASS);

	EOP:
		BPF_RETURN(XDP_DROP);
}


#ifdef KLEE_VERIFICATION
int set_up_maps() {
  BPF_MAP_INIT(&my_map, "", "", "");
  int one = 1;
  int two = 2;
  bpf_map_update_elem(&my_map, &one, &two, 0);
}

int main() {
	struct pkt *packet = create_packet(sizeof(struct pkt));
	struct xdp_md *ctx = create_ctx(packet, sizeof(struct pkt), 0);
	set_up_maps();
	xdp_main(ctx);
}
#endif