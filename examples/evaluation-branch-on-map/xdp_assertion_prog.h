#ifndef __XDP_MAP_H
#define __XDP_MAP_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../../ebpf-se/examples/common/parsing_helpers.h"
#include "../../ebpf-se/examples/common/debug_tags.h"

struct addressInfo {
  int count;
};

struct bpf_map_def SEC("maps") sourceAddressInfo = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct addressInfo),
	.max_entries = 10,
};

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[100];
};

#endif // XDP_MAP_H
