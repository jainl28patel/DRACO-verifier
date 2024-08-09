#ifndef COMMON_MAPS
#define COMMON_MAPS

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_map_def SEC("maps") macs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = 6,
    .max_entries = 10,
};

struct __attribute__((__packed__)) pkt {
  struct ethhdr ether;
  struct iphdr ipv4;
  struct tcphdr tcp;
  char payload[100];
};

#endif // COMMON_MAPS