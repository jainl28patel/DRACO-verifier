#ifndef USES_BPF_MAPS
#define USES_BPF_MAPS
#endif

#ifndef USES_BPF_MAP_LOOKUP_ELEM
#define USES_BPF_MAP_LOOKUP_ELEM
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../../ebpf-se/examples/common/parsing_helpers.h"
#include "../../ebpf-se/examples/common/debug_tags.h"
#include "../../verification_tools/verification_helpers.h"
#include "common_maps.h"
#include "program1.h"
#include "program2.h"

#ifdef KLEE_VERIFICATION
#include "klee/klee.h"
#include <stdlib.h>
int main(int argc, char** argv) {
  BPF_MAP_INIT(&macs, "macs_map", "", "");
	struct pkt *pkt = malloc(sizeof(struct pkt));
	klee_make_symbolic(pkt, sizeof(struct pkt), "user_pkt");
	struct xdp_md test;
  test.data = (long)(&(pkt->ether));
  test.data_end = (long)(pkt + 1);
  test.data_meta = 0;
  test.ingress_ifindex = 0;
  xdp_first_prog(&test);
  __separate();
  xdp_second_prog(&test);
  return 0;
}
#endif