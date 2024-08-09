#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <linux/bpf.h>
#include "common.h"

typedef int(*set_up_maps_func)(void);

struct xdp_end_state {
	int rvalue;
	void* pkt;
};

bool xdp_end_state_equal(struct xdp_end_state *a, struct xdp_end_state *b, size_t packet_size) {
	return a->rvalue == b->rvalue && memcmp(a->pkt, b->pkt, packet_size) == 0;
}

struct xdp_end_state get_xdp_end_state(xdp_func f, struct xdp_md* ctx, size_t eth_offset) {
	struct xdp_end_state s;
	s.pkt = (void*)(long)(ctx->data) - eth_offset;
	s.rvalue = f(ctx);
	return s;
}

int functional_verify(xdp_func prog, 
					   xdp_func spec, 
					   struct xdp_md *ctx, 
					   size_t packet_size,
					   size_t eth_offset,
					   set_up_maps_func set_up_maps) {
	// Make a copy of packet
	void* packet = (void*)(long)ctx->data;
	void* packet_copy = malloc(packet_size - eth_offset);
	memcpy(packet_copy, packet, packet_size - eth_offset);

	// Make a copy of ctx
	struct xdp_md ctx_copy;
    memcpy(&ctx_copy, ctx, sizeof(struct xdp_md));
	ctx_copy.data = (long)packet_copy + eth_offset;
	ctx_copy.data_end = (long)packet_copy + packet_size;

	// Set up maps
	if (set_up_maps != NULL) assert(set_up_maps() == 0 && "Failed to set up maps");

	// Run the program
	struct xdp_end_state prog_end_state = get_xdp_end_state(prog, ctx, eth_offset);

	// Reset maps
	if (set_up_maps != NULL) assert(set_up_maps() == 0 && "Failed to set up maps second time");

	// Run the spec
	struct xdp_end_state spec_end_state = get_xdp_end_state(spec, &ctx_copy, eth_offset);

	// Check if return value and end state of packet is equal
	assert(xdp_end_state_equal(&prog_end_state, &spec_end_state, packet_size));
	return 0;
}