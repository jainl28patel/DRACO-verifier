#include <stdlib.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <klee/klee.h>

#ifndef VERIFICAION_HELPERS
#define VERIFICAION_HELPERS
typedef int(*xdp_func)(struct xdp_md*);

uint32_t ipv4_uint8_to_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    uint32_t result = 0;
    result += a;
    result <<= 8;
    result += b;
    result <<= 8;
    result += c;
    result <<= 8;
    result += d;

    return result;
}

enum xdp_action_verify {
    XDP_ANY = XDP_REDIRECT + 1,
    XDP_ABORTED_IGNORE_STATE,
	XDP_DROP_IGNORE_STATE,
	XDP_PASS_IGNORE_STATE,
	XDP_TX_IGNORE_STATE,
	XDP_REDIRECT_IGNORE_STATE,
    XDP_ANY_IGNORE_STATE
};

struct xdp_end_state {
	int rvalue;
	struct xdp_md* ctx;
};

struct xdp_end_state get_xdp_end_state(xdp_func f, struct xdp_md* ctx) {
	struct xdp_end_state s;
	s.rvalue = f(ctx);
    s.ctx = ctx;
	return s;
}
bool return_value_equal(struct xdp_end_state *prog, struct xdp_end_state *spec) {
    return prog->rvalue == spec->rvalue || prog->rvalue + XDP_ABORTED_IGNORE_STATE == spec->rvalue;
}

bool end_state_equal(struct xdp_end_state *x, struct xdp_end_state *y, size_t eth_offset) {
    void* x_ctx = x->ctx;
    void* y_ctx = y->ctx;
    bool end_metadata_equal = memcmp(x_ctx+8, y_ctx+8, sizeof(struct xdp_md) - 8) == 0;
    size_t x_packet_size = x->ctx->data_end - x->ctx->data + eth_offset;
    size_t y_packet_size = y->ctx->data_end - y->ctx->data + eth_offset;
    bool packet_size_equal = x_packet_size == y_packet_size;
    void* x_pkt = (void*)(long)x->ctx->data - eth_offset;
    void* y_pkt = (void*)(long)y->ctx->data - eth_offset;
    bool end_packet_equal = memcmp(x_pkt, y_pkt, x_packet_size) == 0;
    return end_metadata_equal && packet_size_equal && end_packet_equal;
}

void* create_packet(size_t pkt_size) {
	void *packet = malloc(pkt_size);
	klee_make_symbolic(packet, pkt_size, "packet");
	return packet;
}

struct xdp_md* create_ctx(void* packet, size_t packet_size, size_t eth_offset) {
    struct xdp_md* ctx = (struct xdp_md*)(malloc(sizeof(struct xdp_md)));
    klee_make_symbolic(ctx, sizeof(struct xdp_md), "ctx");
	ctx->data = (long)packet + eth_offset;
	ctx->data_end = (long)packet + packet_size;
    ctx->data_meta = 0;
    ctx->ingress_ifindex = 0;
    ctx->rx_queue_index = 0;
    return (struct xdp_md*)ctx;
}
#endif