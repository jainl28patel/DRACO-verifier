#include <linux/bpf.h>
#include <stdbool.h>
#include <string.h>
#include "common.h"
#include "assert.h"

#ifndef WEAK_PARTIAL_SPEC
#define WEAK_PARTIAL_SPEC

#ifdef KLEE_VERIFICATION

#define END_BPF() return -1

struct xdp_end_state spec_end_state;

// #define MAX_PATHS 10

// size_t no_path = 0;
// struct xdp_end_state prog_end_states[MAX_PATHS];
// struct xdp_md prog_end_md[MAX_PATHS];

size_t global_eth_offset;

bool _check_return_path(enum xdp_action action, struct xdp_md *ctx) {
    struct xdp_end_state prog_end_state;
    prog_end_state.rvalue = action;
    prog_end_state.ctx = ctx;

    if (spec_end_state.rvalue < XDP_ANY)
        if (return_value_equal(&prog_end_state, &spec_end_state) && end_state_equal(&prog_end_state, &spec_end_state, global_eth_offset)) return true;

    if (spec_end_state.rvalue == XDP_ANY)
        if (end_state_equal(&prog_end_state, &spec_end_state, global_eth_offset)) return true;

    if (spec_end_state.rvalue > XDP_ANY) {
        if (return_value_equal(&prog_end_state, &spec_end_state)) return true;
    }

    return false;

    // assert(no_path < MAX_PATHS && "Increase MAX_PATHS");
    // struct xdp_end_state *prog_end_state = &prog_end_states[no_path];

    // // Copy return value
    // prog_end_state->rvalue = action;

    // // Copy ctx.data
    // size_t packet_size = global_eth_offset + ctx->data_end - ctx->data;
    // void* prog_end_pkt = malloc(packet_size);
    // assert(prog_end_pkt != NULL);
    // memcpy(prog_end_pkt, (void*)((long)ctx->data - global_eth_offset), packet_size);
    
    // // Copy ctx
    // struct xdp_md* prog_end_ctx = (struct xdp_md*)malloc(sizeof(struct xdp_md));
    // assert(prog_end_ctx != NULL);
    // memcpy(prog_end_ctx, ctx, sizeof(struct xdp_md));
    // prog_end_ctx->data = (long)prog_end_pkt + global_eth_offset;
    // prog_end_ctx->data_end = (long)prog_end_pkt + packet_size;

    // prog_end_state->ctx = prog_end_ctx;

    // no_path++;
}

#define BPF_RETURN(x) if(_check_return_path(x, ctx)) return x



// void check_return_value_end_state(struct xdp_end_state *spec, size_t eth_offset) {
//     for (size_t i = 0; i < no_path; i++) {
//         if (return_value_equal(&prog_end_states[i], spec) && end_state_equal(&prog_end_states[i], spec, eth_offset)) return;
//     }
//     assert(false && "No path with same return value and end state");
// }

// void check_return_value(struct xdp_end_state *spec) {
//     for (size_t i = 0; i < no_path; i++) {
//         if (return_value_equal(&prog_end_states[i], spec)) return;
//     }
//     assert(false && "No path with same return value");
// }

// void check_end_state(struct xdp_end_state *spec, size_t eth_offset) {
//     for (size_t i = 0; i < no_path; i++) {
//         if (end_state_equal(&prog_end_states[i], spec, eth_offset)) return;
//     }
//     assert(false && "No path with same end state");
// }

void functional_verify_weak(xdp_func xdp_main, 
                      xdp_func xdp_spec, 
                      struct xdp_md *ctx,
                      size_t packet_size,
					  size_t eth_offset) {
    global_eth_offset = eth_offset;

    // Make a copy of packet
    void* packet = (void*)(long)ctx->data;
    void* packet_copy = malloc(packet_size - eth_offset);
    assert(packet_copy != NULL);
	memcpy(packet_copy, packet, packet_size - eth_offset);

    // Make a copy of ctx
    struct xdp_md ctx_copy;
    memcpy(&ctx_copy, ctx, sizeof(struct xdp_md));
	ctx_copy.data = (long)packet_copy + eth_offset;
	ctx_copy.data_end = (long)packet_copy + packet_size;

    // Run the spec
	spec_end_state = get_xdp_end_state(xdp_spec, &ctx_copy);

    if(spec_end_state.rvalue != XDP_ANY_IGNORE_STATE) {
        // Run the program
        if(xdp_main(ctx)==-1) {
            assert(false);
        }

        // if (spec_end_state.rvalue < XDP_ANY)
        //     check_return_value_end_state(&spec_end_state, eth_offset);

        // if (spec_end_state.rvalue == XDP_ANY)
        //     check_end_state(&spec_end_state, eth_offset);

        // if (spec_end_state.rvalue > XDP_ANY) {
        //     check_return_value(&spec_end_state);
        // }

    }
}
#else
#define BPF_RETURN(x) return x
#define END_BPF() {}
#endif
#endif