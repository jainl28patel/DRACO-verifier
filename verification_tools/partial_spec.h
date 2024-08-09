#include <linux/bpf.h>
#include <stdbool.h>
#include "common.h"
#include "assert.h"

#ifndef PARTIAL_SPEC
#define PARTIAL_SPEC

#ifndef USES_BPF_MAP_UPDATE_ELEM
#define USES_BPF_MAP_UPDATE_ELEM
#endif

#ifndef USES_BPF_MAP_DELETE_ELEM
#define USES_BPF_MAP_DELETE_ELEM
#endif

#define BPF_RETURN(x) return x

void add_key(void* map, const void* key) {
    struct bpf_map_def *map_ptr = ((struct bpf_map_def *)map);
    struct MapStub *stub = bpf_map_stubs[map_ptr->map_id];
    void* value = malloc(stub->value_size); 
    assert(value); 
    klee_make_symbolic(value, stub->value_size, "..."); 
    assert(bpf_map_update_elem(map, key, value, 0) >= 0); 
}

#define BPF_MAP_KEY_EXISTS(map, key) add_key(map, key)
#define BPF_MAP_KEY_NOT_EXISTS(map, key) bpf_map_delete_elem(map, key)


bool ignore_packet_state = false;

bool ignore_map_state = false;
#define BPF_IGNORE_MAP_STATE() ignore_map_state = true

void functional_verify(xdp_func xdp_main, 
                      xdp_func xdp_spec, 
                      struct xdp_md *ctx,
                      size_t packet_size,
					  size_t eth_offset) {
    // Make a copy of packet
    void* packet = (void*)(long)ctx->data - eth_offset;
    void* packet_copy = malloc(packet_size);
    assert(packet_copy != NULL);
	memcpy(packet_copy, packet, packet_size);

    // Make a copy of ctx
    struct xdp_md ctx_copy;
    memcpy(&ctx_copy, ctx, sizeof(struct xdp_md));
	ctx_copy.data = (long)packet_copy + eth_offset;
	ctx_copy.data_end = (long)packet_copy + packet_size;

    duplicate_maps();

	struct xdp_end_state spec_end_state = get_xdp_end_state(xdp_spec, &ctx_copy);
    // void* table_copy = map_get_copy(bpf_map_stubs[0]);

    if(spec_end_state.rvalue != XDP_ANY_IGNORE_STATE) {
        // Run the program
        // for (size_t no = 0; no < bpf_map_ctr; no++) {
        //     BPF_MAP_RESET(bpf_map_stubs[no]);
        // }
        // set_up_maps();
        // bpf_map_stubs[0] = initial_copy;
        use_copy = bpf_map_ctr;
        struct xdp_end_state prog_end_state = get_xdp_end_state(xdp_main, ctx);

        for (int i = 0; i < bpf_map_ctr; i++) {
            if (!map_same_lookup_inserts(bpf_map_stubs[i], bpf_map_stubs[i+bpf_map_ctr]) || !map_same_lookup_inserts(bpf_map_stubs[i+bpf_map_ctr], bpf_map_stubs[i]) ) return;
        }
        if (!ignore_map_state) {
            for (int i = 0; i < bpf_map_ctr; i++) {
                assert(map_equal(bpf_map_stubs[i], bpf_map_stubs[i+bpf_map_ctr]));
            }
        }

        if (spec_end_state.rvalue != XDP_ANY)
            assert(return_value_equal(&prog_end_state, &spec_end_state));

        if (spec_end_state.rvalue <= XDP_ANY)
            assert(end_state_equal(&prog_end_state, &spec_end_state, eth_offset));
    }
}

#endif