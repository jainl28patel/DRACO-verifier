#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "klee/klee.h"
#ifndef __VERIFICATION_HELPER
#define __VERIFICATION_HELPER

void __separate() {
  // do nothing. This function is used as a separator for running two programs
}

void assume_map_contains_key(struct bpf_map_def *map, const void *key) {
  klee_assume(bpf_map_lookup_elem(map, key) != NULL);
}

void assume_map_does_not_contain_key(struct bpf_map_def *map, const void *key) {
  klee_assume(bpf_map_lookup_elem(map, key) == NULL);
}

void assume_map_contents(struct bpf_map_def *map, const void *key, const void *value) {
  unsigned int value_size = map->value_size;
  void *v = bpf_map_lookup_elem(map, key);
  klee_assume(v && memcmp(v, value, value_size) == 0);
}

#endif