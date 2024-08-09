#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

#ifdef KLEE_VERIFICATION

int expected_return = -1;

bool expected_not_returns[XDP_REDIRECT+1] = { false };

#define MAX_CONSTANTS 10
#define CONSTANTS_BUFFER_SIZE 80000
int constants = 0;
void* constants_pointer[MAX_CONSTANTS];
size_t constants_size[MAX_CONSTANTS];
int constants_buffer_ptr = 0;
char constants_buffer[CONSTANTS_BUFFER_SIZE];

#define MAX_LEADS_TO_ACTION 10
int leads_to = 0;
enum xdp_action leads_to_return_values[MAX_LEADS_TO_ACTION];

#define MAX_IF_ACTIONS 10
int if_actions = 0;
enum xdp_action if_actions_return_values[MAX_IF_ACTIONS];
bool if_actions_bools[MAX_IF_ACTIONS];
void* if_actions_targets[MAX_IF_ACTIONS];
void* if_actions_expecteds[MAX_IF_ACTIONS];
size_t if_actions_sizes[MAX_IF_ACTIONS];

#define MAX_IFS 10
int ifs = 0;
bool if_bools[MAX_IFS];
void* if_targets[MAX_IFS];
void* if_expecteds[MAX_IFS];
size_t if_sizes[MAX_IFS];

void _set_expected_return(value) {
    bool contradiction = !expected_not_returns[value];
    assert(contradiction && "Previously asserted that this value is not expected");
    expected_return = value;
}

void _set_expected_not_return(value) {
    assert(value <= XDP_REDIRECT && "Invalid XDP return code");
    bool contradiction = value != expected_return;
    assert(contradiction && "Previously asserted that this value is expected");
    expected_not_returns[value] = true;
}

void _add_constant(void* ptr, size_t len) {
    assert(constants < MAX_CONSTANTS && "Increase MAX_CONSTANTS");
    bool out_of_memory = (constants_buffer_ptr + len) <= CONSTANTS_BUFFER_SIZE;
    assert(out_of_memory && "Increase CONSTANTS_BUFFER_SIZE");
    constants_pointer[constants] = ptr;
    constants_size[constants] = len;
    memcpy(constants_buffer + constants_buffer_ptr, ptr, len);
    constants_buffer_ptr += len;
    constants++;
}

void _add_leads_to(bool condition, enum xdp_action return_value) {
    if (condition) {
        assert(leads_to < MAX_LEADS_TO_ACTION && "Increase MAX_LEADS_TO");
        leads_to_return_values[leads_to] = return_value;
        leads_to++;
    }
}

void _add_if_action(enum xdp_action return_value, void* addr, void *value, size_t size, bool if_bool) {
    assert(if_actions < MAX_IF_ACTIONS && "Increase MAX_IFS");
    if_actions_return_values[if_actions] = return_value;
    if_actions_bools[if_actions] = if_bool;
    if_actions_targets[if_actions] = addr;
    if_actions_expecteds[if_actions] = value;
    if_actions_sizes[if_actions] = size;
    if_actions++;
}

void _add_if(void* addr, void *value, size_t size, bool if_bool) {
    assert(ifs < MAX_IFS && "Increase MAX_IFS");
    if_bools[ifs] = if_bool;
    if_targets[ifs] = addr;
    if_expecteds[ifs] = value;
    if_sizes[ifs] = size;
    ifs++;
}

void _run_unrestricted_asserts(enum xdp_action return_value) {
    bool bpf_assert_return = expected_return == -1 || expected_return == return_value;
    assert(bpf_assert_return);
    
    bool bpf_assert_not_return = !expected_not_returns[return_value];
    assert(bpf_assert_not_return);
   
    constants_buffer_ptr = 0;
    for (int i = 0; i < constants; i++) {
        bool constant_unchanged = !memcmp(constants_pointer[i], constants_buffer + constants_buffer_ptr, constants_size[i]);
        assert(constant_unchanged);
        constants_buffer_ptr += constants_size[i];
    }
    for (int i = 0; i < leads_to; i++) {
        bool bpf_assert_leads_to_action = return_value == leads_to_return_values[i];
        assert(bpf_assert_leads_to_action);
    }
    for (int i = 0; i < if_actions; i++) {
        if (if_actions_return_values[i] == return_value) {
            bool bpf_assert_if_action = !memcmp(if_actions_targets[i], if_actions_expecteds[i], if_actions_sizes[i]);
            if(!if_actions_bools[i]) bpf_assert_if_action = !bpf_assert_if_action;
            assert(bpf_assert_if_action);       
        }
        free(if_actions_expecteds[i]);
    }
    for (int i = 0; i < ifs; i++) {
        bool bpf_assert_if = !memcmp(if_targets[i], if_expecteds[i], if_sizes[i]);
        if(!if_bools[i]) bpf_assert_if = !bpf_assert_if;
        assert(bpf_assert_if);       
        free(if_expecteds[i]);
    }
}

#define BPF_ASSERT(msg, x) assert(msg && x)
#define BPF_ASSERT_RETURN(value) _set_expected_return(value)
#define BPF_ASSERT_NOT_RETURN(value) _set_expected_not_return(value)
#define BPF_ASSERT_CONSTANT(addr, len) _add_constant(addr, len)
#define BPF_ASSERT_NOT_TRAVERSED() assert("Traversed a path not to be traversed" && false)
#define BPF_ASSERT_LEADS_TO_ACTION(condition, return_value) _add_leads_to(condition, return_value)
#define _BPF_ASSERT_IF_ACTION_THEN(return_value, target, type, value, eq_bool) {\
    type* expected = (type*)malloc(sizeof(type));\
    *expected = value;\
    _add_if_action(return_value, target, expected, sizeof(type), eq_bool);\
}
#define BPF_ASSERT_IF_ACTION_THEN_EQ(return_value, target, type, value) _BPF_ASSERT_IF_ACTION_THEN(return_value, target, type, value, true)
#define BPF_ASSERT_IF_ACTION_THEN_NEQ(return_value, target, type, value) _BPF_ASSERT_IF_ACTION_THEN(return_value, target, type, value, false)
#define _BPF_ASSERT_IF_THEN(condition, target, type, value, eq_bool) {\
    if (condition) {\
        type* expected = (type*)malloc(sizeof(type));\
        *expected = value;\
        _add_if(target, expected, sizeof(type), eq_bool);\
    }\
}
#define BPF_ASSERT_IF_THEN_EQ(condition, target, type, value) _BPF_ASSERT_IF_THEN(condition, target, type, value, true)
#define BPF_ASSERT_IF_THEN_NEQ(condition, target, type, value) _BPF_ASSERT_IF_THEN(condition, target, type, value, false)
#define BPF_ASSERT_END_EQ(target, type, value) _BPF_ASSERT_IF_THEN(true, target, type, value, true)
#define BPF_ASSERT_END_NEQ(target, type, value) _BPF_ASSERT_IF_THEN(true, target, type, value, false)
#define _BPF_ASSERT_IF_THEN_ADDR(condition, target, addr, size, eq_bool) {\
    if (condition) {\
        void* expected = malloc(size);\
        memcpy(expected, addr, size);\
        _add_if(target, expected, size, eq_bool);\
    }\
}
#define BPF_ASSERT_END_EQ_ADDR(target, addr, size) _BPF_ASSERT_IF_THEN_ADDR(true, target, addr, size, true)
#define BPF_RETURN(return_value) {_run_unrestricted_asserts(return_value); return return_value;}
#else
#define BPF_ASSERT(msg, x) {}
#define BPF_ASSERT_RETURN(value) {}
#define BPF_ASSERT_NOT_RETURN(value) {}
#define BPF_ASSERT_NOT_TRAVERSED() {}
#define BPF_ASSERT_CONSTANT(addr, len) {}
#define BPF_ASSERT_LEADS_TO_ACTION(condition, return_value) {}
#define BPF_ASSERT_IF_ACTION_THEN_EQ(return_value, target, type, value) {}
#define BPF_ASSERT_IF_ACTION_THEN_NEQ(return_value, target, type, value) {}
#define BPF_ASSERT_IF_THEN_EQ(condition, target, type, value) {}
#define BPF_ASSERT_IF_THEN_NEQ(condition, target, type, value) {}
#define BPF_ASSERT_END_EQ(target, type, value) {}
#define BPF_ASSERT_END_EQ_ADDR(target, addr, size) {}
#define BPF_ASSERT_END_NEQ(target, type, value) {}
#define BPF_RETURN(return_value) return return_value
#endif
