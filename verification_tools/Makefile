ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
LIBBPF_DIR:=$(ROOT_DIR)/../libbpf-stubbed/src
LIBBPF_INCLUDE_DIR:=$(LIBBPF_DIR)/build/usr/include/

LLVM_RELEASE=13
LLC=llc-$(LLVM_RELEASE)
CLANG=clang-$(LLVM_RELEASE)
CC := gcc
UNAME_P := $(shell uname -p)

BPF_CFLAGS ?= -I $(LIBBPF_INCLUDE_DIR) -I $(ROOT_DIR)/../headers/
BPF_CFLAGS += -I /usr/include/$(UNAME_P)-linux-gnu

VERIFY_FILE=verify
READWRITE_FILE=readWriteSet

verify: libbpf
	$(CLANG) \
		$(BPF_CFLAGS) \
		-D KLEE_VERIFICATION \
		-fno-discard-value-names \
		-c -g $(VERIFY_FILE).c

readWrite:
	$(CLANG) \
		-fno-discard-value-names \
		-o $(READWRITE_FILE) $(READWRITE_FILE).c

libbpf: 
	if [ ! -d "$(LIBBPF_INCLUDE_DIR)" ]; then cd $(LIBBPF_DIR) && bash build.sh; fi

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	rm -f *.ll *.bc *.o