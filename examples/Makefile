ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
current_dir := $(shell dirname $(mkfile_path))
LIBBPF_DIR:=$(current_dir)/../ebpf-se/libbpf-stubbed/src
COMMON_DIR:=$(current_dir)/../ebpf-se/examples/common
KLEE_PATH:=$(current_dir)/../ebpf-se/tool/deps/klee
LIBXDP_PATH:=$(current_dir)/../ebpf-se/tool/deps/libxdp
XDP_PATH:=$(current_dir)/../ebpf-se/tool/deps/xdp

LLVM_RELEASE=13
LLC=llc-$(LLVM_RELEASE)
CLANG=clang-$(LLVM_RELEASE)
LLVM_STRIP=llvm-strip-$(LLVM_RELEASE)
CC := gcc
UNAME_P := $(shell uname -p)

XDP_C ?= ${XDP_TARGETS:=.c}
XDP_BC = ${XDP_C:.c=.bc}
XDP_OBJ = ${XDP_C:.c=.o}

OBJECT_LIBBPF = $(LIBBPF_DIR)/obj/libbpf.a

# Extend if including Makefile already added some
COMMON_OBJS += $(COMMON_DIR)/common_params.o $(COMMON_DIR)/common_user_bpf_xdp.o

# Create expansions for dependencies
COMMON_H := ${COMMON_OBJS:.o=.h}

EXTRA_DEPS +=

# BPF-prog kern and userspace shares struct via header file:
KERN_USER_H ?= $(wildcard common_kern_user.h)

LDFLAGS ?= -L$(LIBBPF_DIR)

BPF_CFLAGS ?= -I$(ROOT_DIR)/../headers/ -I /usr/include/$(UNAME_P)-linux-gnu
KLEE_BPF_CFLAGS ?= $(BPF_CFLAGS) -I$(LIBBPF_DIR)/build/usr/include/ 
ACTUAL_BPF_CFLAGS ?= $(BPF_CFLAGS) 
XDP_CFLAGS = -I $(XDP_PATH)
# BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I$(current_dir)/../headers/
# BPF_CFLAGS += -I /usr/include/$(UNAME_P)-linux-gnu

ifeq ($(REPLAY), 1)
	BPF_CFLAGS += -DREPLAY
endif

clean-klee:
	rm -rf $(ROOT_DIR)/klee-*
	rm -f $(ROOT_DIR)/res-tree-*
	rm -f $(ROOT_DIR)/neg-tree*

clean: clean-klee
	@#rm -rf $(LIBBPF_DIR)/build
	@#$(MAKE) -C $(LIBBPF_DIR) clean
	@#$(MAKE) -C $(COMMON_DIR) clean
	rm -f $(XDP_OBJ)
	rm -f *.ll *.bc
	rm -f *~
	rm -f replayer

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

xdp-target: $(XDP_C) Makefile $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
		-target bpf \
		-DKLEE_VERIFICATION\
		$(KLEE_BPF_CFLAGS) \
		-I $(KLEE_INCLUDE) \
		-D__USE_VMLINUX__ \
		-D__TARGET_ARCH_x86 \
		-DBPF_NO_PRESERVE_ACCESS_INDEX \
		-Wall \
		-Wno-unused-value \
		-Wno-unused-variable \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-fno-builtin \
		-O0 -emit-llvm -c -g $(XDP_C)
	#$(LLC) -I $(KLEE_INCLUDE) -march=bpf -filetype=obj $(XDP_BC) -o ${XDP_OBJ}

libbpf:
	cd $(LIBBPF_DIR) && bash build.sh

symbex:
	/usr/bin/time -v \
		klee -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 -libc=uclibc --external-calls=all --disable-verify \
		-solver-backend=z3 --exit-on-error -max-memory=750000 -search=dfs $(XDP_BC)

#loader:
#	$(CLANG) $(XDP_CFLAGS) $(COMMON_DIR)/loader.c -o $(COMMON_DIR)/loader -lxdp

verify:
	@if [ $(shell id -u) != 0 ]; then echo Requires sudo; exit 1; fi
	@$(CLANG) \
		-target bpf \
		$(ACTUAL_BPF_CFLAGS) \
		-D__USE_VMLINUX__ \
		-D__TARGET_ARCH_x86 \
		-DBPF_NO_PRESERVE_ACCESS_INDEX \
		-fno-builtin \
		-O2 -g -c $(XDP_C) -o $(XDP_OBJ) 
	@echo $(XDP_C) compiled!
	@../verification_tools/xdp-loader load -m skb lo $(XDP_OBJ) -vv 2> verifier_log; \
		if [ $$? = 0 ]; then \
		echo $(XDP_TARGETS) $(XDP_FUNCTION) passed verification; \
		../verification_tools/xdp-loader unload lo --all; \
		else \
		grep -Fxq "legacy map definitions" verifier_log; \
		if [ $$? ]; then \
		echo Legacy BPF map definitions not supported; \
		else \
		echo $(XDP_TARGETS) $(XDP_FUNCTION) failed verification; \
		cat verifier_log | awk '/-- BEGIN /{flag=1; next}/libbpf: -- END /{flag=0} flag' ; \
		fi \
		fi
	@rm verifier_log
	@#$(COMMON_DIR)/loader $(XDP_OBJ) $(XDP_SECTION) $(XDP_FUNCTION)

.PHONY: replayer
replayer:
	$(CLANG) -DKLEE_VERIFICATION -I $(KLEE_INCLUDE) -L $(KLEE_PATH)/build/lib $(XDP_C) -lkleeRuntest -o replayer

viewer:
	g++ -I $(KLEE_INCLUDE) \
		$(COMMON_DIR)/ktest_viewer.c \
		$(KLEE_PATH)/build/lib/Basic/CMakeFiles/kleeBasic.dir/KTest.cpp.o \
		-o $(COMMON_DIR)/ktest_viewer

replay:
	@F=`printf "%06d" $f`; \
	#$(COMMON_DIR)/ktest_viewer klee-last/test$$F.ktest; \
	KTEST_FILE=klee-last/test$$F.ktest ./replayer ; echo $$?

assert: clean-klee xdp-target symbex

assert-partial:
	@n=`awk '/generated tests/ {print $$NF}' 'klee-last/info'`; \
	i=1; while [ $$i -le $$n ]; do\
		F=`printf "%06d" $$i`; \
		KTEST_FILE=klee-last/test$$F.ktest ./replayer ;\
		if [ $$? = 1 ]; then\
		echo Return value of 1; \
		else \
		echo Return value not 1; \
		fi ;\
		i=`echo $$i + 1 | bc`;\
	done

verify-interactions: $(XDP_C) Makefile $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
		-target bpf \
		-DKLEE_VERIFICATION\
		-DVERIFY_INTERACTIONS\
		$(KLEE_BPF_CFLAGS) \
		-I $(KLEE_INCLUDE) \
		-D__USE_VMLINUX__ \
		-D__TARGET_ARCH_x86 \
		-DBPF_NO_PRESERVE_ACCESS_INDEX \
		-Wall \
		-Wno-unused-value \
		-Wno-unused-variable \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-fno-discard-value-names \
		-fno-builtin \
		-O0 -emit-llvm -c -g $(XDP_C)
	# $(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	llvm-dis -show-annotations $(XDP_TARGETS).bc
	/usr/bin/time -v \
		klee -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 -libc=uclibc --external-calls=all --disable-verify \
		-solver-backend=z3 -silent-klee-assume=true --exit-on-error -max-memory=750000 -search=dfs -single-object-resolution=true \
		-verification=true -read-set=true -write-set=true -map-correlation=true $(XDP_TARGETS).bc

verify-two-phase: $(XDP_C) Makefile $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
		-target bpf \
		-DKLEE_VERIFICATION\
		-DVERIFY_INTERACTIONS\
		$(KLEE_BPF_CFLAGS) \
		-I $(KLEE_INCLUDE) \
		-D__USE_VMLINUX__ \
		-D__TARGET_ARCH_x86 \
		-DBPF_NO_PRESERVE_ACCESS_INDEX \
		-Wall \
		-Wno-unused-value \
		-Wno-unused-variable \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-fno-discard-value-names \
		-fno-builtin \
		-O0 -emit-llvm -c -g $(XDP_C)
	# $(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	llvm-dis -show-annotations $(XDP_TARGETS).bc
	/usr/bin/time -v \
		klee -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 -libc=uclibc --external-calls=all --disable-verify \
		-solver-backend=z3 --exit-on-error -max-memory=750000 -search=dfs -single-object-resolution=true \
		-verification=true -read-set=true -write-set=true -map-correlation=true -read-write-two-phase=true $(XDP_TARGETS).bc

verify-map-policy: $(XDP_C) Makefile $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
		-target bpf \
		-DKLEE_VERIFICATION\
		-DVERIFY_INTERACTIONS\
		$(KLEE_BPF_CFLAGS) \
		-I $(KLEE_INCLUDE) \
		-D__USE_VMLINUX__ \
		-D__TARGET_ARCH_x86 \
		-DBPF_NO_PRESERVE_ACCESS_INDEX \
		-Wall \
		-Wno-unused-value \
		-Wno-unused-variable \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-fno-discard-value-names \
		-fno-builtin \
		-O0 -emit-llvm -c -g $(XDP_C)
	llvm-dis -show-annotations $(XDP_TARGETS).bc
	/usr/bin/time -v \
		klee -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 -libc=uclibc --external-calls=all --disable-verify \
		-solver-backend=z3 --exit-on-error -max-memory=750000 -search=dfs -single-object-resolution=true \
		-verification=true -read-set=true -write-set=true -map-correlation=true -read-write-two-phase=true -map-access-control-file=$(MAP_CONFIG_PATH) $(XDP_TARGETS).bc

verify-packet-policy: $(XDP_C) Makefile $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
		-target bpf \
		-DKLEE_VERIFICATION\
		-DVERIFY_INTERACTIONS\
		$(KLEE_BPF_CFLAGS) \
		-I $(KLEE_INCLUDE) \
		-D__USE_VMLINUX__ \
		-D__TARGET_ARCH_x86 \
		-DBPF_NO_PRESERVE_ACCESS_INDEX \
		-Wall \
		-Wno-unused-value \
		-Wno-unused-variable \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-fno-discard-value-names \
		-fno-builtin \
		-O0 -emit-llvm -c -g $(XDP_C)
	llvm-dis -show-annotations $(XDP_TARGETS).bc
	/usr/bin/time -v \
		klee -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 -libc=uclibc --external-calls=all --disable-verify \
		-solver-backend=z3 --exit-on-error -max-memory=750000 -search=dfs -single-object-resolution=true \
		-verification=true -read-set=true -write-set=true -map-correlation=true -read-write-two-phase=true -map-access-control-file=$(MAP_CONFIG_PATH) $(XDP_TARGETS).bc

symbex-cve-2022-2322:
	# compile the program
	$(CLANG) \
		-DKLEE_VERIFICATION\
		-DVERIFY_INTERACTIONS\
		-DKLEE_SYM_PRINTF \
		$(KLEE_BPF_CFLAGS) \
		-I $(KLEE_INCLUDE) \
		-D__USE_VMLINUX__ \
		-D__TARGET_ARCH_x86 \
		-DBPF_NO_PRESERVE_ACCESS_INDEX \
		-Wall \
		-Wno-unused-value \
		-Wno-unused-variable \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-fno-discard-value-names \
		-fno-builtin \
		-O0 -emit-llvm -c -g $(XDP_C)
	llvm-dis -show-annotations $(XDP_TARGETS).bc
	sudo /home/jainil/Draco/DRACO-verifier/klee/build/bin/klee -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 -libc=uclibc --external-calls=all --disable-verify \
		-solver-backend=z3 --exit-on-error -max-memory=750000 -search=dfs -single-object-resolution=true -link-llvm-lib=/home/jainil/Draco/DRACO-verifier/ebpf-se/libbpf-stubbed/src/obj/libbpf.bc \
		-verification=true $(XDP_TARGETS).bc

verify-helperFunc-access: $(XDP_C) Makefile $(KERN_USER_H) $(EXTRA_DEPS)
	$(CLANG) \
		-target bpf \
		-DKLEE_VERIFICATION\
		-DVERIFY_INTERACTIONS\
		$(KLEE_BPF_CFLAGS) \
		-I $(KLEE_INCLUDE) \
		-D__USE_VMLINUX__ \
		-D__TARGET_ARCH_x86 \
		-DBPF_NO_PRESERVE_ACCESS_INDEX \
		-Wall \
		-Wno-unused-value \
		-Wno-unused-variable \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-fno-discard-value-names \
		-fno-builtin \
		-O0 -emit-llvm -c -g $(XDP_C)
	# $(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	llvm-dis -show-annotations $(XDP_TARGETS).bc
	/usr/bin/time -v \
		klee -kdalloc -kdalloc-heap-start-address=0x00040000000 -kdalloc-heap-size=1 -libc=uclibc --external-calls=all --disable-verify \
		-solver-backend=z3 -silent-klee-assume=true --exit-on-error -max-memory=750000 -search=dfs -single-object-resolution=true \
		-verification=true -read-set=true -write-set=true -map-correlation=true -restrict-helper-function=true -helper-function-restriction-rules=$(HELPER_FUNC_CONFIG) $(XDP_TARGETS).bc
