CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
CC ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.
CFLAGS := -Wall -O2 -I.
LDFLAGS := -lbpf -lelf -lz -lpthread

.PHONY: all clean

all: TimeDilation td_trigger_test

vmlinux.h:
	@if [ ! -f vmlinux.h ]; then \
		echo "===> [timedilation] Generating vmlinux.h from BTF..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

TimeDilation.bpf.o: TimeDilation.bpf.c TimeDilation.h scx_starve.h vmlinux.h
	@echo "===> [timedilation] Compiling BPF object"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

TimeDilation.skel.h: TimeDilation.bpf.o
	@echo "===> [timedilation] Generating skeleton"
	$(BPFTOOL) gen skeleton $< > $@

TimeDilation: TimeDilation.c TimeDilation.skel.h TimeDilation.h scx_starve.h
	@echo "===> [timedilation] Compiling userspace tool"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

td_trigger_test: td_trigger_test.c TimeDilation.h vmlinux.h
	@echo "===> [timedilation] Compiling trigger exerciser"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f TimeDilation td_trigger_test \
	      TimeDilation.bpf.o TimeDilation.skel.h vmlinux.h
