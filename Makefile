CLANG ?= $(or $(BPF_CLANG),clang)
CC ?= cc
BPFTOOL ?= bpftool

VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
VMLINUX ?= vmlinux.h

LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS ?= $(shell pkg-config --libs libbpf)

CFLAGS ?= -O2 -g -Wall -Wextra
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86 $(LIBBPF_CFLAGS)

VMLINUX:=$(VMLINUX)

.PHONY: all clean

all: sched

$(VMLINUX): $(VMLINUX_BTF)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

sched.bpf.o: sched.bpf.c $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

sched.skel.h: sched.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

sched: sched.c sched.skel.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

clean:
	rm -f sched sched.bpf.o sched.skel.h $(VMLINUX)
