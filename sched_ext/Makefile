BPF_CLANG ?= clang
BPF_CFLAGS := -g -O2 -Wall -Wextra -target bpf -D__TARGET_ARCH_x86

VMLINUX_H := vmlinux.h
BPF_OBJ := sched_simple.bpf.o
SKEL := sched_simple.skel.h

USER_C := sched_simple.c
USER_BIN := sched_simple

.PHONY: all clean vmlinux

all: $(USER_BIN)

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(BPF_OBJ): sched_simple.bpf.c $(VMLINUX_H)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(USER_BIN): $(USER_C) $(SKEL)
	cc -g -O2 -Wall -Wextra -I. $< -o $@ -lbpf -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(SKEL) $(USER_BIN) $(VMLINUX_H)
