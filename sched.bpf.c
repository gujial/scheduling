#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern void scx_bpf_destroy_dsq(u64 dsq_id) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;

char LICENSE[] SEC("license") = "GPL";

#define SIMPLE_DSQ_ID 1

SEC("struct_ops.s/simple_init")
s32 simple_init(void)
{
	if (scx_bpf_create_dsq(SIMPLE_DSQ_ID, -1))
		return -1;
	return 0;
}

SEC("struct_ops.s/simple_exit")
s32 BPF_PROG(simple_exit, struct scx_exit_info *ei)
{
	(void)ei;
	scx_bpf_destroy_dsq(SIMPLE_DSQ_ID);
	return 0;
}

SEC("struct_ops/simple_enqueue")
s32 BPF_PROG(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SIMPLE_DSQ_ID, SCX_SLICE_DFL, enq_flags);
	return 0;
}

SEC("struct_ops/simple_dispatch")
s32 BPF_PROG(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	(void)cpu;
	(void)prev;
	scx_bpf_dsq_move_to_local(SIMPLE_DSQ_ID);
	return 0;
}

SEC(".struct_ops")
struct sched_ext_ops simple_ops = {
	.enqueue = (void (*)(struct task_struct *, u64))simple_enqueue,
	.dispatch = (void (*)(s32, struct task_struct *))simple_dispatch,
	.init = simple_init,
	.exit = (void (*)(struct scx_exit_info *))simple_exit,
	.name = "simple_global",
};
