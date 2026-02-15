#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define SLICE_NS (5ULL * 1000 * 1000)

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	/*
	 * 把所有任务放入全局 DSQ，使用默认时间片。
	 */
	scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SLICE_NS, enq_flags);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * 从全局 DSQ 取一个任务运行。
	 */
	scx_bpf_consume(SCX_DSQ_GLOBAL);
}

s32 BPF_STRUCT_OPS(simple_init)
{
	return 0;
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	/* no-op */
}

SEC(".struct_ops")
struct sched_ext_ops simple_ops = {
	.enqueue = (void *)simple_enqueue,
	.dispatch = (void *)simple_dispatch,
	.init = (void *)simple_init,
	.exit = (void *)simple_exit,
	.name = "simple_scx",
};
