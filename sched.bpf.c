#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 卦象定义
enum yijing_gua {
    GUA_KUN  = 0, // 000 坤：极阴
    GUA_ZHEN = 1, // 001 震：雷
    GUA_KAN  = 2, // 010 坎：水
    GUA_DUI  = 3, // 011 兑：泽
    GUA_GEN  = 4, // 100 艮：山
    GUA_LI   = 5, // 101 离：火
    GUA_XUN  = 6, // 110 巽：风
    GUA_QIAN = 7, // 111 乾：极阳
};

// 进程私有上下文（用于计算增量）
struct task_ctx {
    u64 last_vruntime;
    u64 last_run_timestamp;
    u32 last_nvcsw; // 上次自愿上下文切换次数
    u32 current_gua;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);
    __type(value, struct task_ctx);
} task_ctx_map SEC(".maps");

extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern void scx_bpf_destroy_dsq(u64 dsq_id) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;

char LICENSE[] SEC("license") = "GPL";

#define DSQ_ID 1
#define slice_long   10000000ULL  // 10ms (乾卦：天行健)
#define slice_normal  5000000ULL  // 5ms
#define slice_short   1000000ULL  // 1ms (坤卦：地势坤)
#define LOW_PRIO_DSQ  64          // 自定义低优队列 ID

/*
	定卦算法：根据进程的行为特征计算八卦类型（gua_type）。每个维度对应一个爻，三维度组合成八卦。
	在 eBPF 中，我们可以实时监控进程的三个维度，每个维度根据阈值产生一个“阴（0）”或“阳（1）”：
    	初爻（底部）：计算强度。CPU 利用率 > 50% 为阳，否则为阴。
    	二爻（中部）：交互频率。上下文切换/自愿睡眠频率高为阳（灵动），低为阴（沉稳）。
    	三爻（顶部）：内存/IO 足迹。RSS 内存占用或磁盘 IO 带宽大为阳，小为阴。
*/
static __always_inline u32 calculate_task_gua(struct task_struct *p, struct task_ctx *tctx) {
    u32 yao1 = 0, yao2 = 0, yao3 = 0;
    u64 now = bpf_ktime_get_ns();
    
    // --- 初爻：计算强度 ---
    // 计算两次调度间的 CPU 占用率 (简单的 delta 计算)
    u64 runtime = BPF_CORE_READ(p, se.sum_exec_runtime);
    u64 wall_time = 0;
    u64 delta_runtime = 0;

    if (tctx->last_run_timestamp > 0)
        wall_time = now - tctx->last_run_timestamp;

    if (tctx->last_vruntime > 0 && runtime >= tctx->last_vruntime)
        delta_runtime = runtime - tctx->last_vruntime;

    if (wall_time > 0 && delta_runtime > 0) {
        u64 util = (delta_runtime * 1000) / wall_time;
        if (util > 500) yao1 = 1; // 占用超过 50% 为阳
    }

    // --- 二爻：交互灵活性 ---
    // 检查自愿上下文切换 (nvcsw) 的频率
    u32 nvcsw = BPF_CORE_READ(p, nvcsw);
    if (tctx->last_nvcsw > 0 && nvcsw > tctx->last_nvcsw &&
        nvcsw - tctx->last_nvcsw > 50) { // 阈值根据经验设定
        yao2 = 1; // 灵动为阳
    }

    // --- 三爻：空间足迹 ---
    // 获取进程的物理内存占用 (RSS)
    struct mm_struct *mm = BPF_CORE_READ(p, mm);
    if (mm) {
        // 读取 RSS 计数 (需处理 eBPF 的 core read)
        long rss = BPF_CORE_READ(mm, rss_stat[0].count);
        if (rss > 25600) { // 超过 100MB (4K page * 25600) 为阳
            yao3 = 1;
        }
    }

    // 更新历史记录供下次计算使用
    tctx->last_run_timestamp = now;
    tctx->last_nvcsw = nvcsw;
    tctx->last_vruntime = runtime;

	// 合成八卦 (三位二进制)
    tctx->current_gua = (yao3 << 2) | (yao2 << 1) | yao1;
    return tctx->current_gua;
}

/*
	寻龙点穴算法：根据卦象的“五行属性”将进程分配到最合适的物理核心上。
	乾卦（纯阳）任务：分配到 “天位”（频率最高的核心，如 Core 0 或 Turbo Boost 核心）。
    坤卦（纯阴）任务：分配到 “地位”（能效核心/小核），追求平稳。
    震卦（雷）任务：分配到离中断源最近的核心，追求极致响应。
    离卦（火）任务：分配到散热条件最好（当前温度最低）的核心。
*/
s32 select_cpu_by_fengshui(struct task_struct *p, u32 gua) {
    //TODO: 实际实现中需要根据系统拓扑结构和当前负载情况进行调整
}

/*
	五行相生相克算法：在调度决策中引入“相生相克”关系，动态调整进程优先级和核心分配。
	将资源竞争抽象为五行：木（创建）、火（执行）、土（存储）、金（IO）、水（数据流）。
    相生（协作）：若核心 A 运行着“水”任务（网卡数据流），则优先调度“木”任务（协议栈处理），因为水生木，缓存预热效果好。
    相克（冲突）：若核心 B 运行着“火”任务（高功耗计算），禁止再调度“火”任务进入（避免热节流/Thermal Throttling），应调度“水”任务（IO 等待型）来“降温”。
*/
bool is_conflict(u32 task_element, u32 cpu_element) {
    // TODO: 实际实现中需要根据具体的五行分类和系统状态进行调整
}

/*
	变卦算法：解决进程长时间运行后的状态变化（Aging）。
	《易经》的核心是“变”。一个进程最初是“乾卦”（积极运行），运行太久后会变成“亢龙有悔”，即物极必反，优先级应当下调。
    阳极生阴：如果一个“阳”任务运行时间超过了 slice，强制将其最低位的爻翻转，改变其卦象，从而触发重新调度。
    阴极生阳：一个在等待队列（坎/水）中积压太久的进程，通过“变爻”提升其“阳气”，使其获得执行机会。
*/
void handle_bian_gua(struct task_context *ctx) {
    // TODO: 实际实现中需要根据进程的运行时间和等待时间进行调整
}

SEC("struct_ops.s/init")
s32 sched_init(void)
{
	if (scx_bpf_create_dsq(DSQ_ID, -1))
		return -1;
	return 0;
}

SEC("struct_ops.s/exit")
s32 BPF_PROG(sched_exit, struct scx_exit_info *ei)
{
	(void)ei;
	scx_bpf_destroy_dsq(DSQ_ID);
	return 0;
}

SEC("struct_ops/enqueue")
s32 BPF_PROG(enqueue, struct task_struct *p, u64 enq_flags)
{
    u32 pid = BPF_CORE_READ(p, pid);
    struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
    if (!tctx) {
        struct task_ctx init = {};
        bpf_map_update_elem(&task_ctx_map, &pid, &init, BPF_NOEXIST);
        tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
    }
    if (tctx) {
        // 定卦
        // 实时观测进程特征，更新卦象
        u32 gua = calculate_task_gua(p, tctx);
        tctx->current_gua = gua;

        // 根据卦象选择分发策略
        // 这里体现了“天、地、人”三才布局思想
        
        if (gua == GUA_QIAN) {
            /* 
             * 乾卦 (111)：天行健，君子以自强不息
             * 策略：分发至全局队列，赋予极长的时间片，减少切换损耗
             */
            scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, slice_long, enq_flags);
            
        } else if (gua == GUA_KUN) {
            /* 
             * 坤卦 (000)：地势坤，君子以厚德载物
             * 策略：放入自定义的低优“地”字号队列，使用短时间片，避免干扰核心业务
             */
            scx_bpf_dispatch(p, LOW_PRIO_DSQ, slice_short, enq_flags);
            
        } else if (gua == GUA_DUI || gua == GUA_ZHEN) {
            /* 
             * 兑/震卦 (含阳爻，具动感)：代表交互式任务
             * 策略：放入本地 CPU 队列，追求 L1/L2 缓存亲和性，快速响应
             */
            scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_normal, enq_flags);
            
        } else {
            /* 
             * 其余卦象 (如坎、艮、巽、离)：中庸之道
             * 策略：默认本地调度
             */
            scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_normal, enq_flags);
        }
    }

	return 0;
}

SEC("struct_ops/dispatch")
s32 BPF_PROG(dispatch, s32 cpu, struct task_struct *prev)
{
	(void)cpu;
	(void)prev;
	scx_bpf_dsq_move_to_local(DSQ_ID);
	return 0;
}

SEC(".struct_ops")
struct sched_ext_ops ops = {
	.enqueue = (void (*)(struct task_struct *, u64))enqueue,
	.dispatch = (void (*)(s32, struct task_struct *))dispatch,
	.init = sched_init,
	.exit = (void (*)(struct scx_exit_info *))sched_exit,
	.name = "global",
};
