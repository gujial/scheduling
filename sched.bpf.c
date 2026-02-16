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
    u64 enqueue_time;   // 入队时间，用于计算运行/等待时长
    u32 assigned_cpu;   // 分配的 CPU
    u32 current_element; // 当前五行元素
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);
    __type(value, struct task_ctx);
} task_ctx_map SEC(".maps");

/* 系统配置信息 */
struct sys_config {
    u32 num_cpus;      // CPU总数
    u32 num_perf_cpus; // 性能核心数
    u32 num_eff_cpus;  // 能效核心数
    u32 reserved[5];   // 预留字段
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct sys_config);
} sys_config_map SEC(".maps");

extern s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern void scx_bpf_destroy_dsq(u64 dsq_id) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;

char LICENSE[] SEC("license") = "GPL";

/* 时间片定义 */
#define slice_long   10000000ULL  // 10ms (乾卦：天行健)
#define slice_normal  5000000ULL  // 5ms
#define slice_short   1000000ULL  // 1ms (坤卦：地势坤)

/* 八卦对应的DSQ ID */
#define DSQ_KUN   1  // 000 坤：极阴
#define DSQ_ZHEN  2  // 001 震：雷
#define DSQ_KAN   3  // 010 坎：水
#define DSQ_DUI   4  // 011 兑：泽
#define DSQ_GEN   5  // 100 艮：山
#define DSQ_LI    6  // 101 离：火
#define DSQ_XUN   7  // 110 巽：风
#define DSQ_QIAN  8  // 111 乾：极阳

/*
	定卦算法：根据进程的行为特征计算八卦类型（gua_type）。每个维度对应一个爻，三维度组合成八卦。
	在 eBPF 中，我们可以实时监控进程的三个维度，每个维度根据阈值产生一个"阴（0）"或"阳（1）"：
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
	寻龙点穴算法：根据卦象的"五行属性"将进程分配到最合适的物理核心上。
	乾卦（纯阳）任务：分配到 "天位"（频率最高的核心，如 Core 0 或 Turbo Boost 核心）。
    坤卦（纯阴）任务：分配到 "地位"（能效核心/小核），追求平稳。
    震卦（雷）任务：分配到离中断源最近的核心，追求极致响应。
    离卦（火）任务：分配到散热条件最好（当前温度最低）的核心。
*/
static __always_inline s32 select_cpu_by_fengshui(u32 pid, u32 gua) {
    s32 selected_cpu = -1;

    /* 从系统配置map中获取实际CPU数量 */
    u32 key = 0;
    struct sys_config *config = bpf_map_lookup_elem(&sys_config_map, &key);
    u32 num_cpus = 8; // 默认8个CPU
    u32 num_perf_cpus = 4; // 默认性能核心
    
    if (config) {
        num_cpus = config->num_cpus > 0 ? config->num_cpus : 8;
        num_perf_cpus = config->num_perf_cpus > 0 ? config->num_perf_cpus : (num_cpus / 2);
    }

    /* 获取当前 CPU，用作基准 */
    s32 current_cpu = bpf_get_smp_processor_id();
    if (current_cpu < 0) current_cpu = 0;

    switch (gua) {
        case GUA_QIAN:
            /* 乾卦（纯阳 111）：天位 - 优先调度到高频核心 */
            /* 倾向于性能核心（前num_perf_cpus个核心） */
            selected_cpu = pid % num_perf_cpus;
            break;
            
        case GUA_KUN:
            /* 坤卦（纯阴 000）：地位 - 调度到能效核心 */
            /* 倾向于能效核心（后面的核心），减少竞争 */
            if (num_cpus > num_perf_cpus) {
                u32 eff_cpu_count = num_cpus - num_perf_cpus;
                selected_cpu = num_perf_cpus + (pid % eff_cpu_count);
            } else {
                selected_cpu = pid % num_cpus;
            }
            break;
            
        case GUA_ZHEN:
            /* 震卦（雷 001）：追求响应性 - 保持在当前核心附近 */
            /* 优先在性能核心中保持亲和性 */
            if (current_cpu < num_perf_cpus) {
                selected_cpu = current_cpu;  // 保持在当前性能核心
            } else {
                selected_cpu = pid % num_perf_cpus;  // 迁移到性能核心
            }
            break;
            
        case GUA_LI:
            /* 离卦（火 101）：需要散热 - 选择相对空闲的核心 */
            /* 分散到不同核心以降低热密度 */
            selected_cpu = (pid + current_cpu) % num_cpus;
            break;
            
        case GUA_XUN:
            /* 巽卦（风 110）：灵活流动 - 选择相邻核心 */
            selected_cpu = (current_cpu + 1) % num_cpus;
            break;
            
        case GUA_KAN:
            /* 坎卦（水 010）：流动特性 - 允许跨核运行 */
            /* IO密集型任务，倾向于能效核心 */
            if (num_cpus > num_perf_cpus) {
                u32 eff_cpu_count = num_cpus - num_perf_cpus;
                selected_cpu = num_perf_cpus + ((pid ^ current_cpu) % eff_cpu_count);
            } else {
                selected_cpu = (pid ^ current_cpu) % num_cpus;
            }
            break;
            
        case GUA_GEN:
            /* 艮卦（山 100）：稳定特性 - 黏着在当前核心 */
            selected_cpu = current_cpu;
            break;
            
        case GUA_DUI:
            /* 兑卦（泽 011）：交互特性 - 选择邻近核心 */
            /* 优先在性能核心中进行交互 */
            if (current_cpu < num_perf_cpus) {
                selected_cpu = (current_cpu + 1) % num_perf_cpus;
            } else {
                selected_cpu = pid % num_perf_cpus;
            }
            break;
            
        default:
            selected_cpu = current_cpu;
    }

    return selected_cpu >= 0 ? selected_cpu : current_cpu;
}

/* 将卦象映射到五行元素 */
static __always_inline u32 gua_to_xingwu(u32 gua) {
    /* 五行定义：0=木, 1=火, 2=土, 3=金, 4=水 */
    switch (gua) {
        case GUA_QIAN: return 3;  /* 乾=金（刚健） */
        case GUA_KUN:  return 2;  /* 坤=土（厚实） */
        case GUA_ZHEN: return 0;  /* 震=木（生发） */
        case GUA_LI:   return 1;  /* 离=火（光明） */
        case GUA_XUN:  return 0;  /* 巽=木（柔和） */
        case GUA_KAN:  return 4;  /* 坎=水（流动） */
        case GUA_GEN:  return 2;  /* 艮=土（止） */
        case GUA_DUI:  return 3;  /* 兑=金（璀璨） */
        default:       return 2;  /* 默认土 */
    }
}

/*
	五行相生相克算法：在调度决策中引入"相生相克"关系，动态调整进程优先级和核心分配。
	将资源竞争抽象为五行：木（创建）、火（执行）、土（存储）、金（IO）、水（数据流）。
    相生（协作）：若核心 A 运行着"水"任务（网卡数据流），则优先调度"木"任务（协议栈处理），因为水生木，缓存预热效果好。
    相克（冲突）：若核心 B 运行着"火"任务（高功耗计算），禁止再调度"火"任务进入（避免热节流/Thermal Throttling），应调度"水"任务（IO 等待型）来"降温"。
*/
bool is_conflict(u32 task_element, u32 cpu_element) {
    /* 五行相克关系矩阵：
     * 木克土，土克水，水克火，火克金，金克木
     * 如果 task_element 克 cpu_element，返回 true（冲突）
     * 木(0) 克 土(2), 土(2) 克 水(4), 水(4) 克 火(1), 
     * 火(1) 克 金(3), 金(3) 克 木(0)
     */
    switch (task_element) {
        case 0:  /* 木 */
            return cpu_element == 2; /* 木克土 */
        case 1:  /* 火 */
            return cpu_element == 3; /* 火克金 */
        case 2:  /* 土 */
            return cpu_element == 4; /* 土克水 */
        case 3:  /* 金 */
            return cpu_element == 0; /* 金克木 */
        case 4:  /* 水 */
            return cpu_element == 1; /* 水克火 */
        default:
            return false;
    }
}

/*
	变卦算法：解决进程长时间运行后的状态变化（Aging）。
	《易经》的核心是"变"。一个进程最初是"乾卦"（积极运行），运行太久后会变成"亢龙有悔"，即物极必反，优先级应当下调。
    阳极生阴：如果一个"阳"任务运行时间超过了 slice，强制将其最低位的爻翻转，改变其卦象，从而触发重新调度。
    阴极生阳：一个在等待队列（坎/水）中积压太久的进程，通过"变爻"提升其"阳气"，使其获得执行机会。
*/
static __always_inline u32 handle_bian_gua(struct task_struct *p, struct task_ctx *tctx, u64 elapsed_ns) {
    u32 current_gua = tctx->current_gua;
    
    /* 阳极生阴：运行时间过长（超过 50ms）的纯阳任务应转为阴卦 */
    if (current_gua == GUA_QIAN && elapsed_ns > 50000000ULL) {
        /* 乾(111) -> 坤(000)，翻转所有爻 */
        tctx->current_gua = GUA_KUN;
        return GUA_KUN;
    }
    
    /* 阴极生阳：在队列中等待过久的纯阴任务应转为阳卦，提升执行机会 */
    if (current_gua == GUA_KUN && elapsed_ns > 100000000ULL) {
        /* 坤(000) -> 乾(111)，翻转所有爻 */
        tctx->current_gua = GUA_QIAN;
        return GUA_QIAN;
    }
    
    /* 单爻翻转：运行时间中等(10-50ms)的多爻卦象，翻转最低位（初爻） */
    if (elapsed_ns > 10000000ULL && elapsed_ns <= 50000000ULL) {
        if (current_gua != GUA_QIAN && current_gua != GUA_KUN) {
            u32 new_gua = current_gua ^ 1;  /* 翻转最低位 */
            tctx->current_gua = new_gua;
            return new_gua;
        }
    }
    
    /* 无需变卦 */
    return current_gua;
}

SEC("struct_ops.s/init")
s32 sched_init(void)
{
    /* 创建八卦DSQ */
    if (scx_bpf_create_dsq(DSQ_KUN, -1))
        return -1;
    if (scx_bpf_create_dsq(DSQ_ZHEN, -1))
        return -1;
    if (scx_bpf_create_dsq(DSQ_KAN, -1))
        return -1;
    if (scx_bpf_create_dsq(DSQ_DUI, -1))
        return -1;
    if (scx_bpf_create_dsq(DSQ_GEN, -1))
        return -1;
    if (scx_bpf_create_dsq(DSQ_LI, -1))
        return -1;
    if (scx_bpf_create_dsq(DSQ_XUN, -1))
        return -1;
    if (scx_bpf_create_dsq(DSQ_QIAN, -1))
        return -1;
	return 0;
}

SEC("struct_ops.s/exit")
s32 BPF_PROG(sched_exit, struct scx_exit_info *ei)
{
	(void)ei;
    /* 销毁八卦DSQ */
    scx_bpf_destroy_dsq(DSQ_KUN);
    scx_bpf_destroy_dsq(DSQ_ZHEN);
    scx_bpf_destroy_dsq(DSQ_KAN);
    scx_bpf_destroy_dsq(DSQ_DUI);
    scx_bpf_destroy_dsq(DSQ_GEN);
    scx_bpf_destroy_dsq(DSQ_LI);
    scx_bpf_destroy_dsq(DSQ_XUN);
    scx_bpf_destroy_dsq(DSQ_QIAN);
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
        u64 now = bpf_ktime_get_ns();
        u64 elapsed_ns = 0;
        
        /* 记录入队时间 */
        if (tctx->enqueue_time == 0) {
            tctx->enqueue_time = now;
        } else {
            elapsed_ns = now - tctx->enqueue_time;
        }
        
        /* 第一步：定卦 - 实时观测进程特征，计算卦象 */
        u32 gua = calculate_task_gua(p, tctx);
        
        /* 第二步：变卦 - 根据运行/等待时长调整卦象（处理状态衰老） */
        gua = handle_bian_gua(p, tctx, elapsed_ns);
        tctx->current_gua = gua;
        
        /* 第三步：映射到五行元素 */
        u32 task_element = gua_to_xingwu(gua);
        tctx->current_element = task_element;
        
        /* 第四步：寻龙点穴 - 根据卦象选择最优 CPU */
        s32 selected_cpu = select_cpu_by_fengshui(pid, gua);
        if (selected_cpu >= 0) {
            tctx->assigned_cpu = selected_cpu;
        }
        
        /* 第五步：五行相克检查 - 避免资源冲突 */
        /* 注：在实际应用中可以根据当前 CPU 上的任务进行冲突检查 */
        /* 这里我们的策略是使用冲突检查优化队列分配 */
        
        /* 第六步：根据卦象和分析结果选择分发策略 */
        u64 time_slice = slice_normal;  /* 默认时间片 */
        u64 dsq_id = SCX_DSQ_GLOBAL;     /* 默认全局队列 */
        
        switch (gua) {
            case GUA_QIAN:
                /* 
                 * 乾卦 (111)：天行健，君子以自强不息
                 * 特点：纯阳，极度活跃
                 * 策略：分发至乾DSQ，赋予极长的时间片，减少上下文切换损耗
                 * 调度到高性能核心
                 */
                dsq_id = DSQ_QIAN;
                time_slice = slice_long;    /* 10ms 极长时间片 */
                break;
            
            case GUA_KUN:
                /* 
                 * 坤卦 (000)：地势坤，君子以厚德载物
                 * 特点：纯阴，极度沉稳
                 * 策略：放入坤DSQ，短时间片，避免饥荒和干扰
                 * 调度到能效核心
                 */
                dsq_id = DSQ_KUN;
                time_slice = slice_short;   /* 1ms 短时间片 */
                break;
            
            case GUA_ZHEN:
                /* 
                 * 震卦 (001)：雷动
                 * 特点：含阳爻，具动感，响应性强
                 * 策略：分发至震DSQ，中等时间片，追求缓存亲和性和响应性
                 */
                dsq_id = DSQ_ZHEN;
                time_slice = slice_normal;  /* 5ms 标准时间片 */
                break;
            
            case GUA_DUI:
                /* 
                 * 兑卦 (011)：泽润
                 * 特点：含阳爻，交互式，社交型
                 * 策略：分发至兑DSQ，中等时间片，追求交互响应
                 */
                dsq_id = DSQ_DUI;
                time_slice = slice_normal;  /* 5ms 标准时间片 */
                break;
            
            case GUA_LI:
                /* 
                 * 离卦 (101)：火炫
                 * 特点：高运算强度，高功耗
                 * 策略：分发至离DSQ，长时间片，减少热节流
                 * 调度到散热好的核心
                 */
                dsq_id = DSQ_LI;
                time_slice = slice_long;    /* 10ms 减少热节流 */
                break;
            
            case GUA_XUN:
                /* 
                 * 巽卦 (110)：风行
                 * 特点：灵活变化，善于适应
                 * 策略：分发至巽DSQ，中等时间片，灵活调度
                 */
                dsq_id = DSQ_XUN;
                time_slice = slice_normal;
                break;
            
            case GUA_KAN:
                /* 
                 * 坎卦 (010)：水流
                 * 特点：流动，IO密集
                 * 策略：分发至坎DSQ，短时间片，快速响应IO事件
                 */
                dsq_id = DSQ_KAN;
                time_slice = slice_short;   /* 1ms 快速响应 */
                break;
            
            case GUA_GEN:
                /* 
                 * 艮卦 (100)：山止
                 * 特点：稳定，缓冲型
                 * 策略：分发至艮DSQ，中等时间片，倾向于黏着当前核心
                 */
                dsq_id = DSQ_GEN;
                time_slice = slice_normal;
                break;
            
            default:
                dsq_id = SCX_DSQ_GLOBAL;
                time_slice = slice_normal;
        }
        
        /* 执行队列插入 */
        scx_bpf_dsq_insert(p, dsq_id, time_slice, enq_flags);
        
        /* 重置入队时间，准备下一周期 */
        tctx->enqueue_time = now;
    }

	return 0;
}

SEC("struct_ops/dispatch")
s32 BPF_PROG(dispatch, s32 cpu, struct task_struct *prev)
{
    /* 
     * dispatch 是从就绪队列中选择任务进行分派执行的关键点
     * 智能分派策略：按优先级和五行相克关系从不同的卦象DSQ中分派
     * 
     * 分派优先级：
     * 1. 乾卦(高性能)优先级最高，保证高性能任务执行
     * 2. 其他卦象按动态优先级分派
     * 3. 坤卦(能效)优先级最低，避免饥荒
     * 4. 全局队列由内核自动处理
     */
    
    /* 优先级1：乾卦(极阳) - 高性能任务 */
    if (scx_bpf_dsq_move_to_local(DSQ_QIAN)) {
        return 0;
    }
    
    /* 优先级2：离卦(火) - 高运算强度任务 */
    if (scx_bpf_dsq_move_to_local(DSQ_LI)) {
        return 0;
    }
    
    /* 优先级3：震卦/兑卦(雷/泽) - 交互式任务 */
    if (scx_bpf_dsq_move_to_local(DSQ_ZHEN)) {
        return 0;
    }
    if (scx_bpf_dsq_move_to_local(DSQ_DUI)) {
        return 0;
    }
    
    /* 优先级4：巽卦(风) - 灵活适应型任务 */
    if (scx_bpf_dsq_move_to_local(DSQ_XUN)) {
        return 0;
    }
    
    /* 优先级5：艮卦(山) - 稳定型任务 */
    if (scx_bpf_dsq_move_to_local(DSQ_GEN)) {
        return 0;
    }
    
    /* 优先级6：坎卦(水) - IO密集型任务 */
    if (scx_bpf_dsq_move_to_local(DSQ_KAN)) {
        return 0;
    }
    
    /* 优先级7：坤卦(极阴) - 能效型任务，最后分派以避免饥荒 */
    if (scx_bpf_dsq_move_to_local(DSQ_KUN)) {
        return 0;
    }
    
    /* 所有DSQ都为空，内核会从 SCX_DSQ_GLOBAL 中自动获取任务 */
	return 0;
}

SEC(".struct_ops")
struct sched_ext_ops ops = {
	.enqueue = (void (*)(struct task_struct *, u64))enqueue,
	.dispatch = (void (*)(s32, struct task_struct *))dispatch,
	.init = sched_init,
	.exit = (void (*)(struct scx_exit_info *))sched_exit,
	.name = "fengshui",
};
