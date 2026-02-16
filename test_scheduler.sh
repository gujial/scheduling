#!/bin/bash
# 调度器测试脚本 - 针对32核CPU (16 P核 + 16 E核)

set -e

# 配置参数
NUM_CPUS=32
NUM_P_CORES=16  # 性能核心
NUM_E_CORES=16  # 能效核心
TEST_DURATION=60  # 测试持续时间（秒）
OUTPUT_DIR="./scx"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查必要的工具
check_dependencies() {
    log_info "检查依赖项..."
    
    if ! command -v stress-ng &> /dev/null; then
        log_error "stress-ng 未安装，请先安装: sudo apt install stress-ng"
        exit 1
    fi
    
    if [ ! -f "./sched" ]; then
        log_error "调度器程序 ./sched 不存在，请先运行 make 编译"
        exit 1
    fi
    
    if [ ! -f "./plot.py" ]; then
        log_error "绘图脚本 ./plot.py 不存在"
        exit 1
    fi
    
    if [ "$EUID" -ne 0 ]; then
        log_error "此脚本需要 root 权限运行"
        exit 1
    fi
    
    log_info "依赖项检查完成"
}

# 清理旧数据
cleanup_old_data() {
    log_info "清理旧数据..."
    rm -rf "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
}

# 启动调度器
start_scheduler() {
    log_info "启动调度器..."
    ./sched &
    SCHED_PID=$!
    sleep 2  # 等待调度器初始化
    
    if ! kill -0 $SCHED_PID 2>/dev/null; then
        log_error "调度器启动失败"
        exit 1
    fi
    
    log_info "调度器已启动 (PID: $SCHED_PID)"
}

# 停止调度器
stop_scheduler() {
    log_info "停止调度器..."
    if [ ! -z "$SCHED_PID" ] && kill -0 $SCHED_PID 2>/dev/null; then
        kill -SIGINT $SCHED_PID
        wait $SCHED_PID 2>/dev/null || true
    fi
    log_info "调度器已停止"
}

# 运行 stress-ng 测试
run_stress_tests() {
    log_info "开始 stress-ng 负载测试 (持续 ${TEST_DURATION} 秒)..."
    
    # 测试场景1: CPU密集型任务
    log_info "场景1: CPU密集型任务 (在所有核心上运行)"
    stress-ng --cpu $NUM_CPUS --cpu-method all --timeout ${TEST_DURATION}s &
    STRESS_PIDS+=($!)
    
    sleep $((TEST_DURATION + 5))
    
    # 等待所有stress进程完成
    for pid in "${STRESS_PIDS[@]}"; do
        wait $pid 2>/dev/null || true
    done
    
    log_info "等待数据采集..."
    sleep 5
    
    # 测试场景2: 混合负载 (CPU + 内存)
    log_info "场景2: 混合负载 (CPU + 内存)"
    STRESS_PIDS=()
    stress-ng --cpu $((NUM_CPUS / 2)) --vm $((NUM_CPUS / 4)) --vm-bytes 128M --timeout ${TEST_DURATION}s &
    STRESS_PIDS+=($!)
    
    sleep $((TEST_DURATION + 5))
    
    for pid in "${STRESS_PIDS[@]}"; do
        wait $pid 2>/dev/null || true
    done
    
    log_info "等待数据采集..."
    sleep 5
    
    # 测试场景3: I/O密集型 + CPU轻负载
    log_info "场景3: I/O密集型 + CPU轻负载"
    STRESS_PIDS=()
    stress-ng --cpu $((NUM_CPUS / 4)) --io 8 --hdd 4 --timeout ${TEST_DURATION}s &
    STRESS_PIDS+=($!)
    
    sleep $((TEST_DURATION + 5))
    
    for pid in "${STRESS_PIDS[@]}"; do
        wait $pid 2>/dev/null || true
    done
    
    log_info "等待最终数据采集..."
    sleep 5
}

# 运行简化版测试（快速测试）
run_quick_test() {
    log_info "开始快速测试 (持续 ${TEST_DURATION} 秒)..."
    
    # 混合负载: CPU + 内存 + I/O
    log_info "运行混合负载测试..."
    stress-ng \
        --cpu $((NUM_CPUS * 3 / 4)) \
        --cpu-method all \
        --vm $((NUM_CPUS / 4)) \
        --vm-bytes 256M \
        --io 4 \
        --timeout ${TEST_DURATION}s &
    STRESS_PID=$!
    
    # 每10秒输出一次进度
    for i in $(seq 1 $((TEST_DURATION / 10))); do
        sleep 10
        log_info "测试进度: $((i * 10))/${TEST_DURATION} 秒"
    done
    
    wait $STRESS_PID 2>/dev/null || true
    
    log_info "等待最终数据采集..."
    sleep 5
}

# 生成图表
generate_plots() {
    log_info "生成可视化图表..."
    
    if [ ! -f "$OUTPUT_DIR/task_ctx_"*.json ]; then
        log_error "未找到采样数据文件"
        return 1
    fi
    
    python3 ./plot.py
    
    if [ $? -eq 0 ]; then
        log_info "图表已生成在 $OUTPUT_DIR 目录下:"
        ls -lh "$OUTPUT_DIR"/*.png 2>/dev/null || log_warn "未找到生成的PNG文件"
    else
        log_error "图表生成失败"
        return 1
    fi
}

# 清理函数
cleanup() {
    log_info "执行清理..."
    stop_scheduler
    
    # 清理所有stress-ng进程
    pkill -9 stress-ng 2>/dev/null || true
    
    log_info "清理完成"
}

# 设置信号处理
trap cleanup EXIT INT TERM

# 主函数
main() {
    echo "======================================"
    echo "  eBPF 调度器测试脚本"
    echo "  CPU配置: ${NUM_CPUS}核 (${NUM_P_CORES}P + ${NUM_E_CORES}E)"
    echo "======================================"
    echo ""
    
    # 解析命令行参数
    TEST_MODE="quick"
    if [ "$1" == "--full" ]; then
        TEST_MODE="full"
        log_info "使用完整测试模式"
    else
        log_info "使用快速测试模式 (使用 --full 进行完整测试)"
    fi
    
    if [ "$2" != "" ]; then
        TEST_DURATION=$2
        log_info "测试时长设置为: ${TEST_DURATION} 秒"
    fi
    
    check_dependencies
    cleanup_old_data
    start_scheduler
    
    if [ "$TEST_MODE" == "full" ]; then
        run_stress_tests
    else
        run_quick_test
    fi
    
    stop_scheduler
    
    log_info "测试完成"
    echo ""
    
    generate_plots
    
    echo ""
    log_info "所有任务完成！"
    echo "结果保存在: $OUTPUT_DIR/"
}

# 脚本入口
STRESS_PIDS=()
SCHED_PID=""
main "$@"
