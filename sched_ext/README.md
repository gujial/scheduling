# eBPF sched_ext 示例

这是一个最小化的 sched_ext 调度器示例：把所有任务放入全局 DSQ 并从全局 DSQ 取任务运行。

## 在 VM 中构建并加载

VM 启动后，在 VM 内执行：

1. 进入共享目录：
   - `/src/sched_ext`
2. 生成并编译：
   - `make`
3. 以 root 加载：
   - `./sched_simple`

按 Ctrl+C 退出并卸载。
