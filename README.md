# eBPF sched_ext 示例

这是一个最小化的 sched_ext 调度器示例：把所有任务放入全局 DSQ 并从全局 DSQ 取任务运行。

## 构建并启动测试 VM

在宿主机执行：

1. 进入开发环境（可选，但推荐）：
   - `nix develop`
2. 构建 VM：
   - `nix build .#nixosConfigurations.ebpf-vm.config.system.build.vm`
3. 运行 VM：
   - `./result/bin/run-ebpf-test-vm`

VM 启动后会自动以 root 登录，宿主机工作区会挂载到 `/src`。

## 在 VM 中构建并加载

VM 启动后，在 VM 内执行：

1. 进入共享目录：
   - `/src/scheduling`
2. 生成并编译：
   - `make`
3. 以 root 加载：
   - `./sched`

按 Ctrl+C 退出并卸载。
