#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "sched.skel.h"

/* 系统配置结构体（与BPF代码保持一致） */
struct sys_config {
	uint32_t num_cpus;      /* CPU总数 */
	uint32_t num_perf_cpus; /* 性能核心数 */
	uint32_t num_eff_cpus;  /* 能效核心数 */
	uint32_t reserved[5];   /* 预留字段 */
};

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

/* 检测系统CPU拓扑并初始化配置 */
static void init_sys_config(struct sys_config *config)
{
	/* 获取CPU总数 */
	int num_cpus = libbpf_num_possible_cpus();
	if (num_cpus <= 0) {
		num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	}
	if (num_cpus <= 0) {
		num_cpus = 8; /* 默认值 */
	}

	config->num_cpus = num_cpus;

	/* 
	 * 检测小核/大核配置（P-core/E-core）
	 * 在Arm big.LITTLE或Intel P+E架构中
	 * 此处为启发式估计：假设后半部分为能效核心
	 */
	config->num_perf_cpus = (num_cpus + 1) / 2;  /* 性能核心为前半部分 */
	config->num_eff_cpus = num_cpus / 2;         /* 能效核心为后半部分 */

	fprintf(stderr, "System config: num_cpus=%u, perf=%u, eff=%u\n",
		config->num_cpus, config->num_perf_cpus, config->num_eff_cpus);
}

/* 将系统配置写入BPF map */
static int write_sys_config_to_bpf(struct sched_bpf *skel, struct sys_config *config)
{
	int map_fd;
	uint32_t key = 0;

	if (!skel || !skel->maps.sys_config_map) {
		fprintf(stderr, "Failed to get sys_config_map\n");
		return -1;
	}

	map_fd = bpf_map__fd(skel->maps.sys_config_map);
	if (map_fd < 0) {
		fprintf(stderr, "Failed to get sys_config_map fd: %d\n", map_fd);
		return -1;
	}

	if (bpf_map_update_elem(map_fd, &key, config, 0) != 0) {
		fprintf(stderr, "Failed to update sys_config_map: %s\n", strerror(errno));
		return -1;
	}

	fprintf(stderr, "System config written to BPF map successfully\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct sched_bpf *skel = NULL;
	int err;

	(void)argc;
	(void)argv;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	if (bump_memlock_rlimit()) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
		return 1;
	}

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	skel = sched_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = sched_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
		goto cleanup;
	}

	err = sched_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* 初始化系统配置并写入BPF map */
	struct sys_config config = {0};
	init_sys_config(&config);
	if (write_sys_config_to_bpf(skel, &config) != 0) {
		fprintf(stderr, "Warning: Failed to write system config to BPF map\n");
	}

	printf("sched_ext scheduler loaded. Press Ctrl+C to exit.\n");

	while (!exiting)
		sleep(1);

cleanup:
	sched_bpf__destroy(skel);
	return err != 0;
}
