#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
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

/* 与 BPF 中的 task_ctx 对齐 */
struct task_ctx {
	uint64_t last_vruntime;
	uint64_t last_run_timestamp;
	uint32_t last_nvcsw;
	uint32_t current_gua;
	uint64_t enqueue_time;
	uint32_t assigned_cpu;
	uint32_t current_element;
};

enum output_format {
	OUTPUT_BOTH = 0,
	OUTPUT_JSON = 1,
	OUTPUT_CSV = 2,
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

static int ensure_dir_exists(const char *dir)
{
	struct stat st;
	if (stat(dir, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		fprintf(stderr, "Output path exists but is not a directory: %s\n", dir);
		return -1;
	}
	if (mkdir(dir, 0755) != 0) {
		fprintf(stderr, "Failed to create output dir %s: %s\n", dir, strerror(errno));
		return -1;
	}
	return 0;
}

static int dump_task_ctx_json(int map_fd, const char *path, long long ts_sec)
{
	FILE *f = fopen(path, "w");
	if (!f) {
		fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
		return -1;
	}

	fprintf(f, "{\"timestamp\":%lld,\"tasks\":[", ts_sec);

	uint32_t key = 0, next_key = 0;
	struct task_ctx val = {0};
	int first = 1;
	int err = bpf_map_get_next_key(map_fd, NULL, &next_key);
	while (!err) {
		if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
			if (!first)
				fprintf(f, ",");
			fprintf(
				f,
				"{\"pid\":%u,\"current_gua\":%u,\"assigned_cpu\":%u,\"current_element\":%u,\"enqueue_time\":%llu}",
				next_key,
				val.current_gua,
				val.assigned_cpu,
				val.current_element,
				(unsigned long long)val.enqueue_time);
			first = 0;
		}
		key = next_key;
		err = bpf_map_get_next_key(map_fd, &key, &next_key);
	}

	fprintf(f, "]}\n");
	fclose(f);
	return 0;
}

static int dump_task_ctx_csv(int map_fd, const char *path, long long ts_sec)
{
	FILE *f = fopen(path, "w");
	if (!f) {
		fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
		return -1;
	}

	fprintf(f, "timestamp,pid,current_gua,assigned_cpu,current_element,enqueue_time\n");

	uint32_t key = 0, next_key = 0;
	struct task_ctx val = {0};
	int err = bpf_map_get_next_key(map_fd, NULL, &next_key);
	while (!err) {
		if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
			fprintf(
				f,
				"%lld,%u,%u,%u,%u,%llu\n",
				ts_sec,
				next_key,
				val.current_gua,
				val.assigned_cpu,
				val.current_element,
				(unsigned long long)val.enqueue_time);
		}
		key = next_key;
		err = bpf_map_get_next_key(map_fd, &key, &next_key);
	}

	fclose(f);
	return 0;
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
	const char *out_dir = "./scx";
	int interval_ms = 10000;
	enum output_format fmt = OUTPUT_BOTH;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-o") && i + 1 < argc) {
			out_dir = argv[++i];
			continue;
		}
		if (!strcmp(argv[i], "-i") && i + 1 < argc) {
			interval_ms = atoi(argv[++i]);
			if (interval_ms <= 0)
				interval_ms = 1000;
			continue;
		}
		if (!strcmp(argv[i], "--format") && i + 1 < argc) {
			const char *opt = argv[++i];
			if (!strcmp(opt, "json"))
				fmt = OUTPUT_JSON;
			else if (!strcmp(opt, "csv"))
				fmt = OUTPUT_CSV;
			else
				fmt = OUTPUT_BOTH;
			continue;
		}
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			printf("Usage: %s [-o out_dir] [-i interval_ms] [--format json|csv|both]\n", argv[0]);
			return 0;
		}
	}

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
	printf("Output dir: %s, interval: %dms, format: %s\n",
		out_dir,
		interval_ms,
		fmt == OUTPUT_JSON ? "json" : (fmt == OUTPUT_CSV ? "csv" : "both"));

	if (ensure_dir_exists(out_dir) != 0) {
		err = 1;
		goto cleanup;
	}

	int task_ctx_fd = bpf_map__fd(skel->maps.task_ctx_map);
	if (task_ctx_fd < 0) {
		fprintf(stderr, "Failed to get task_ctx_map fd: %d\n", task_ctx_fd);
		err = 1;
		goto cleanup;
	}

	struct timespec ts;
	long long next_sample_ns = 0;

	while (!exiting) {
		clock_gettime(CLOCK_MONOTONIC, &ts);
		long long now_ns = (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
		if (next_sample_ns == 0)
			next_sample_ns = now_ns;

		if (now_ns >= next_sample_ns) {
			long long ts_sec = (long long)time(NULL);
			char json_path[256];
			char csv_path[256];

			if (fmt == OUTPUT_JSON || fmt == OUTPUT_BOTH) {
				snprintf(json_path, sizeof(json_path), "%s/task_ctx_%lld.json", out_dir, ts_sec);
				dump_task_ctx_json(task_ctx_fd, json_path, ts_sec);
			}
			if (fmt == OUTPUT_CSV || fmt == OUTPUT_BOTH) {
				snprintf(csv_path, sizeof(csv_path), "%s/task_ctx_%lld.csv", out_dir, ts_sec);
				dump_task_ctx_csv(task_ctx_fd, csv_path, ts_sec);
			}
			next_sample_ns = now_ns + (long long)interval_ms * 1000000LL;
		}

		sleep(1);
	}

cleanup:
	sched_bpf__destroy(skel);
	return err != 0;
}
