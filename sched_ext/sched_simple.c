#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "sched_simple.skel.h"

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int sig)
{
	(void)sig;
	exiting = 1;
}

int main(void)
{
	struct sched_simple_bpf *skel = NULL;
	int err = 0;

	signal(SIGINT, handle_signal);
	signal(SIGTERM, handle_signal);

	skel = sched_simple_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open and load BPF skeleton\n");
		return 1;
	}

	err = sched_simple_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF program: %d\n", err);
		sched_simple_bpf__destroy(skel);
		return 1;
	}

	printf("simple_scx loaded. Press Ctrl+C to exit.\n");
	while (!exiting) {
		sleep(1);
	}

	sched_simple_bpf__destroy(skel);
	return 0;
}
