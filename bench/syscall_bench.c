// SPDX-License-Identifier: GPL-2.0-only
/*
 * syscall_bench.c - calls a very cheap system call many times and prints the average time.
 * KPTI makes every system call slower, so I run this on a pti=on boot and on a pti=off boot
 * and compare the two numbers.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 5000000;   /* how many system calls to make (default 5 million) */
	struct timespec a;   /* time before the loop */
	struct timespec b;   /* time after the loop */

	clock_gettime(CLOCK_MONOTONIC, &a);
	for (long i = 0; i < iters; i++)   /* i = how many calls done so far */
		syscall(SYS_getppid);          /* getppid does almost nothing, so the time is mostly syscall overhead */
	clock_gettime(CLOCK_MONOTONIC, &b);
	double ns = (b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec);   /* total time in nanoseconds */
	printf("iters=%ld  avg_ns_per_syscall=%.1f\n", iters, ns / iters);
	return 0;
}
