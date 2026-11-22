// SPDX-License-Identifier: GPL-2.0-only
/*
 * sv_debugfs.c - the test interface. I write a command into a file and read the answer
 * from another file:
 *
 *   echo "<command> [a] [b]" > /sys/kernel/debug/secretvault/ctl
 *   cat /sys/kernel/debug/secretvault/result
 *
 * Commands: alloc | free <id> | check <id> | access <id> | hold <id> <ms>
 *           control | stress <threads> <iters> | bench <iters> | list
 */
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/stdarg.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include "sv.h"

#define SV_MAX_SLOTS 16     /* how many secrets can be alive at the same time from the test interface */
#define SV_OUT_SZ    4096   /* size of the text buffer that holds the answer of the last command */

static DEFINE_MUTEX(sv_cmd_lock);                /* only one command runs at a time (also protects slots[] and out[]) */
static struct sv_secret *slots[SV_MAX_SLOTS];    /* the secrets, the "id" in the commands is the index here */
static char out[SV_OUT_SZ];                      /* answer text of the last command, read through "result" */
static size_t outlen;                            /* how many bytes of out[] are used */
static struct dentry *sv_dir;                    /* the /sys/kernel/debug/secretvault directory */

/* printf into out[] (so "cat result" shows it) */
static __printf(1, 2) void emit(const char *fmt, ...)
{
	va_list ap;   /* the "..." arguments */

	if (outlen >= sizeof(out) - 1)   /* buffer full, drop the rest */
		return;
	va_start(ap, fmt);
	outlen += vscnprintf(out + outlen, sizeof(out) - outlen, fmt, ap);
	va_end(ap);
}

/* ---- callbacks that run on the secret ---- */

/* fills the page with the pattern. Runs before the page is hidden. */
static void fill_pattern(void *page, size_t len, void *ctx)
{
	u64 *p = page;   /* the page seen as an array of 8-byte words */
	size_t i;        /* word index */

	for (i = 0; i < len / sizeof(u64); i++)
		p[i] = SV_PATTERN_WORD;
}

/* what verify_cb reports back (only numbers, never the secret bytes) */
struct verify_ctx {
	u64 mismatches;   /* how many words are NOT the pattern (should be 0) */
	u64 xor;          /* xor of all words, a tiny checksum */
};

/* checks that the secret is still intact while the window is open */
static int verify_cb(void *secret, size_t len, void *c)
{
	struct verify_ctx *v = c;   /* where to put the result */
	u64 *p = secret;            /* the page as 8-byte words */
	size_t i;                   /* word index */

	v->mismatches = 0;
	v->xor = 0;
	for (i = 0; i < len / sizeof(u64); i++) {
		v->xor ^= p[i];
		if (p[i] != SV_PATTERN_WORD)
			v->mismatches++;
	}
	return 0;   /* only the numbers leave the window, never the bytes */
}

/* keeps the window open for a while: c points to the milliseconds to wait */
static int hold_cb(void *secret, size_t len, void *c)
{
	msleep(*(unsigned long *)c);
	return 0;
}

/* does nothing, I use it to measure how much opening+closing the window costs */
static int noop_cb(void *secret, size_t len, void *c)
{
	return 0;
}

/* ---- commands ---- */

/* find the secret with this id, or write an error */
static struct sv_secret *get_slot(unsigned long id)
{
	if (id >= SV_MAX_SLOTS || !slots[id]) {
		emit("ERROR: no secret with id %lu\n", id);
		return NULL;
	}
	return slots[id];
}

/* "alloc": make a new secret in the first free slot */
static int cmd_alloc(void)
{
	int id;    /* index of the free slot */
	int ret;   /* result of sv_alloc */

	for (id = 0; id < SV_MAX_SLOTS; id++)
		if (!slots[id])
			break;
	if (id == SV_MAX_SLOTS) {
		emit("ERROR: no free slot\n");
		return -ENOSPC;
	}
	ret = sv_alloc(&slots[id], fill_pattern, NULL);
	if (ret) {
		emit("ERROR: sv_alloc failed (%d)\n", ret);
		return ret;
	}
	emit("alloc ok id=%d pfn=0x%lx dmap=%px\n", id, slots[id]->pfn, slots[id]->dmap);
	return 0;
}

/* "free <id>" */
static int cmd_free(unsigned long id)
{
	struct sv_secret *s = get_slot(id);   /* the secret to free */

	if (!s)
		return -ENOENT;
	sv_free(s);
	slots[id] = NULL;
	emit("free ok id=%lu\n", id);
	return 0;
}

/* print what the scanner found (used by check and control) */
static void report_scan(unsigned long pfn, struct sv_scan *r)
{
	int i;   /* index into r->rec */

	emit("alias_present=%d alias_residual_np=%d\n", r->present, r->residual_np);
	for (i = 0; i < r->nrec; i++)
		emit("  alias[%d] va=%px level=%u present=%d\n", i,
		     (void *)r->rec[i].vaddr, r->rec[i].level, r->rec[i].present);
}

/* "check <id>": is the secret really hidden? */
static int cmd_check(unsigned long id)
{
	struct sv_secret *s = get_slot(id);   /* the secret to check */
	struct sv_scan *r;                    /* scanner result (allocated, it is too big for the stack) */
	bool present;                         /* is the direct map entry present? */
	unsigned int level;                   /* page table level of that entry */
	u64 probe;                            /* a place to try reading 8 bytes into */
	int readable;                         /* 1 if reading the page worked (bad), 0 if it faulted (good) */
	int rc;                               /* result of sv_dmap_state */
	int scan_rc;                          /* result of the scanner */

	if (!s)
		return -ENOENT;
	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	mutex_lock(&s->lock);   /* so nobody opens the window while I check */
	rc = sv_dmap_state(s->dmap, &present, &level);
	readable = !copy_from_kernel_nofault(&probe, s->dmap, sizeof(probe));   /* safe read, fails instead of crashing */
	scan_rc = sv_scan_aliases(s->pfn, r);
	mutex_unlock(&s->lock);
	if (scan_rc) {
		emit("ERROR: alias scan unusable (%d); refusing to report PASS\n", scan_rc);
		kfree(r);
		return scan_rc;
	}

	emit("id=%lu pfn=0x%lx dmap=%px\n", id, s->pfn, s->dmap);
	emit("dmap_lookup_rc=%d dmap_pte_present=%d level=%u nofault_read_ok=%d\n",
	     rc, present, level, readable);
	report_scan(s->pfn, r);
	/* two different findings, so I print them on separate lines */
	emit("PRESENT_ALIAS_CHECK: %s (no present mapping, not readable; the Meltdown-US-style property)\n",
	     (!present && !readable && !r->present) ? "PASS" : "FAIL");
	emit("RESIDUAL_NP_INFO: %d non-present PTE(s) still hold this pfn (expected >=1 in this design; "
	     "L1TF-class exposure, NOT covered)\n", r->residual_np);
	kfree(r);
	return 0;
}

/* "access <id>": open the window, check the secret is intact, close it */
static int cmd_access(unsigned long id)
{
	struct sv_secret *s = get_slot(id);   /* the secret to use */
	struct verify_ctx v = {};             /* result of the check */
	int ret;                              /* result of sv_access */

	if (!s)
		return -ENOENT;
	ret = sv_access(s, verify_cb, &v);
	emit("access rc=%d mismatches=%llu xor=0x%llx RESULT: %s\n", ret, v.mismatches, v.xor,
	     (!ret && !v.mismatches) ? "PASS secret-intact" : "FAIL");
	return ret;
}

/* "hold <id> <ms>": keep the window open for ms milliseconds so I can probe /proc/kcore from another shell */
static int cmd_hold(unsigned long id, unsigned long ms)
{
	struct sv_secret *s = get_slot(id);   /* the secret to hold open */
	int ret;                              /* result of sv_access */

	if (!s)
		return -ENOENT;
	if (ms > 60000)
		ms = 60000;   /* max one minute */
	emit("hold: window opening for %lu ms (probe from another shell now)\n", ms);
	ret = sv_access(s, hold_cb, &ms);
	emit("hold done rc=%d\n", ret);
	return ret;
}

/* "control": test the scanner on a NORMAL page. It should find the page's mapping, otherwise "0 found" for the secret means nothing */
static int cmd_control(void)
{
	struct page *pg = alloc_page(GFP_KERNEL | __GFP_ZERO);   /* an ordinary, not hidden, page */
	struct sv_scan *r;                                       /* scanner result */
	bool present;                                            /* is its direct map entry present? */
	unsigned int level;                                      /* page table level of that entry */
	u64 probe;                                               /* place to try reading 8 bytes into */
	int readable;                                            /* 1 if the read worked (it should for a normal page) */
	int rc;                                                  /* result of sv_dmap_state */

	if (!pg)
		return -ENOMEM;
	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r) {
		__free_page(pg);
		return -ENOMEM;
	}
	rc = sv_dmap_state(page_address(pg), &present, &level);
	readable = !copy_from_kernel_nofault(&probe, page_address(pg), sizeof(probe));
	if (sv_scan_aliases(page_to_pfn(pg), r)) {
		emit("ERROR: alias scan unusable\n");
		kfree(r);
		__free_page(pg);
		return -ENOENT;
	}
	emit("control(normal page) pfn=0x%lx dmap_lookup_rc=%d present=%d level=%u readable=%d\n",
	     page_to_pfn(pg), rc, present, level, readable);
	report_scan(page_to_pfn(pg), r);
	emit("RESULT: %s\n", (present && readable && r->present >= 1) ?
	     "PASS scanner-sees-normal-alias" : "FAIL scanner-broken");
	kfree(r);
	__free_page(pg);
	return 0;
}

/* ---- stress test: many threads use the secret while the owner frees it ---- */

/* shared between the main command and the worker threads */
struct stress_ctx {
	struct sv_secret *s;   /* the secret everyone fights over */
	unsigned long iters;   /* how many accesses each thread tries */
	atomic_t ok;           /* accesses that worked */
	atomic_t gone;         /* accesses refused because the secret was already freed (-ENODEV, this is fine) */
	atomic_t err;          /* any other error (this would be a real problem) */
};

/* one worker thread */
static int stress_thread(void *arg)
{
	struct stress_ctx *c = arg;   /* the shared data */
	unsigned long i;              /* how many accesses done so far */

	for (i = 0; i < c->iters; i++) {
		int r = sv_access(c->s, noop_cb, NULL);   /* result of one access */

		if (!r)
			atomic_inc(&c->ok);
		else if (r == -ENODEV)
			atomic_inc(&c->gone);      /* it was freed while I was using it: the correct, safe outcome */
		else
			atomic_inc(&c->err);
		cond_resched();
	}
	sv_put(c->s);                          /* give back the reference this thread was holding */
	return 0;
}

#define SV_MAX_THREADS 8   /* max worker threads for the stress test */

/* "stress <threads> <iters>" */
static int cmd_stress(unsigned long nthreads, unsigned long iters)
{
	struct task_struct *t[SV_MAX_THREADS] = {};   /* the worker threads */
	struct stress_ctx c = {};                     /* shared data */
	unsigned long i;                              /* loop counter */
	unsigned long started = 0;                    /* how many threads were really created */
	int ret;                                      /* result of sv_alloc */

	if (!nthreads || nthreads > SV_MAX_THREADS)
		nthreads = 4;
	if (!iters || iters > 200000)
		iters = 2000;
	c.iters = iters;

	ret = sv_alloc(&c.s, fill_pattern, NULL);
	if (ret) {
		emit("ERROR: sv_alloc failed (%d)\n", ret);
		return ret;
	}
	for (i = 0; i < nthreads; i++) {
		sv_get(c.s);                       /* each worker gets its own reference */
		t[i] = kthread_create(stress_thread, &c, "sv_stress/%lu", i);
		if (IS_ERR(t[i])) {
			t[i] = NULL;
			sv_put(c.s);
			continue;
		}
		get_task_struct(t[i]);             /* so kthread_stop() below is safe even if the thread already ended */
		started++;
	}
	for (i = 0; i < nthreads; i++)
		if (t[i])
			wake_up_process(t[i]);

	usleep_range(1000, 2000);              /* let the workers start */
	sv_free(c.s);                          /* the owner frees while the workers are still running */

	for (i = 0; i < nthreads; i++) {
		if (t[i]) {
			kthread_stop(t[i]);        /* waits until the worker is completely finished */
			put_task_struct(t[i]);
		}
	}
	emit("stress threads=%lu iters=%lu ok=%d freed_under_us=%d errors=%d\n", started, iters,
	     atomic_read(&c.ok), atomic_read(&c.gone), atomic_read(&c.err));
	emit("RESULT: %s\n", (started && !atomic_read(&c.err)) ? "PASS no-uaf-no-errors" : "FAIL");
	return 0;
}

/* "bench <iters>": how long do alloc/free and opening the window take? */
static int cmd_bench(unsigned long iters)
{
	struct sv_secret *s;   /* a secret for the tests */
	struct page *pg;       /* a normal page for the baseline */
	u64 t0;                /* start time of the current measurement */
	u64 t_base;            /* total time for normal alloc+free */
	u64 t_vault;           /* total time for secret alloc+free */
	u64 t_win;             /* total time for opening+closing the window */
	unsigned long i;       /* loop counter */
	int ret;               /* result of sv_alloc */

	if (!iters || iters > 100000)
		iters = 1000;

	/* baseline: a normal page */
	t0 = ktime_get_ns();
	for (i = 0; i < iters; i++) {
		pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!pg)
			return -ENOMEM;
		__free_page(pg);
	}
	t_base = ktime_get_ns() - t0;

	/* a secret page: alloc (with hiding) + free */
	t0 = ktime_get_ns();
	for (i = 0; i < iters; i++) {
		ret = sv_alloc(&s, fill_pattern, NULL);
		if (ret)
			return ret;
		sv_free(s);
	}
	t_vault = ktime_get_ns() - t0;

	/* just opening and closing the window on one secret */
	ret = sv_alloc(&s, fill_pattern, NULL);
	if (ret)
		return ret;
	t0 = ktime_get_ns();
	for (i = 0; i < iters; i++)
		sv_access(s, noop_cb, NULL);
	t_win = ktime_get_ns() - t0;
	sv_free(s);

	emit("bench iters=%lu\n", iters);
	emit("baseline_alloc_free_ns_avg=%llu\n", t_base / iters);
	emit("vault_alloc_free_ns_avg=%llu\n", t_vault / iters);
	emit("window_open_close_ns_avg=%llu\n", t_win / iters);
	return 0;
}

/* "list": show all live secrets */
static int cmd_list(void)
{
	int i;       /* slot index */
	int n = 0;   /* how many secrets are alive */

	for (i = 0; i < SV_MAX_SLOTS; i++) {
		if (!slots[i])
			continue;
		emit("id=%d pfn=0x%lx windows=%llu avg_window_ns=%llu\n", i, slots[i]->pfn,
		     slots[i]->window_count,
		     slots[i]->window_count ? slots[i]->window_ns_total / slots[i]->window_count : 0);
		n++;
	}
	emit("secrets=%d\n", n);
	return 0;
}

/* called when I write to the "ctl" file: parse the command and run it */
static ssize_t ctl_write(struct file *f, const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	char buf[64];             /* copy of what was written */
	char cmd[16];             /* the command word, e.g. "alloc" */
	unsigned long a = 0;      /* first number after the command (usually the id) */
	unsigned long b = 0;      /* second number after the command */
	int n;                    /* how many words sscanf found */
	int ret = -EINVAL;        /* result of the command */

	if (!cnt || cnt >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, cnt))
		return -EFAULT;
	buf[cnt] = 0;
	n = sscanf(buf, "%15s %lu %lu", cmd, &a, &b);
	if (n < 1)
		return -EINVAL;

	mutex_lock(&sv_cmd_lock);
	outlen = 0;     /* start a fresh answer */
	out[0] = 0;
	if (!strcmp(cmd, "alloc"))
		ret = cmd_alloc();
	else if (!strcmp(cmd, "free") && n >= 2)
		ret = cmd_free(a);
	else if (!strcmp(cmd, "check") && n >= 2)
		ret = cmd_check(a);
	else if (!strcmp(cmd, "access") && n >= 2)
		ret = cmd_access(a);
	else if (!strcmp(cmd, "hold") && n >= 3)
		ret = cmd_hold(a, b);
	else if (!strcmp(cmd, "control"))
		ret = cmd_control();
	else if (!strcmp(cmd, "stress"))
		ret = cmd_stress(n >= 2 ? a : 4, n >= 3 ? b : 2000);
	else if (!strcmp(cmd, "bench"))
		ret = cmd_bench(n >= 2 ? a : 1000);
	else if (!strcmp(cmd, "list"))
		ret = cmd_list();
	else
		emit("ERROR: unknown or malformed command\n");
	mutex_unlock(&sv_cmd_lock);

	return ret ? ret : cnt;
}

/* called when I read the "result" file: give back the answer of the last command */
static ssize_t result_read(struct file *f, char __user *ubuf, size_t cnt, loff_t *ppos)
{
	ssize_t r;   /* number of bytes copied to the user */

	mutex_lock(&sv_cmd_lock);
	r = simple_read_from_buffer(ubuf, cnt, ppos, out, outlen);
	mutex_unlock(&sv_cmd_lock);
	return r;
}

/* what the two files do */
static const struct file_operations ctl_fops = {
	.owner = THIS_MODULE, .write = ctl_write, .llseek = noop_llseek,
};
static const struct file_operations result_fops = {
	.owner = THIS_MODULE, .read = result_read, .llseek = default_llseek,
};

/* create the debugfs directory and the two files (root only) */
int sv_debugfs_init(void)
{
	sv_dir = debugfs_create_dir("secretvault", NULL);
	if (IS_ERR_OR_NULL(sv_dir))
		return -ENOMEM;
	debugfs_create_file("ctl", 0200, sv_dir, NULL, &ctl_fops);       /* write-only */
	debugfs_create_file("result", 0400, sv_dir, NULL, &result_fops); /* read-only */
	return 0;
}

/* remove the files and free every secret that is still alive */
void sv_debugfs_exit(void)
{
	int i;   /* slot index */

	debugfs_remove_recursive(sv_dir);
	mutex_lock(&sv_cmd_lock);
	for (i = 0; i < SV_MAX_SLOTS; i++) {
		if (slots[i]) {
			sv_free(slots[i]);
			slots[i] = NULL;
		}
	}
	mutex_unlock(&sv_cmd_lock);
}
