// SPDX-License-Identifier: GPL-2.0-only
/*
 * sv_main.c - the main part of secretvault: allocate a secret page, hide it from the
 * kernel direct map, and open/close a "window" when I want to use it.
 *
 * Known problem: when the window is open the page is mapped in the shared kernel page
 * tables, so any CPU could read it. My test T07 shows this on purpose.
 */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/ktime.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include "sv.h"

/* type of set_memory_np / set_memory_p: (address, number of pages) -> 0 on success */
typedef int (*sv_cpa_fn)(unsigned long addr, int numpages);

static sv_cpa_fn sv_cpa_np;   /* set_memory_np: clears the present bit (hides the page) */
static sv_cpa_fn sv_cpa_p;    /* set_memory_p: sets the present bit again (un-hides the page) */
static unsigned long (*sv_kallsyms)(const char *name);   /* kallsyms_lookup_name, finds kernel symbols by name */

/* find any kernel symbol by name (I use it for init_mm in sv_pt.c) */
void *sv_sym(const char *name)
{
	return sv_kallsyms ? (void *)sv_kallsyms(name) : NULL;
}

/*
 * set_memory_np and set_memory_p are not always exported to modules, and the kernel
 * stopped exporting kallsyms_lookup_name in 5.7. The trick: put a kprobe on
 * kallsyms_lookup_name, the kprobe's addr field then tells me where the function is.
 * Fine for a VM experiment, a bad idea for real code.
 */
static int sv_resolve_symbols(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };   /* the probe, only used to get the address */
	int ret;                                                         /* return code from register_kprobe */

	ret = register_kprobe(&kp);
	if (ret)
		return ret;
	sv_kallsyms = (void *)kp.addr;
	unregister_kprobe(&kp);

	sv_cpa_np = (sv_cpa_fn)sv_sym("set_memory_np");
	sv_cpa_p  = (sv_cpa_fn)sv_sym("set_memory_p");
	if (!sv_cpa_np || !sv_cpa_p)
		return -ENOENT;
	return 0;
}

/* hide one page: clear the present bit in the direct map (this also splits a 2M entry and flushes the TLB) */
int sv_hide_page(void *va)
{
	if (!va || !sv_cpa_np)
		return -EINVAL;
	return sv_cpa_np((unsigned long)va, 1);
}
EXPORT_SYMBOL_GPL(sv_hide_page);

/* un-hide one page: set the present bit again */
int sv_unhide_page(void *va)
{
	if (!va || !sv_cpa_p)
		return -EINVAL;
	return sv_cpa_p((unsigned long)va, 1);
}
EXPORT_SYMBOL_GPL(sv_unhide_page);

/* make a new secret page. fill() puts the secret in, then the page is hidden */
int sv_alloc(struct sv_secret **out, sv_fill_fn fill, void *ctx)
{
	struct sv_secret *s;   /* the new secret object */
	int ret;               /* result of hiding the page */

	if (!out)
		return -EINVAL;
	*out = NULL;           /* so the caller never gets a half-made pointer if something fails */

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	s->page = alloc_page(GFP_KERNEL | __GFP_ZERO);   /* one zeroed page */
	if (!s->page) {
		kfree(s);
		return -ENOMEM;
	}
	s->dmap = page_address(s->page);
	s->pfn = page_to_pfn(s->page);
	s->len = PAGE_SIZE;
	mutex_init(&s->lock);
	kref_init(&s->ref);                 /* reference count starts at 1 = the owner's reference */

	/* fill the secret in while the page is still mapped, so there is no second copy anywhere */
	if (fill)
		fill(s->dmap, s->len, ctx);

	ret = sv_hide_page(s->dmap);
	if (ret) {
		memzero_explicit(s->dmap, s->len);
		__free_page(s->page);
		mutex_destroy(&s->lock);
		kfree(s);
		return ret;
	}

	*out = s;
	return 0;
}
EXPORT_SYMBOL_GPL(sv_alloc);

/* called when the LAST reference is dropped, so nobody can be using the secret anymore */
static void sv_release(struct kref *ref)
{
	struct sv_secret *s = container_of(ref, struct sv_secret, ref);   /* get the secret from its kref */

	if (sv_unhide_page(s->dmap)) {
		/* can't touch the page safely, so I leak it instead of crashing */
		pr_err("secretvault: cannot unhide pfn 0x%lx on release, leaking page\n", s->pfn);
	} else {
		memzero_explicit(s->dmap, s->len);   /* wipe it (memzero_explicit can't be optimized away) */
		__free_page(s->page);
	}
	mutex_destroy(&s->lock);
	kfree(s);
}

/* take one more reference (use this before sharing the secret with another thread) */
void sv_get(struct sv_secret *s)
{
	if (s)
		kref_get(&s->ref);
}
EXPORT_SYMBOL_GPL(sv_get);

/* drop one reference */
void sv_put(struct sv_secret *s)
{
	if (s)
		kref_put(&s->ref, sv_release);
}
EXPORT_SYMBOL_GPL(sv_put);

/* open the window, run fn() on the secret, close the window */
int sv_access(struct sv_secret *s, sv_access_fn fn, void *ctx)
{
	u64 t0;      /* start time, for the stats */
	int ret;     /* result of un-hiding, then result of fn() */
	int ret2;    /* result of hiding the page again */

	if (!s || !fn)
		return -EINVAL;

	mutex_lock(&s->lock);
	if (s->dead) {                          /* the owner already freed it */
		ret = -ENODEV;
		goto out;
	}
	t0 = ktime_get_ns();

	ret = sv_unhide_page(s->dmap);          /* window opens */
	if (ret)
		goto out;
	s->window_open = true;

	ret = fn(s->dmap, s->len, ctx);         /* the actual work on the secret */

	s->window_open = false;
	ret2 = sv_hide_page(s->dmap);           /* window closes */
	if (ret2) {
		/* the secret is still visible, so make a lot of noise */
		pr_err("secretvault: FAILED to re-hide pfn 0x%lx (%d)\n", s->pfn, ret2);
		WARN_ON_ONCE(1);
		if (!ret)
			ret = ret2;
	}
	s->window_count++;
	s->window_ns_total += ktime_get_ns() - t0;
out:
	mutex_unlock(&s->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(sv_access);

/* owner calls this when done: mark dead, drop the owner's reference */
void sv_free(struct sv_secret *s)
{
	if (!s)
		return;
	mutex_lock(&s->lock);
	if (s->dead) {                          /* already freed once, ignore the second call */
		mutex_unlock(&s->lock);
		return;
	}
	s->dead = true;                         /* from now on sv_access() returns -ENODEV */
	mutex_unlock(&s->lock);
	sv_put(s);
}
EXPORT_SYMBOL_GPL(sv_free);

static int __init sv_init(void)
{
	int ret = sv_resolve_symbols();   /* find set_memory_np/p first, nothing works without them */

	if (ret) {
		pr_err("secretvault: cannot resolve set_memory_np/p (%d)\n", ret);
		return ret;
	}
	ret = sv_debugfs_init();
	if (ret)
		return ret;
	pr_info("secretvault: loaded (see /sys/kernel/debug/secretvault/)\n");
	return 0;
}

static void __exit sv_exit(void)
{
	sv_debugfs_exit();   /* this also frees every secret that is still alive */
	pr_info("secretvault: unloaded\n");
}

module_init(sv_init);
module_exit(sv_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kernel secret vault: direct-map removal + access window (student project)");
