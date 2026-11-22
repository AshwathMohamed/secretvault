/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * sv.h - shared header for my secretvault module.
 * Everything the other .c files need to know about is declared here.
 */
#ifndef _SV_H
#define _SV_H

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/mm_types.h>

/* the fake "secret" I fill the page with (same 8 bytes repeated). I search for this in the tests */
#define SV_PATTERN_WORD 0xC0FFEE5EC2E7BEEFULL

/* how many alias entries the scanner will write down at most (it still counts the rest) */
#define SV_MAX_ALIASES  16

/*
 * Rules for using a secret (I learned these the hard way, see docs/CHANGES.md):
 *  - sv_alloc() gives the caller ONE reference. The caller owns it.
 *  - If someone else will also use the secret, they call sv_get() first and sv_put() when done.
 *  - sv_free() is only for the owner and is called once. It marks the secret dead and
 *    drops the owner's reference. The page is really freed when the last reference is gone.
 *  - Only call these from normal process context (they can sleep).
 */
struct sv_secret {
	struct kref ref;        /* reference counter, the secret is freed when this reaches 0 */
	struct page *page;      /* the physical page that holds the secret */
	void *dmap;             /* address of this page in the kernel direct map (only usable while the window is open) */
	unsigned long pfn;      /* page frame number = which physical page it is */
	size_t len;             /* how many bytes the secret uses (one whole page, 4096) */
	bool dead;              /* set by sv_free(), after this sv_access() refuses. Protected by lock */
	bool window_open;       /* true only while the page is un-hidden. Protected by lock */
	struct mutex lock;      /* makes sure only one thread opens the window at a time */
	u64 window_count;       /* how many times the window was opened (for stats) */
	u64 window_ns_total;    /* total nanoseconds spent with the window open (for stats) */
};

/* function that fills the page with the secret. It runs BEFORE the page is hidden. */
typedef void (*sv_fill_fn)(void *page, size_t len, void *ctx);

/* function that works on the secret while the window is open. It must not copy the secret out. */
typedef int (*sv_access_fn)(void *secret, size_t len, void *ctx);

int  sv_alloc(struct sv_secret **out, sv_fill_fn fill, void *ctx);
void sv_get(struct sv_secret *s);
void sv_put(struct sv_secret *s);
void sv_free(struct sv_secret *s);
int  sv_access(struct sv_secret *s, sv_access_fn fn, void *ctx);

/* looks up a kernel function/variable by name (for the ones modules are not allowed to use directly) */
void *sv_sym(const char *name);

/* hide / un-hide one page of the direct map (clear / set its "present" bit) */
int  sv_hide_page(void *va);
int  sv_unhide_page(void *va);

/* ---- page table scanner (sv_pt.c) ---- */

/* one mapping of the page that the scanner found */
struct sv_alias {
	unsigned long vaddr;    /* virtual address of that mapping */
	u8 level;               /* 1 = normal 4K entry, 2 = 2M entry, 3 = 1G entry */
	bool present;           /* true if the entry is really usable, false if it is the leftover non-present one */
};

/* the scanner's result for one physical page */
struct sv_scan {
	int present;            /* how many usable (present) mappings point at the page */
	int residual_np;        /* how many non-present entries still contain the page number (the L1TF problem) */
	int nrec;               /* how many entries are stored in rec[] below */
	struct sv_alias rec[SV_MAX_ALIASES];   /* the first few mappings found */
};

/* looks up the page table entry of one address: is it present, and at which level */
int  sv_dmap_state(void *va, bool *present_out, unsigned int *level_out);

/* walks the kernel page tables looking for every mapping of page number pfn. returns 0 if ok */
int  sv_scan_aliases(unsigned long pfn, struct sv_scan *res);

/* ---- debugfs test interface (sv_debugfs.c) ---- */
int  sv_debugfs_init(void);
void sv_debugfs_exit(void);

#endif /* _SV_H */
