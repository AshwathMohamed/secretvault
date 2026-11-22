// SPDX-License-Identifier: GPL-2.0-only
/*
 * sv_pt.c - page table helpers for checking if my secret page is really hidden.
 *
 * Warning: the scanner walks the page tables without locking, so it can be wrong if the
 * kernel changes them at the same moment. It is only a debug/test tool. It only looks at
 * the kernel half of the kernel page tables (init_mm), because I never map the secret into
 * a user process.
 *
 * x86-64 page table levels, top to bottom: PGD -> P4D -> PUD -> PMD -> PTE
 * (P4D is skipped on 4-level systems). A PUD entry can map 1 GB directly, a PMD entry 2 MB,
 * a PTE entry 4 KB.
 */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/log2.h>
#include <linux/pgtable.h>
#include <asm/pgtable.h>
#include "sv.h"

/* checks the page table entry of one address: is it present and at which level (1=4K, 2=2M, 3=1G) */
int sv_dmap_state(void *va, bool *present_out, unsigned int *level_out)
{
	unsigned int level;   /* level of the entry that lookup_address found */
	pte_t *pte;           /* the entry itself */

	if (!va || !present_out || !level_out)
		return -EINVAL;
	pte = lookup_address((unsigned long)va, &level);
	if (!pte) {
		*present_out = false;
		*level_out = 0;
		return -ENOENT;
	}
	*present_out = pte_present(*pte);
	*level_out = level;
	return 0;
}

/* virtual address where PGD entry number idx starts (kernel addresses have all the top bits set) */
static unsigned long sv_pgd_base(int idx)
{
	unsigned long a = (unsigned long)idx << PGDIR_SHIFT;   /* a = start address of this PGD entry */

	/* fill the top bits with ones so the address is a proper kernel address */
	a |= ~0UL << (PGDIR_SHIFT + ilog2(PTRS_PER_PGD));
	return a;
}

/* write down one mapping that the scanner found */
static void sv_record(struct sv_scan *r, unsigned long va, u8 level, bool present)
{
	if (present)
		r->present++;        /* a usable mapping: this is bad for a hidden page */
	else
		r->residual_np++;    /* leftover non-present entry */
	if (r->nrec < SV_MAX_ALIASES) {   /* only the first few are stored, the counters above count all */
		r->rec[r->nrec].vaddr = va;
		r->rec[r->nrec].level = level;
		r->rec[r->nrec].present = present;
		r->nrec++;
	}
}

/* walk the whole kernel half of the page tables and find every entry that points at page number pfn */
int sv_scan_aliases(unsigned long pfn, struct sv_scan *r)
{
	struct mm_struct *kmm = sv_sym("init_mm");   /* the kernel's own address space (not exported, so looked up by name) */
	int i, j, k, l, m;                            /* loop counters: i=PGD, j=P4D, k=PUD, l=PMD, m=PTE */

	if (!r)
		return -EINVAL;
	memset(r, 0, sizeof(*r));
	if (!kmm)
		return -ENOENT;   /* without init_mm the scan means nothing, so report an error instead of "0 found" */

	/* the upper half of the PGD (entries 256..511) is the kernel */
	for (i = PTRS_PER_PGD / 2; i < PTRS_PER_PGD; i++) {
		unsigned long a0 = sv_pgd_base(i);   /* start address covered by this PGD entry */
		pgd_t *pgd = kmm->pgd + i;           /* the PGD entry */

		if (pgd_none(*pgd) || !pgd_present(*pgd))
			continue;

		for (j = 0; j < PTRS_PER_P4D; j++) {
			unsigned long a1 = a0 + (unsigned long)j * P4D_SIZE;   /* start address of this P4D entry */
			p4d_t *p4d = p4d_offset(pgd, a1);                       /* the P4D entry */

			if (p4d_none(*p4d) || !p4d_present(*p4d))
				continue;

			for (k = 0; k < PTRS_PER_PUD; k++) {
				unsigned long a2 = a1 + (unsigned long)k * PUD_SIZE;   /* start address of this PUD entry */
				pud_t *pud = pud_offset(p4d, a2);                       /* the PUD entry */
				pud_t pude = READ_ONCE(*pud);                           /* a copy, so it can't change while I look at it */

				if (pud_none(pude))
					continue;
				if (pud_leaf(pude)) {                  /* a 1 GB mapping */
					unsigned long s = pud_pfn(pude);   /* first page number this 1 GB entry covers */

					if (pud_present(pude) &&
					    pfn >= s && pfn < s + PTRS_PER_PMD * PTRS_PER_PTE)
						sv_record(r, a2, 3, true);
					continue;
				}
				if (!pud_present(pude))
					continue;

				for (l = 0; l < PTRS_PER_PMD; l++) {
					unsigned long a3 = a2 + (unsigned long)l * PMD_SIZE;   /* start address of this PMD entry */
					pmd_t *pmd = pmd_offset(pud, a3);                       /* the PMD entry */
					pmd_t pmde = READ_ONCE(*pmd);                           /* a copy of it */

					if (pmd_none(pmde))
						continue;
					if (pmd_leaf(pmde)) {                  /* a 2 MB mapping */
						unsigned long s = pmd_pfn(pmde);   /* first page number this 2 MB entry covers */

						if (pmd_present(pmde) &&
						    pfn >= s && pfn < s + PTRS_PER_PTE)
							sv_record(r, a3, 2, true);
						continue;
					}
					if (!pmd_present(pmde))
						continue;

					for (m = 0; m < PTRS_PER_PTE; m++) {
						unsigned long a4 = a3 + (unsigned long)m * PAGE_SIZE;   /* address of this 4 KB page */
						pte_t *pte = pte_offset_kernel(pmd, a4);                 /* the PTE */
						pte_t e = READ_ONCE(*pte);                               /* a copy of it */

						if (pte_none(e))
							continue;
						if (pte_pfn(e) != pfn)   /* not our page */
							continue;
						/* present = usable mapping, not present = the leftover entry */
						sv_record(r, a4, 1, pte_present(e));
					}
				}
				cond_resched();   /* let other tasks run, this walk can take a while */
			}
		}
	}

	return 0;
}
