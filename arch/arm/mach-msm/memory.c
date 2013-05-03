/* arch/arm/mach-msm/memory.c
 *
 * Copyright (C) 2007 Google, Inc.
 * Copyright (c) 2009-2011, Code Aurora Forum. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/bootmem.h>
#include <linux/module.h>
#include <linux/memory_alloc.h>
#include <linux/memblock.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/mach/map.h>
#include <asm/cacheflush.h>
#include <asm/setup.h>
#include <asm/mach-types.h>
#include <mach/msm_memtypes.h>
#include <linux/hardirq.h>
#if defined(CONFIG_MSM_NPA_REMOTE)
#include "npa_remote.h"
#include <linux/completion.h>
#include <linux/err.h>
#endif
#include <linux/android_pmem.h>
#include <mach/msm_iomap.h>
#include <mach/socinfo.h>
#include <../../mm/mm.h>

#if defined(CONFIG_ARCH_MSM7X30)
unsigned int ebi0_size = 0x20000000;
EXPORT_SYMBOL(ebi0_size);
#endif

void *strongly_ordered_page;
char strongly_ordered_mem[PAGE_SIZE*2-4];

void map_page_strongly_ordered(void)
{
#if defined(CONFIG_ARCH_MSM7X27) && !defined(CONFIG_ARCH_MSM7X27A)
	long unsigned int phys;
	struct map_desc map;

	if (strongly_ordered_page)
		return;

	strongly_ordered_page = (void*)PFN_ALIGN((int)&strongly_ordered_mem);
	phys = __pa(strongly_ordered_page);

	map.pfn = __phys_to_pfn(phys);
	map.virtual = MSM_STRONGLY_ORDERED_PAGE;
	map.length = PAGE_SIZE;
	map.type = MT_DEVICE_STRONGLY_ORDERED;
	create_mapping(&map);

	printk(KERN_ALERT "[K] Initialized strongly ordered page successfully\n");
#endif
}
EXPORT_SYMBOL(map_page_strongly_ordered);

void write_to_strongly_ordered_memory(void)
{
#if defined(CONFIG_ARCH_MSM7X27) && !defined(CONFIG_ARCH_MSM7X27A)
	if (!strongly_ordered_page) {
		if (!in_interrupt())
			map_page_strongly_ordered();
		else {
			printk(KERN_ALERT "[K] Cannot map strongly ordered page in "
				"Interrupt Context\n");
			/* capture it here before the allocation fails later */
			BUG();
		}
	}
	*(int *)MSM_STRONGLY_ORDERED_PAGE = 0;
#endif
}
EXPORT_SYMBOL(write_to_strongly_ordered_memory);

/* These cache related routines make the assumption (if outer cache is
 * available) that the associated physical memory is contiguous.
 * They will operate on all (L1 and L2 if present) caches.
 */
void clean_and_invalidate_caches(unsigned long vstart,
	unsigned long length, unsigned long pstart)
{
	dmac_flush_range((void *)vstart, (void *) (vstart + length));
	outer_flush_range(pstart, pstart + length);
}

void clean_caches(unsigned long vstart,
	unsigned long length, unsigned long pstart)
{
	dmac_clean_range((void *)vstart, (void *) (vstart + length));
	outer_clean_range(pstart, pstart + length);
}

void invalidate_caches(unsigned long vstart,
	unsigned long length, unsigned long pstart)
{
	dmac_inv_range((void *)vstart, (void *) (vstart + length));
	outer_inv_range(pstart, pstart + length);
}

char *memtype_name[] = {
	"SMI_KERNEL",
	"SMI",
	"EBI0",
	"EBI1"
};

struct reserve_info *reserve_info;

/**
 * calculate_reserve_limits() - calculate reserve limits for all
 * memtypes
 *
 * for each memtype in the reserve_info->memtype_reserve_table, sets
 * the `limit' field to the largest size of any memblock of that
 * memtype.
 */
static void __init calculate_reserve_limits(void)
{
	struct memblock_region *mr;
	int memtype;
	struct memtype_reserve *mt;

	for_each_memblock(memory, mr) {
		memtype = reserve_info->paddr_to_memtype(mr->base);
		if (memtype == MEMTYPE_NONE) {
			pr_warning("unknown memory type for region at %lx\n",
				(long unsigned int)mr->base);
			continue;
		}
		mt = &reserve_info->memtype_reserve_table[memtype];
		mt->limit = max_t(unsigned long, mt->limit, mr->size);
	}
}

static void __init adjust_reserve_sizes(void)
{
	int i;
	struct memtype_reserve *mt;

	mt = &reserve_info->memtype_reserve_table[0];
	for (i = 0; i < MEMTYPE_MAX; i++, mt++) {
		if (mt->flags & MEMTYPE_FLAGS_1M_ALIGN)
			mt->size = (mt->size + SECTION_SIZE - 1) & SECTION_MASK;
		if (mt->size > mt->limit) {
			pr_warning("%pa size for %s too large, setting to %pa\n",
				&mt->size, memtype_name[i], &mt->limit);
			mt->size = mt->limit;
		}
	}
}

static void __init reserve_memory_for_mempools(void)
{
	int memtype, memreg_type;
	struct memtype_reserve *mt;
	struct memblock_region *mr, *mr_candidate = NULL;
	int ret;

	mt = &reserve_info->memtype_reserve_table[0];
	for (memtype = 0; memtype < MEMTYPE_MAX; memtype++, mt++) {
		if (mt->flags & MEMTYPE_FLAGS_FIXED || !mt->size)
			continue;

		/* Choose the memory block with the highest physical
		 * address which is large enough, so that we will not
		 * take memory from the lowest memory bank which the kernel
		 * is in (and cause boot problems) and so that we might
		 * be able to steal memory that would otherwise become
		 * highmem.
		 */
		for_each_memblock(memory, mr) {
			memreg_type =
				reserve_info->paddr_to_memtype(mr->base);
			if (memtype != memreg_type)
				continue;
			if (mr->size >= mt->size
				&& (mr_candidate == NULL
					|| mr->base > mr_candidate->base))
				mr_candidate = mr;
		}
		BUG_ON(mr_candidate == NULL);
		/* bump mt up against the top of the region */
		mt->start = mr_candidate->base + mr_candidate->size - mt->size;
		ret = memblock_reserve(mt->start, mt->size);
		BUG_ON(ret);
		ret = memblock_free(mt->start, mt->size);
		BUG_ON(ret);
		ret = memblock_remove(mt->start, mt->size);
		BUG_ON(ret);
	}
}

static void __init initialize_mempools(void)
{
	struct mem_pool *mpool;
	int memtype;
	struct memtype_reserve *mt;

	mt = &reserve_info->memtype_reserve_table[0];
	for (memtype = 0; memtype < MEMTYPE_MAX; memtype++, mt++) {
		if (!mt->size)
			continue;
		mpool = initialize_memory_pool(mt->start, mt->size, memtype);
		if (!mpool)
			pr_warning("failed to create %s mempool\n",
				memtype_name[memtype]);
	}
}

#define  MAX_FIXED_AREA_SIZE 0x11000000

void __init msm_reserve(void)
{
	unsigned long msm_fixed_area_size;
	unsigned long msm_fixed_area_start;

	memory_pool_init();
	if (reserve_info->calculate_reserve_sizes)
		reserve_info->calculate_reserve_sizes();

	msm_fixed_area_size = reserve_info->fixed_area_size;
	msm_fixed_area_start = reserve_info->fixed_area_start;
	if (msm_fixed_area_size)
		if (msm_fixed_area_start > reserve_info->low_unstable_address
			- MAX_FIXED_AREA_SIZE)
			reserve_info->low_unstable_address =
			msm_fixed_area_start;

	calculate_reserve_limits();
	adjust_reserve_sizes();
	reserve_memory_for_mempools();
	initialize_mempools();
}

static int get_ebi_memtype(void)
{
	/* on 7x30 and 8x55 "EBI1 kernel PMEM" is really on EBI0 */
	if (cpu_is_msm7x30() || cpu_is_msm8x55())
		return MEMTYPE_EBI0;
	return MEMTYPE_EBI1;
}

void *allocate_contiguous_ebi(unsigned long size,
	unsigned long align, int cached)
{
	return allocate_contiguous_memory(size, get_ebi_memtype(),
		align, cached);
}
EXPORT_SYMBOL(allocate_contiguous_ebi);

phys_addr_t allocate_contiguous_ebi_nomap(unsigned long size,
	unsigned long align)
{
	return _allocate_contiguous_memory_nomap(size, get_ebi_memtype(),
		align, __builtin_return_address(0));
}
EXPORT_SYMBOL(allocate_contiguous_ebi_nomap);

/* emulation of the deprecated pmem_kalloc and pmem_kfree */
int32_t pmem_kalloc(const size_t size, const uint32_t flags)
{
	int pmem_memtype;
	int memtype = MEMTYPE_NONE;
	int ebi1_memtype = MEMTYPE_EBI1;
	unsigned int align;
	int32_t paddr;

	switch (flags & PMEM_ALIGNMENT_MASK) {
	case PMEM_ALIGNMENT_4K:
		align = SZ_4K;
		break;
	case PMEM_ALIGNMENT_1M:
		align = SZ_1M;
		break;
	default:
		pr_alert("Invalid alignment %x\n",
			(flags & PMEM_ALIGNMENT_MASK));
		return -EINVAL;
	}

	/* on 7x30 and 8x55 "EBI1 kernel PMEM" is really on EBI0 */
	if (cpu_is_msm7x30() || cpu_is_msm8x55())
			ebi1_memtype = MEMTYPE_EBI0;

	pmem_memtype = flags & PMEM_MEMTYPE_MASK;
	if (pmem_memtype == PMEM_MEMTYPE_EBI1)
		memtype = ebi1_memtype;
	else if (pmem_memtype == PMEM_MEMTYPE_SMI)
		memtype = MEMTYPE_SMI_KERNEL;
	else {
		pr_alert("Invalid memory type %x\n",
			flags & PMEM_MEMTYPE_MASK);
		return -EINVAL;
	}

	paddr = _allocate_contiguous_memory_nomap(size, memtype, align,
		__builtin_return_address(0));

	if (!paddr && pmem_memtype == PMEM_MEMTYPE_SMI)
		paddr = _allocate_contiguous_memory_nomap(size,
			ebi1_memtype, align, __builtin_return_address(0));

	if (!paddr)
		return -ENOMEM;
	return paddr;
}
EXPORT_SYMBOL(pmem_kalloc);

int pmem_kfree(const int32_t physaddr)
{
	free_contiguous_memory_by_paddr(physaddr);

	return 0;
}
EXPORT_SYMBOL(pmem_kfree);

unsigned int msm_ttbr0;

void store_ttbr0(void)
{
	/* Store TTBR0 for post-mortem debugging purposes. */
	asm("mrc p15, 0, %0, c2, c0, 0\n"
		: "=r" (msm_ttbr0));
}
