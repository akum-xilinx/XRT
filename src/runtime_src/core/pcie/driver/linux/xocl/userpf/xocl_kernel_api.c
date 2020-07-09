/*
 * A GEM style device manager for PCIe based OpenCL accelerators.
 *
 * Copyright (C) 2016-2019 Xilinx, Inc. All rights reserved.
 *
 * Authors:
 *    Amit Kumar <akum@xilinx.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/bitops.h>
#include <linux/swap.h>
#include <linux/dma-buf.h>
#include <linux/pagemap.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 0, 0)
#include <drm/drm_backport.h>
#endif
#include <drm/drmP.h>
#include "common.h"
#include "../xocl_drv.h"
#include "xocl_kernel_api.h"

//TO-DO: Remove these
#define	INVALID_BO_PADDR	0xffffffffffffffffull
#ifdef _XOCL_BO_DEBUG
#define BO_ENTER(fmt, args...)          \
        printk(KERN_INFO "[BO] Entering %s:"fmt"\n", __func__, ##args)
#define BO_DEBUG(fmt, args...)          \
        printk(KERN_INFO "[BO] %s:%d:"fmt"\n", __func__, __LINE__, ##args)
#else
#define BO_ENTER(fmt, args...)
#define BO_DEBUG(fmt, args...)
#endif

extern void xocl_describe(const struct drm_xocl_bo *xobj);

#if defined(XOCL_DRM_FREE_MALLOC)
static inline void drm_free_large(void *ptr)
{
        kvfree(ptr);
}

static inline void *drm_malloc_ab(size_t nmemb, size_t size)
{
        return kvmalloc_array(nmemb, size, GFP_KERNEL);
}
#endif

static size_t xocl_bo_physical_addr(const struct drm_xocl_bo *xobj)
{
	uint64_t paddr;

	paddr = xobj->mm_node ? xobj->mm_node->start : INVALID_BO_PADDR;
	return paddr;
}

static struct sg_table *alloc_onetime_sg_table(struct page **pages, uint64_t offset, uint64_t size)
{
        int ret;
        unsigned int nr_pages;
        struct sg_table *sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);

        if (!sgt)
                return ERR_PTR(-ENOMEM);

        pages += (offset >> PAGE_SHIFT);
        offset &= (~PAGE_MASK);
        nr_pages = PAGE_ALIGN(size + offset) >> PAGE_SHIFT;

        ret = sg_alloc_table_from_pages(sgt, pages, nr_pages, offset, size, GFP_KERNEL);
        if (ret)
                goto cleanup;

        return sgt;

cleanup:
        kfree(sgt);
        return ERR_PTR(-ENOMEM);
}

struct list_head gem_obj_list;
LIST_HEAD(gem_obj_list);
static DEFINE_SPINLOCK(gem_obj_list_lock);

struct kernel_gem_obj_node{
	struct list_head list;
	struct drm_gem_object *obj;
};

struct xocl_drm_dev_info uapp_drm_context;

static int xocl_gem_obj_to_kernel_list(struct drm_gem_object *gem_obj)
{
	struct kernel_gem_obj_node *gem_node = (struct kernel_gem_obj_node *) 
			kzalloc	(sizeof(struct kernel_gem_obj_node),GFP_KERNEL);
	if(!gem_node)
		return -ENOMEM;

	gem_node->obj = gem_obj;

	spin_lock(&gem_obj_list_lock);
	list_add_tail(&gem_node->list, &gem_obj_list);
	spin_unlock(&gem_obj_list_lock);

	return 0;
}

int xocl_create_bo_ifc(struct drm_xocl_create_bo *args)
{
	int ret;
        struct drm_gem_object *gem_obj;

	if (!atomic_read(&uapp_drm_context.active)) {
		return -EFAULT;
	}
	ret = xocl_create_bo_ioctl(uapp_drm_context.dev, args, 
							uapp_drm_context.file);
	if (ret)
		return ret;

	gem_obj = xocl_gem_object_lookup(uapp_drm_context.dev, 
					uapp_drm_context.file,
                                        args->handle);
	ret = xocl_gem_obj_to_kernel_list(gem_obj);
	return ret;
}

EXPORT_SYMBOL_GPL(xocl_create_bo_ifc);

int xocl_map_bo_ifc(struct drm_xocl_map_bo *args)
{
	int ret;

	if (!atomic_read(&uapp_drm_context.active)) {
		return -EFAULT;
	}
	ret = xocl_map_bo_ioctl(uapp_drm_context.dev, args, 
							uapp_drm_context.file);
	return ret;
}
EXPORT_SYMBOL_GPL(xocl_map_bo_ifc);

int xocl_sync_bo_ifc(struct drm_xocl_sync_bo *args)
{
	int ret;

	if (!atomic_read(&uapp_drm_context.active)) {
		return -EFAULT;
	}
	ret = xocl_sync_bo_ioctl(uapp_drm_context.dev, args, 
							uapp_drm_context.file);
	return ret;
}
EXPORT_SYMBOL_GPL(xocl_sync_bo_ifc);

int xocl_info_bo_ifc(struct drm_xocl_info_bo *args)
{
	int ret;

	if (!atomic_read(&uapp_drm_context.active)) {
		return -EFAULT;
	}
	ret = xocl_info_bo_ioctl(uapp_drm_context.dev, args, 
							uapp_drm_context.file);
	return ret;
}
EXPORT_SYMBOL_GPL(xocl_info_bo_ifc);

int xocl_execbuf_ifc(struct drm_xocl_execbuf *args)
{
	int ret;

	if (!atomic_read(&uapp_drm_context.active)) {
		return -EFAULT;
	}
	ret = xocl_execbuf_ioctl(uapp_drm_context.dev, args, 
							uapp_drm_context.file);
	return ret;
}
EXPORT_SYMBOL_GPL(xocl_execbuf_ifc);

int xocl_create_kmem_bo_ifc(struct drm_xocl_kptr_bo *args)
{
	int ret, i;
	struct drm_xocl_bo *xobj;
	struct xocl_drm *drm_p = uapp_drm_context.dev->dev_private;
	uint64_t page_count = 0;

	if (!atomic_read(&uapp_drm_context.active)) {
		return -EFAULT;
	}

	if (offset_in_page(args->addr))
		return -EINVAL;

	xobj = xocl_drm_create_bo(drm_p, args->size, 
					(args->flags | XCL_BO_FLAGS_KERNPTR));
	BO_ENTER("xobj %p", xobj);

	if (IS_ERR(xobj)) {
		DRM_ERROR("object creation failed\n");
		return PTR_ERR(xobj);
	}

	/* Use the page rounded size to accurately account for num of pages */
	page_count = xobj->base.size >> PAGE_SHIFT;

	xobj->pages = drm_malloc_ab(page_count, sizeof(*xobj->pages));
	if (!xobj->pages) {
		ret = -ENOMEM;
		goto out1;
	}

	for (i=0; i<page_count; i++)
	{
		xobj->pages[i] = virt_to_page(args->addr+i*PAGE_SIZE);
	}

	xobj->sgt = drm_prime_pages_to_sg(xobj->pages, page_count);
	if (IS_ERR(xobj->sgt)) {
		ret = PTR_ERR(xobj->sgt);
		goto out0;
	}

	ret = drm_gem_handle_create(uapp_drm_context.file, &xobj->base, 
								&args->handle);
	if (ret)
		goto out1;

	xocl_describe(xobj);
	ret = xocl_gem_obj_to_kernel_list(&xobj->base);

	return ret;

out0:
	drm_free_large(xobj->pages);
	xobj->pages = NULL;
out1:
	xocl_drm_free_bo(&xobj->base);
	DRM_DEBUG("handle creation failed\n");
	return ret;
}
EXPORT_SYMBOL_GPL(xocl_create_kmem_bo_ifc);

int xocl_remap_kmem_bo_ifc(struct drm_xocl_kptr_bo *args)
{
	int i;
        int ret;
        unsigned int page_count;

        struct drm_xocl_bo *xobj;
        struct drm_gem_object *gem_obj;

	if (!atomic_read(&uapp_drm_context.active)) {
		return -EFAULT;
	}
	gem_obj = xocl_gem_object_lookup(uapp_drm_context.dev, 
					uapp_drm_context.file,
                                        args->handle);

        if (!gem_obj) {
                DRM_ERROR("Failed to look up GEM BO %d\n", args->handle);
                return -ENOENT;
        }

	xobj = to_xocl_bo(gem_obj);

        if (xobj->pages) {
                drm_free_large(xobj->pages);
                xobj->pages = NULL;
        }

        if (xobj->sgt) {
                sg_free_table(xobj->sgt);
                kfree(xobj->sgt);
        }

        /* Use the page rounded size so we can accurately account for number of pages */
        page_count = xobj->base.size >> PAGE_SHIFT;

        xobj->pages = drm_malloc_ab(page_count, sizeof(*xobj->pages));
        if (!xobj->pages) {
                ret = -ENOMEM;
                goto out1;
        }
	
	//pr_info("%s: %d %p", __func__, page_count, xobj->pages);

        for (i=0; i<page_count; i++)
        {
                xobj->pages[i] = virt_to_page(args->addr+i*PAGE_SIZE);
        }

        xobj->sgt = drm_prime_pages_to_sg(xobj->pages, page_count);
        if (IS_ERR(xobj->sgt)) {
                ret = PTR_ERR(xobj->sgt);
                goto out0;
        }

	XOCL_DRM_GEM_OBJECT_PUT_UNLOCKED(&xobj->base);
        return ret;
out0:
        drm_free_large(xobj->pages);
        xobj->pages = NULL;
out1:
	return ret;
}
EXPORT_SYMBOL_GPL(xocl_remap_kmem_bo_ifc);

int xocl_create_sgl_bo_ifc(struct drm_xocl_sgl_bo *args)
{
        int i;
        int ret;
        struct drm_xocl_bo *xobj;
	struct xocl_drm *drm_p = uapp_drm_context.dev->dev_private;
        unsigned int page_count;

        struct scatterlist *sg;
        int nents;

	if (!atomic_read(&uapp_drm_context.active)) {
		return -EFAULT;
	}

	xobj = xocl_drm_create_bo(drm_p, args->size, 
					(args->flags | XCL_BO_FLAGS_KERNPTR));
        BO_ENTER("xobj %p", xobj);

        if (IS_ERR(xobj)) {
                DRM_DEBUG("object creation failed\n");
                return PTR_ERR(xobj);
        }

	if (args->sgl) {
        	nents = sg_nents((struct scatterlist *)args->sgl);
        	/* Use the page rounded size so we can accurately account for 
		number of pages */
        	page_count = xobj->base.size >> PAGE_SHIFT;

		/* error out if SGL being mapped is bigger than BO size*/
		if (nents > page_count)
			return -EINVAL;

        	xobj->sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
                if (!xobj->sgt)
                        return -ENOMEM;

                xobj->sgt->sgl = (struct scatterlist *)args->sgl;
                xobj->sgt->nents = xobj->sgt->orig_nents = nents;

                xobj->pages = drm_malloc_ab(page_count, sizeof(*xobj->pages));
                if (!xobj->pages) {
                        ret = -ENOMEM;
                        goto out1;
       		}
	
                for_each_sg((struct scatterlist *)args->sgl, sg, nents, i) {
                        xobj->pages[i] = sg_page(sg);
                }
        }
	else{
		xobj->sgt = NULL;
		xobj->pages = NULL;
		xobj->vmapping = NULL;
	}

        ret = drm_gem_handle_create(uapp_drm_context.file, &xobj->base, 
								&args->handle);
        if (ret)
                goto out1;

        xocl_describe(xobj);
	ret = xocl_gem_obj_to_kernel_list(&xobj->base);

	return ret;
out0:
        drm_free_large(xobj->pages);
        xobj->pages = NULL;
out1:
	xocl_drm_free_bo(&xobj->base);
        DRM_DEBUG("handle creation failed\n");
	return ret;
}
EXPORT_SYMBOL_GPL(xocl_create_sgl_bo_ifc);

int xocl_remap_sgl_bo_ifc(struct drm_xocl_sgl_bo *args)
{
        int i;
        int ret=0;
	unsigned int page_count;
	struct scatterlist *sg;
	int nents = sg_nents((struct scatterlist *)args->sgl);

	struct drm_xocl_bo *xobj;
        struct drm_gem_object *gem_obj;
	if (!atomic_read(&uapp_drm_context.active)) {
		return -EFAULT;
	}
	gem_obj = xocl_gem_object_lookup(uapp_drm_context.dev, 
					uapp_drm_context.file,
                                        args->handle);

	if (!gem_obj) {
		DRM_ERROR("Failed to look up GEM BO %d\n", args->handle);
		return -ENOENT;
	}

	xobj = to_xocl_bo(gem_obj);

        /* Use the page rounded size so we can accurately account for number of pages */
        page_count = xobj->base.size >> PAGE_SHIFT;

	/* error out if SGL being mapped is bigger than BO size*/
	if (nents > page_count)
		return -EINVAL;

	if (!xobj->sgt) {
		xobj->sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
		if (!xobj->sgt)
			return -ENOMEM;

	}

	xobj->sgt->sgl = (struct scatterlist *)args->sgl;
	xobj->sgt->nents = xobj->sgt->orig_nents = nents;

	if (!xobj->pages) {
		page_count = nents;
		xobj->pages = drm_malloc_ab(page_count, sizeof(*xobj->pages));
		if (!xobj->pages)
			return -ENOMEM;
	}

	for_each_sg((struct scatterlist *)args->sgl, sg, nents, i) {
		xobj->pages[i] = sg_page(sg);
	}

	XOCL_DRM_GEM_OBJECT_PUT_UNLOCKED(&xobj->base);
	return ret;
out0:
	drm_free_large(xobj->pages);
	xobj->pages = NULL;
	return ret;
}
EXPORT_SYMBOL_GPL(xocl_remap_sgl_bo_ifc);

void __iomem *xocl_get_bo_kernel_vaddr(uint32_t bo_handle)
{
	struct drm_gem_object *obj;
	struct drm_xocl_bo *xobj;

	if (!atomic_read(&uapp_drm_context.active)) {
		return NULL;
	}

	obj = xocl_gem_object_lookup(uapp_drm_context.dev, 
					uapp_drm_context.file, bo_handle);
	xobj = to_xocl_bo(obj);

	if (!obj) {
		DRM_ERROR("Failed to look up GEM BO %d\n", bo_handle);
		return NULL;
	}

	XOCL_DRM_GEM_OBJECT_PUT_UNLOCKED(&xobj->base);

	if (xobj->flags & XOCL_P2P_MEM)
		return page_to_virt(xobj->pages[0]);
	else
		return xobj->vmapping;
}
EXPORT_SYMBOL_GPL(xocl_get_bo_kernel_vaddr);

void xocl_release_buffers_ifc(void)
{
        struct kernel_gem_obj_node *gem_node;
        struct list_head *pos, *next;

        printk ("%s", __func__);
	spin_lock(&gem_obj_list_lock);
        list_for_each_safe(pos, next, &gem_obj_list){
                gem_node = list_entry(pos, struct kernel_gem_obj_node, list);
		//xocl_drm_free_bo(gem_node->obj);
		XOCL_DRM_GEM_OBJECT_PUT_UNLOCKED(gem_node->obj);
                list_del(pos);
                kfree(gem_node);
        }
	spin_unlock(&gem_obj_list_lock);
}
EXPORT_SYMBOL_GPL(xocl_release_buffers_ifc);

int xocl_migrate_bo_async_ifc(struct drm_xocl_sync_bo *args, void (*cb_func)(unsigned long, int), void *ctx_data)
{
	const struct drm_xocl_bo *xobj;
	struct sg_table *sgt;
	u64 paddr = 0;
	//int channel = 0;
	ssize_t ret = 0;
	struct xocl_drm *drm_p = uapp_drm_context.dev->dev_private;
	struct xocl_dev *xdev = drm_p->xdev;
	struct scatterlist *sg;

        struct drm_gem_object *gem_obj;

	u32 dir = (args->dir == DRM_XOCL_SYNC_BO_TO_DEVICE) ? 1 : 0;

	if (!atomic_read(&uapp_drm_context.active)) {
		return -EFAULT;
	}

	//pr_err("%s: bohandle:%x cb_func:%llx ctx:%llx", __func__, args->handle, (u64)cb_func, (u64)ctx_data);
	gem_obj = xocl_gem_object_lookup(uapp_drm_context.dev, 
					uapp_drm_context.file,
                                        args->handle);
	if (!gem_obj) {
		DRM_ERROR("Failed to look up GEM BO %d\n", args->handle);
		return -ENOENT;
	}

	xobj = to_xocl_bo(gem_obj);
	BO_ENTER("xobj %p", xobj);
	sgt = xobj->sgt;
	sg = sgt->sgl;

	if (!xocl_bo_sync_able(xobj->flags)) {
		DRM_ERROR("BO %d doesn't support sync_bo\n", args->handle);
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (xocl_bo_cma(xobj)) {

		if (dir) {
			dma_sync_single_for_device(&(XDEV(xdev)->pdev->dev), sg_phys(sg),
				sg->length, DMA_TO_DEVICE);
		} else {
			dma_sync_single_for_cpu(&(XDEV(xdev)->pdev->dev), sg_phys(sg),
				sg->length, DMA_FROM_DEVICE);
		}
		goto out;
	}

	//Sarab: If it is a remote BO then why do sync over ARE.
	//We should do sync directly using the other device which this bo locally.
	//So that txfer is: HOST->PCIE->DDR; Else it will be HOST->PCIE->ARE->DDR
	paddr = xocl_bo_physical_addr(xobj);

	if (paddr == 0xffffffffffffffffull)
		return -EINVAL;

	if ((args->offset + args->size) > gem_obj->size) {
		ret = -EINVAL;
		goto out;
	}

	/* only invalidate the range of addresses requested by the user */
	/*
	if (args->dir == DRM_XOCL_SYNC_BO_TO_DEVICE)
		flush_kernel_vmap_range(kaddr, args->size);
	else if (args->dir == DRM_XOCL_SYNC_BO_FROM_DEVICE)
		invalidate_kernel_vmap_range(kaddr, args->size);
	else {
		ret = -EINVAL;
		goto out;
	}
	*/
	paddr += args->offset;

	if (args->offset || (args->size != xobj->base.size)) {
		sgt = alloc_onetime_sg_table(xobj->pages, args->offset, args->size);
		if (IS_ERR(sgt)) {
			ret = PTR_ERR(sgt);
			goto out;
		}
	}

	//drm_clflush_sg(sgt);
#if 0
	channel = xocl_acquire_channel(xdev, dir);
	if (channel < 0) {
		ret = -EINVAL;
		goto clear;
	}
	/* Now perform DMA */
	ret = xocl_migrate_bo(xdev, sgt, dir, paddr, channel, args->size);
	if (ret >= 0)
		ret = (ret == args->size) ? 0 : -EIO;
	xocl_release_channel(xdev, dir, channel);
#endif
	ret = xocl_async_migrate_bo(xdev, sgt, dir, paddr, 0, args->size, cb_func, ctx_data);
clear:
	if (args->offset || (args->size != xobj->base.size)) {
		sg_free_table(sgt);
		kfree(sgt);
	}
out:
	XOCL_DRM_GEM_OBJECT_PUT_UNLOCKED(gem_obj);
	return ret;
}
EXPORT_SYMBOL_GPL(xocl_migrate_bo_async_ifc);

