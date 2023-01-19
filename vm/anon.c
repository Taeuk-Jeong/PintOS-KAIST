/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "lib/kernel/bitmap.h"

#define SECTOR_FOR_BIT (PGSIZE / DISK_SECTOR_SIZE)

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static struct bitmap *swap_bitmap;

static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* Set up the swap_disk. */
	swap_disk = disk_get (1, 1);

	/* Data structure to manage free and used areas in the swap disk. */
	swap_bitmap = bitmap_create (disk_size (swap_disk) / SECTOR_FOR_BIT);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva UNUSED) {
	/* Set up the handler */
	page->operations = &anon_ops;

	struct anon_page *anon_page = &page->anon;
	anon_page->type = type;

	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;

	/* Validation check. */
	if (!bitmap_test (swap_bitmap, anon_page->sec_no / SECTOR_FOR_BIT))
		return false;

	/* Reading the data contents from the disk to memory. */
	for (int i = 0; i < SECTOR_FOR_BIT; i++)
		disk_read (swap_disk, anon_page->sec_no + i, kva + DISK_SECTOR_SIZE * i);

	/* Free a swap slot when its contents are read back into a frame(update the swap table). */
	bitmap_reset (swap_bitmap, anon_page->sec_no / SECTOR_FOR_BIT);

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	/* Find a free swap slot in the disk using the swap table.
	 * If there is no more free slot in the disk, panic the kernel. */
	size_t bit_idx = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
	if (bit_idx == BITMAP_ERROR)
		PANIC ("There is no more free slot in the disk.");

	disk_sector_t sec_no = bit_idx * SECTOR_FOR_BIT;

	/* Copy the page of data into the slot. */
	for (int i = 0; i < SECTOR_FOR_BIT; i++)
		disk_write (swap_disk, sec_no + i, page->frame->kva + DISK_SECTOR_SIZE * i);

	/* The location of the data should be saved in the page struct. */
	anon_page->sec_no = sec_no;

	pml4_clear_page (page->owner->pml4, page->va);

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	struct thread *t = thread_current ();
	void *upage = page->va;
	struct anon_page *anon_page = &page->anon;

	if (pml4_get_page (thread_current ()->pml4, upage)) {
		pml4_clear_page (t->pml4, upage);

		struct frame *frame = page->frame;

		frames_lock_acquire ();
		list_remove (&frame->f_elem);
		frames_lock_release ();
		
		palloc_free_page (frame->kva);
		free (frame);
	} else {
		bitmap_reset (swap_bitmap, (anon_page->sec_no) / SECTOR_FOR_BIT);
	}
}