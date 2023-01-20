/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "lib/kernel/list.h"
#include "userprog/process.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva UNUSED) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	file_page->type = type;

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page = &page->file;

	struct file *file = file_page->file;
	off_t ofs = file_page->offset;
	size_t page_read_bytes = file_page->page_read_bytes;

	file_seek (file, ofs);
	if (file_read (file, kva, page_read_bytes) != (int) page_read_bytes) {
		palloc_free_page (kva);
		return false;
	}
	memset (kva + page_read_bytes, 0, PGSIZE - page_read_bytes);

	return true;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct thread *t = page->owner;
	void *upage = page->va;
	struct file_page *file_page = &page->file;

	if (pml4_get_page (t->pml4, upage)) {
		if (pml4_is_dirty (t->pml4, upage)) {
			if (file_write_at (file_page->file, upage, file_page->page_read_bytes, file_page->offset) \
				!= file_page->page_read_bytes)
				return false;

			pml4_set_dirty (t->pml4, upage, 0);
		}
		pml4_clear_page (t->pml4, upage);
	}

	return true;
}

/* Destroys the file backed page. If the content is dirty, make sure you write back the changes into the file.
 * You do not need to free the page struct in this function. The caller of file_backed_destroy should handle it.*/
static void
file_backed_destroy (struct page *page) {
	struct thread *t = thread_current ();
	void *upage = page->va;
	struct file_page *file_page = &page->file;

	if (pml4_get_page (t->pml4, upage)) {
		if (pml4_is_dirty (t->pml4, upage)) {
			if (file_write_at (file_page->file, upage, file_page->page_read_bytes, file_page->offset) \
				!= file_page->page_read_bytes)
				return;

			pml4_set_dirty (t->pml4, upage, 0);
		}
		pml4_clear_page (t->pml4, upage);

		struct frame *frame = page->frame;
		
		lock_acquire (&frames_lock);
		list_remove (&frame->f_elem);
		lock_release (&frames_lock);

		palloc_free_page (frame->kva);
		free (frame);
	}
}

/* Maps length bytes the file open as fd starting from offset byte into the process's virtual address space at addr.
 * The entire file is mapped into consecutive virtual pages starting at addr. */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
	struct thread *t = thread_current ();
	struct supplemental_page_table *spt = &t->spt;

	/* Use the file_reopen function to obtain a separate and independent reference to the file for each of its mappings. */
	file = file_reopen (file);
	if (file == NULL)
		return NULL;

	struct mmap_file *m = malloc (sizeof *m);
	if (m == NULL)
		return NULL;

	m->addr = addr;
	m->file = file;
	list_push_back (&spt->mmap_file_list, &m->mf_elem);
	list_init (&m->mmap_page_list);

	size_t file_left = file_length (file) - offset;   /* Readable file length. */
	size_t length_left = length;                      /* Remaining length to read. */

	for (void *upage = addr; upage < addr + length; upage += PGSIZE) {
		/* Do calculate how to fill this page. We will read PAGE_READ_BYTES bytes from FILE and zero the final PAGE_ZERO_BYTES bytes. */
		/* If the length of the file is not a multiple of PGSIZE, then some bytes in the final mapped page "stick out" beyond the end of the file.
		 * Set these bytes to zero when the page is faulted in, and discard them when the page is written back to disk. */
		size_t page_read_bytes = file_left >= PGSIZE ? (length_left < PGSIZE ? length_left : PGSIZE) \
													 : (length_left < file_left ? length_left : file_left);

		/* Set up aux to pass information to the lazy_load_segment. */
		struct lazy_load_arg *aux = malloc (sizeof *aux);
		if (aux == NULL)
			return NULL;

		aux->size = sizeof *aux;
		aux->file = file;
		aux->offset = offset;
		aux->page_read_bytes = page_read_bytes;

		/* Memory-mapped pages should be also allocated in a lazy manner just like anonymous pages.
		 * You can use vm_alloc_page_with_initializer or vm_alloc_page to make a page object. */
		if (!vm_alloc_page_with_initializer (VM_FILE, upage, writable, lazy_load_segment, aux)) {
			free (aux);
			return NULL;
		}

		struct page *p = spt_find_page (spt, upage);
		if (p == NULL)
			return NULL;

		list_push_back (&m->mmap_page_list, &p->mp_elem);

		/* Advance. */
		file_left = file_left >= page_read_bytes ? file_left - page_read_bytes : 0;
		length_left -= PGSIZE;
		offset += page_read_bytes;
	}

	return addr;
}

/* Unmaps the mapping for the specified address range addr,
 * which must be the virtual address returned by a previous call to mmap by the same process that has not yet been unmapped.
 * When a mapping is unmapped, whether implicitly or explicitly, all pages written to by the process are written back to the file,
 * and pages not written must not be. The pages are then removed from the process's list of virtual pages. */
void
do_munmap (void *addr) {
	struct thread *t = thread_current ();
	struct supplemental_page_table *spt = &t->spt;
	struct mmap_file *m;
	bool success = false;

	if (pg_ofs (addr) || !is_user_vaddr (addr))
		return;

	struct list *mf_list = &spt->mmap_file_list;
	for (struct list_elem *mf_e = list_begin (mf_list); mf_e != list_end (mf_list); mf_e = list_next (mf_e)) {
		m = list_entry (mf_e, struct mmap_file, mf_elem);
		if (m->addr == addr) {
			list_remove (mf_e);
			success = true;
			break;
		}
	}

	if (!success)
		return;

	struct list *mp_list = &m->mmap_page_list;
	while (!list_empty (mp_list)) {
		struct page *p = list_entry (list_pop_front (mp_list), struct page, mp_elem);
		spt_remove_page (spt, p);
	}

	file_close (m->file);
	free (m);
}